use core::fmt;

use hyf_config::GatewayConfig;
use hyf_core::{MessageId, TimestampMs};
use hyf_link::{LinkEvent, LinkFrameRef, LinkId};
use hyf_router::{
    DropReason, ROUTER_COMMAND_CAPACITY, Router, RouterCommand, RouterEvent, RouterStoreCommand,
};
use hyf_store::Store;
use hyf_wire::{HyfEnvelopeRef, decode_envelope, encode_envelope};

use crate::{GatewayError, GatewayMetrics};

pub const GATEWAY_FRAME_BUFFER_LEN: usize = 2048;

pub trait GatewayLinkExecutor {
    fn send_link_bytes(
        &mut self,
        link_id: LinkId,
        bytes: &[u8],
        now_ms: TimestampMs,
    ) -> Result<(), GatewayError>;
}

pub struct GatewayCore<const MAX_LINKS: usize, const MAX_SEEN: usize, const STORE_CAPACITY: usize> {
    config: GatewayConfig<MAX_LINKS>,
    router: Router<MAX_LINKS, MAX_SEEN>,
    store: Store<STORE_CAPACITY, GATEWAY_FRAME_BUFFER_LEN>,
    metrics: GatewayMetrics,
    last_now_ms: TimestampMs,
    last_delivered_message_id: Option<MessageId>,
    last_delivered_payload_len: usize,
}

impl<const MAX_LINKS: usize, const MAX_SEEN: usize, const STORE_CAPACITY: usize> fmt::Debug
    for GatewayCore<MAX_LINKS, MAX_SEEN, STORE_CAPACITY>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayCore")
            .field("metrics", &self.metrics)
            .field("store_len", &self.store.len())
            .field("last_delivered_message_id", &self.last_delivered_message_id)
            .field(
                "last_delivered_payload_len",
                &self.last_delivered_payload_len,
            )
            .finish()
    }
}

impl<const MAX_LINKS: usize, const MAX_SEEN: usize, const STORE_CAPACITY: usize>
    GatewayCore<MAX_LINKS, MAX_SEEN, STORE_CAPACITY>
{
    pub fn new(config: GatewayConfig<MAX_LINKS>) -> Result<Self, GatewayError> {
        config.validate()?;
        validate_runtime_capacity("router links", config.router.max_links, MAX_LINKS)?;
        validate_runtime_capacity("router dedupe", config.router.max_seen_messages, MAX_SEEN)?;
        validate_runtime_capacity("store", config.store.capacity, STORE_CAPACITY)?;

        Ok(Self {
            config,
            router: Router::new(config.router_policy()),
            store: Store::new(config.store_policy()),
            metrics: GatewayMetrics::default(),
            last_now_ms: TimestampMs(0),
            last_delivered_message_id: None,
            last_delivered_payload_len: 0,
        })
    }

    pub fn config(&self) -> GatewayConfig<MAX_LINKS> {
        self.config
    }

    pub fn metrics(&self) -> GatewayMetrics {
        self.metrics
    }

    pub fn now_ms(&self) -> TimestampMs {
        self.last_now_ms
    }

    pub fn last_delivered_message_id(&self) -> Option<MessageId> {
        self.last_delivered_message_id
    }

    pub fn last_delivered_payload_len(&self) -> usize {
        self.last_delivered_payload_len
    }

    pub fn stored_len(&self) -> usize {
        self.store.len()
    }

    pub fn submit<E>(
        &mut self,
        envelope: HyfEnvelopeRef<'_>,
        executor: &mut E,
    ) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        self.metrics.submitted = self.metrics.submitted.saturating_add(1);
        self.route_event(RouterEvent::LocalSubmit(envelope), executor)?;
        self.flush_store(executor)
    }

    pub fn ingest_link_frame<E>(
        &mut self,
        frame: LinkFrameRef<'_>,
        executor: &mut E,
    ) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        let received_at_ms = frame.received_at_ms;
        self.metrics.received = self.metrics.received.saturating_add(1);
        self.observe_time(received_at_ms, executor)?;
        self.route_event(RouterEvent::Link(LinkEvent::Frame(frame)), executor)?;
        self.flush_store(executor)
    }

    pub fn tick<E>(&mut self, now: TimestampMs, executor: &mut E) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        self.observe_time(now, executor)?;
        self.flush_store(executor)
    }

    pub fn handle_link_event<E>(
        &mut self,
        event: LinkEvent<'static>,
        executor: &mut E,
    ) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        let flush_after_recovery = matches!(event, LinkEvent::Up { .. });
        self.route_event(RouterEvent::Link(event), executor)?;
        if flush_after_recovery {
            self.flush_store(executor)?;
        }
        Ok(())
    }

    fn observe_time<E>(&mut self, now: TimestampMs, executor: &mut E) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        if now.0 <= self.last_now_ms.0 {
            return Ok(());
        }

        self.last_now_ms = now;
        self.route_event(RouterEvent::Tick { now_ms: now }, executor)
    }

    fn route_event<'event, E>(
        &mut self,
        event: RouterEvent<'event>,
        executor: &mut E,
    ) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        let mut commands = [dummy_command(); ROUTER_COMMAND_CAPACITY];
        let count = self.router.handle_event(event, &mut commands)?;
        self.execute_commands(&commands[..count], executor)
    }

    fn execute_commands<'event, E>(
        &mut self,
        commands: &[RouterCommand<'event>],
        executor: &mut E,
    ) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        let mut successes = 0usize;
        let mut first_error = None;
        for command in commands {
            match self.execute_command(*command, executor) {
                Ok(()) => {
                    successes += 1;
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if successes > 0 || commands.is_empty() {
            return Ok(());
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn execute_command<'event, E>(
        &mut self,
        command: RouterCommand<'event>,
        executor: &mut E,
    ) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        match command {
            RouterCommand::Send { link_id, envelope } => {
                self.send_envelope(link_id, envelope, executor)?;
                self.router.commit_seen(envelope);
                Ok(())
            }
            RouterCommand::Store(RouterStoreCommand::Put(envelope)) => {
                if self.config.policy.allow_store_and_forward {
                    self.store.put_envelope(envelope)?;
                    self.metrics.stored = self.metrics.stored.saturating_add(1);
                    self.router.commit_seen(envelope);
                } else {
                    self.metrics.dropped = self.metrics.dropped.saturating_add(1);
                }
                Ok(())
            }
            RouterCommand::Store(RouterStoreCommand::Remove(message_id)) => {
                self.store.remove(message_id)?;
                Ok(())
            }
            RouterCommand::Store(RouterStoreCommand::ExpireBefore(now)) => {
                let expired = self.store.expire_before(now);
                self.metrics.expired = self.metrics.expired.saturating_add(expired as u64);
                Ok(())
            }
            RouterCommand::Drop { .. } | RouterCommand::DropFrame { .. } => {
                self.metrics.dropped = self.metrics.dropped.saturating_add(1);
                Ok(())
            }
            RouterCommand::DeliverLocal(envelope) => {
                self.last_delivered_message_id = Some(envelope.message_id);
                self.last_delivered_payload_len = envelope.payload.len();
                self.metrics.delivered = self.metrics.delivered.saturating_add(1);
                self.router.commit_seen(envelope);
                Ok(())
            }
        }
    }

    fn send_envelope<E>(
        &mut self,
        link_id: LinkId,
        envelope: HyfEnvelopeRef<'_>,
        executor: &mut E,
    ) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
        let len = encode_envelope(envelope, &mut frame)?;
        if let Err(error) = executor.send_link_bytes(link_id, &frame[..len], envelope.created_at_ms)
        {
            self.metrics.link_errors = self.metrics.link_errors.saturating_add(1);
            return Err(error);
        }
        self.metrics.sent = self.metrics.sent.saturating_add(1);
        self.metrics.bytes_sent = self.metrics.bytes_sent.saturating_add(len as u64);
        Ok(())
    }

    fn flush_store<E>(&mut self, executor: &mut E) -> Result<(), GatewayError>
    where
        E: GatewayLinkExecutor,
    {
        let expired = self.store.expire_before(self.last_now_ms);
        self.metrics.expired = self.metrics.expired.saturating_add(expired as u64);
        while let Some(stored) = self.store.first_pending() {
            let message_id = stored.message_id;
            let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
            let len = stored.bytes.len();
            frame[..len].copy_from_slice(stored.bytes);
            let envelope = decode_envelope(&frame[..len])?;
            let mut commands = [dummy_command(); ROUTER_COMMAND_CAPACITY];
            let count = self.router.forward_stored(envelope, &mut commands)?;
            if count == 0 {
                break;
            }
            if let Err(error) = self.execute_commands(&commands[..count], executor) {
                if error.is_recoverable_send_failure() {
                    break;
                }
                return Err(error);
            }
            self.store.remove(message_id)?;
        }
        Ok(())
    }
}

fn validate_runtime_capacity(
    name: &'static str,
    configured: usize,
    maximum: usize,
) -> Result<(), GatewayError> {
    if configured > maximum {
        return Err(GatewayError::RuntimeCapacity {
            name,
            configured,
            maximum,
        });
    }
    Ok(())
}

const fn dummy_command<'a>() -> RouterCommand<'a> {
    RouterCommand::Drop {
        message_id: MessageId([0; 32]),
        reason: DropReason::Duplicate,
    }
}

#[cfg(test)]
mod tests {
    use hyf_config::{
        GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
    };
    use hyf_core::{CommunityId, MessageId, NodeId, TimestampMs};
    use hyf_link::{LinkDriverErrorKind, LinkFrameRef, LinkId};
    use hyf_store::StorePolicy;
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, encode_envelope,
    };

    use super::{GATEWAY_FRAME_BUFFER_LEN, GatewayCore, GatewayLinkExecutor};
    use crate::{GatewayError, GatewayMetrics};

    type TestCore = GatewayCore<2, 8, 4>;

    #[derive(Default)]
    struct TestExecutor {
        send_error: Option<GatewayError>,
        fail_link: Option<LinkId>,
        sent: usize,
        last_link_id: Option<LinkId>,
    }

    impl GatewayLinkExecutor for TestExecutor {
        fn send_link_bytes(
            &mut self,
            link_id: LinkId,
            bytes: &[u8],
            _now_ms: TimestampMs,
        ) -> Result<(), GatewayError> {
            let should_fail = self.fail_link.map_or(true, |failed| failed == link_id);
            if should_fail && let Some(error) = self.send_error {
                return Err(error);
            }
            self.sent += 1;
            self.last_link_id = Some(link_id);
            assert!(!bytes.is_empty());
            Ok(())
        }
    }

    #[test]
    fn core_constructs_from_valid_config() -> Result<(), GatewayError> {
        let core = TestCore::new(valid_config())?;

        assert_eq!(core.metrics(), GatewayMetrics::default());
        assert_eq!(core.stored_len(), 0);
        assert_eq!(core.config().node_id, local());
        Ok(())
    }

    #[test]
    fn core_submit_sends_through_executor() -> Result<(), GatewayError> {
        let mut core = TestCore::new(valid_config())?;
        let mut executor = TestExecutor::default();

        core.handle_link_event(hyf_link::LinkEvent::Up { link_id: link_a() }, &mut executor)?;
        core.submit(sample_envelope(MessageId([1; 32]), remote()), &mut executor)?;

        assert_eq!(executor.sent, 1);
        assert_eq!(executor.last_link_id, Some(link_a()));
        assert_eq!(core.metrics().sent, 1);
        assert!(core.metrics().bytes_sent > 0);
        Ok(())
    }

    #[test]
    fn core_counts_received_frames_before_routing() -> Result<(), GatewayError> {
        let mut core = TestCore::new(valid_config())?;
        let mut executor = TestExecutor::default();
        let envelope = sample_envelope(MessageId([2; 32]), local());
        let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
        let len = encode_envelope(envelope, &mut frame)?;

        core.ingest_link_frame(
            LinkFrameRef::new(link_a(), TimestampMs(120), &frame[..len]),
            &mut executor,
        )?;

        assert_eq!(core.metrics().received, 1);
        assert_eq!(core.metrics().delivered, 1);
        assert_eq!(core.last_delivered_message_id(), Some(MessageId([2; 32])));
        Ok(())
    }

    #[test]
    fn core_flush_store_stops_on_recoverable_driver_error() -> Result<(), GatewayError> {
        let mut core = TestCore::new(valid_config())?;
        let mut executor = TestExecutor::default();

        core.submit(sample_envelope(MessageId([3; 32]), remote()), &mut executor)?;
        assert_eq!(core.stored_len(), 1);

        executor.send_error = Some(GatewayError::Driver {
            link_id: link_a(),
            kind: LinkDriverErrorKind::Backpressure,
        });
        core.handle_link_event(hyf_link::LinkEvent::Up { link_id: link_a() }, &mut executor)?;

        assert_eq!(core.stored_len(), 1);
        assert_eq!(core.metrics().link_errors, 1);
        Ok(())
    }

    #[test]
    fn core_community_submit_fans_out_after_one_link_failure() -> Result<(), GatewayError> {
        let mut core = TestCore::new(local_community_config())?;
        let mut executor = TestExecutor {
            send_error: Some(GatewayError::Driver {
                link_id: link_b(),
                kind: LinkDriverErrorKind::Backpressure,
            }),
            fail_link: Some(link_b()),
            ..TestExecutor::default()
        };

        core.handle_link_event(hyf_link::LinkEvent::Up { link_id: link_a() }, &mut executor)?;
        core.handle_link_event(hyf_link::LinkEvent::Up { link_id: link_b() }, &mut executor)?;
        core.submit(community_envelope(MessageId([5; 32])), &mut executor)?;

        assert_eq!(executor.sent, 1);
        assert_eq!(executor.last_link_id, Some(link_a()));
        assert_eq!(core.metrics().delivered, 1);
        assert_eq!(core.metrics().sent, 1);
        assert_eq!(core.metrics().link_errors, 1);
        assert_eq!(core.last_delivered_message_id(), Some(MessageId([5; 32])));
        Ok(())
    }

    #[test]
    fn core_debug_redacts_last_delivered_payload() -> Result<(), GatewayError> {
        let mut core = TestCore::new(valid_config())?;
        let mut executor = TestExecutor::default();

        core.submit(sample_envelope(MessageId([4; 32]), local()), &mut executor)?;
        let debug = format!("{core:?}");

        assert!(debug.contains("GatewayCore"));
        assert!(debug.contains("last_delivered_message_id"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }

    fn valid_config() -> GatewayConfig<2> {
        GatewayConfig {
            node_id: local(),
            router: RouterConfig::new(2, 8),
            store: StoreConfig::new(4, StorePolicy::new()),
            links: LinkConfigSet::new([
                Some(LinkConfig::new(link_a(), 256)),
                Some(LinkConfig::new(link_b(), 256)),
            ]),
            policy: GatewayPolicyConfig::new(),
        }
    }

    fn local_community_config() -> GatewayConfig<2> {
        let mut local_communities = [None; hyf_router::ROUTER_LOCAL_COMMUNITY_CAPACITY];
        local_communities[0] = Some(room());
        GatewayConfig {
            policy: GatewayPolicyConfig::with_local_communities(local_communities),
            ..valid_config()
        }
    }

    fn sample_envelope(message_id: MessageId, destination: NodeId) -> HyfEnvelopeRef<'static> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id,
            source: local(),
            destination: HyfDestination::Node(destination),
            created_at_ms: TimestampMs(100),
            expires_at_ms: TimestampMs(300),
            hop_limit: 4,
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"secret",
        }
    }

    fn community_envelope(message_id: MessageId) -> HyfEnvelopeRef<'static> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id,
            source: local(),
            destination: HyfDestination::Community(room()),
            created_at_ms: TimestampMs(100),
            expires_at_ms: TimestampMs(300),
            hop_limit: 4,
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"bridge",
        }
    }

    const fn local() -> NodeId {
        NodeId([0x11; 32])
    }

    const fn remote() -> NodeId {
        NodeId([0x22; 32])
    }

    const fn room() -> CommunityId {
        CommunityId([0x33; 16])
    }

    const fn link_a() -> LinkId {
        LinkId([0xaa; 16])
    }

    const fn link_b() -> LinkId {
        LinkId([0xbb; 16])
    }
}
