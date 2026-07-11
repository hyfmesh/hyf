use core::fmt;

use hyf_config::GatewayConfig;
use hyf_core::{MessageId, TimestampMs};
use hyf_link::{LinkEvent, LinkFrameRef, LinkId};
use hyf_link_loopback::{
    LOOPBACK_LEFT_ID, LOOPBACK_MAX_FRAME_LEN, LOOPBACK_RIGHT_ID, LoopbackEndpoint, LoopbackPair,
};
use hyf_router::{DropReason, Router, RouterCommand, RouterEvent, RouterStoreCommand};
use hyf_store::Store;
use hyf_wire::{HyfEnvelopeRef, decode_envelope, encode_envelope};

use crate::{GatewayError, GatewayMetrics};

pub const GATEWAY_FRAME_BUFFER_LEN: usize = LOOPBACK_MAX_FRAME_LEN;
const ROUTER_COMMAND_CAPACITY: usize = 4;

pub struct GatewayRuntime<
    const MAX_LINKS: usize,
    const MAX_SEEN: usize,
    const STORE_CAPACITY: usize,
    const LOOPBACK_QUEUE: usize,
> {
    config: GatewayConfig<MAX_LINKS>,
    router: Router<MAX_LINKS, MAX_SEEN>,
    store: Store<STORE_CAPACITY, GATEWAY_FRAME_BUFFER_LEN>,
    loopback: LoopbackPair<LOOPBACK_QUEUE>,
    metrics: GatewayMetrics,
    last_now_ms: TimestampMs,
    last_delivered_message_id: Option<MessageId>,
    last_delivered_payload_len: usize,
}

impl<
    const MAX_LINKS: usize,
    const MAX_SEEN: usize,
    const STORE_CAPACITY: usize,
    const LOOPBACK_QUEUE: usize,
> fmt::Debug for GatewayRuntime<MAX_LINKS, MAX_SEEN, STORE_CAPACITY, LOOPBACK_QUEUE>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayRuntime")
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

impl<
    const MAX_LINKS: usize,
    const MAX_SEEN: usize,
    const STORE_CAPACITY: usize,
    const LOOPBACK_QUEUE: usize,
> GatewayRuntime<MAX_LINKS, MAX_SEEN, STORE_CAPACITY, LOOPBACK_QUEUE>
{
    pub fn new(config: GatewayConfig<MAX_LINKS>) -> Result<Self, GatewayError> {
        config.validate()?;
        validate_runtime_capacity("router links", config.router.max_links, MAX_LINKS)?;
        validate_runtime_capacity("router dedupe", config.router.max_seen_messages, MAX_SEEN)?;
        validate_runtime_capacity("store", config.store.capacity, STORE_CAPACITY)?;
        validate_supported_links(&config)?;

        let router_policy = config.router_policy();
        let store_policy = config.store_policy();
        let mut runtime = Self {
            config,
            router: Router::new(router_policy),
            store: Store::new(store_policy),
            loopback: LoopbackPair::new(first_link_mtu(&config)),
            metrics: GatewayMetrics::default(),
            last_now_ms: TimestampMs(0),
            last_delivered_message_id: None,
            last_delivered_payload_len: 0,
        };
        runtime.activate_configured_links()?;
        Ok(runtime)
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

    pub fn loopback_queued_len(&mut self, link_id: LinkId) -> Result<usize, GatewayError> {
        let (left, right) = self.loopback.split();
        Ok(endpoint_for_link(left, right, link_id)?.queued_len())
    }

    pub fn receive_loopback_frame<'b>(
        &mut self,
        link_id: LinkId,
        output: &'b mut [u8],
    ) -> Result<Option<LinkFrameRef<'b>>, GatewayError> {
        let (left, right) = self.loopback.split();
        Ok(endpoint_for_link(left, right, link_id)?.receive_into(output)?)
    }

    pub fn ingest_link_frame(&mut self, frame: LinkFrameRef<'_>) -> Result<(), GatewayError> {
        let received_at_ms = frame.received_at_ms;
        self.observe_time(received_at_ms)?;
        self.route_event(RouterEvent::Link(LinkEvent::Frame(frame)))?;
        self.flush_store(self.last_now_ms)
    }

    pub fn poll_loopback(
        &mut self,
        link_id: LinkId,
        output: &mut [u8],
    ) -> Result<bool, GatewayError> {
        let Some(frame) = self.receive_loopback_frame(link_id, output)? else {
            return Ok(false);
        };
        self.ingest_link_frame(frame)?;
        Ok(true)
    }

    pub fn submit(&mut self, envelope: HyfEnvelopeRef<'_>) -> Result<(), GatewayError> {
        self.metrics.submitted = self.metrics.submitted.saturating_add(1);
        self.route_event(RouterEvent::LocalSubmit(envelope))?;
        self.flush_store(self.last_now_ms)
    }

    pub fn tick(&mut self, now: TimestampMs) -> Result<(), GatewayError> {
        self.observe_time(now)?;
        self.flush_store(self.last_now_ms)
    }

    pub fn set_link_up(&mut self, link_id: LinkId, up: bool) -> Result<(), GatewayError> {
        let event = {
            let (left, right) = self.loopback.split();
            endpoint_for_link(left, right, link_id)?.set_up(up)
        };
        self.route_event(RouterEvent::Link(event))?;
        if up {
            self.flush_store(self.last_now_ms)?;
        }
        Ok(())
    }

    fn observe_time(&mut self, now: TimestampMs) -> Result<(), GatewayError> {
        if now.0 <= self.last_now_ms.0 {
            return Ok(());
        }

        self.last_now_ms = now;
        self.route_event(RouterEvent::Tick { now_ms: now })
    }

    fn route_event<'event>(&mut self, event: RouterEvent<'event>) -> Result<(), GatewayError> {
        let mut commands = [dummy_command(); ROUTER_COMMAND_CAPACITY];
        let count = self.router.handle_event(event, &mut commands)?;
        self.execute_commands(&commands[..count])
    }

    fn execute_commands<'event>(
        &mut self,
        commands: &[RouterCommand<'event>],
    ) -> Result<(), GatewayError> {
        for command in commands {
            self.execute_command(*command)?;
        }
        Ok(())
    }

    fn execute_command<'event>(
        &mut self,
        command: RouterCommand<'event>,
    ) -> Result<(), GatewayError> {
        match command {
            RouterCommand::Send { link_id, envelope } => {
                self.send_envelope(link_id, envelope)?;
                self.router.commit_seen(envelope.message_id);
                Ok(())
            }
            RouterCommand::Store(RouterStoreCommand::Put(envelope)) => {
                if self.config.policy.allow_store_and_forward {
                    self.store.put_envelope(envelope)?;
                    self.metrics.stored = self.metrics.stored.saturating_add(1);
                    self.router.commit_seen(envelope.message_id);
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
                self.router.commit_seen(envelope.message_id);
                Ok(())
            }
        }
    }

    fn send_envelope(
        &mut self,
        link_id: LinkId,
        envelope: HyfEnvelopeRef<'_>,
    ) -> Result<(), GatewayError> {
        let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
        let len = encode_envelope(envelope, &mut frame)?;
        self.send_bytes(link_id, &frame[..len], envelope.created_at_ms)?;
        self.metrics.sent = self.metrics.sent.saturating_add(1);
        self.metrics.bytes_sent = self.metrics.bytes_sent.saturating_add(len as u64);
        Ok(())
    }

    fn send_bytes(
        &mut self,
        link_id: LinkId,
        bytes: &[u8],
        now: TimestampMs,
    ) -> Result<(), GatewayError> {
        let result = {
            let (left, right) = self.loopback.split();
            if link_id == left.link_id() {
                left.send_bytes_to(right, bytes, now)
            } else if link_id == right.link_id() {
                right.send_bytes_to(left, bytes, now)
            } else {
                return Err(GatewayError::UnsupportedLink { link_id });
            }
        };
        if let Err(error) = result {
            self.metrics.link_errors = self.metrics.link_errors.saturating_add(1);
            return Err(error.into());
        }
        Ok(())
    }

    fn flush_store(&mut self, now: TimestampMs) -> Result<(), GatewayError> {
        let expired = self.store.expire_before(now);
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
            if let Err(error) = self.execute_commands(&commands[..count]) {
                if matches!(error, GatewayError::Loopback(_)) {
                    break;
                }
                return Err(error);
            }
            self.store.remove(message_id)?;
        }
        Ok(())
    }

    fn activate_configured_links(&mut self) -> Result<(), GatewayError> {
        let links = self.config.links;
        for link in links.as_slice().iter().flatten() {
            if link.enabled {
                self.set_link_up(link.link_id, true)?;
            }
        }
        Ok(())
    }
}

fn endpoint_for_link<'a, const N: usize>(
    left: &'a mut LoopbackEndpoint<N>,
    right: &'a mut LoopbackEndpoint<N>,
    link_id: LinkId,
) -> Result<&'a mut LoopbackEndpoint<N>, GatewayError> {
    if link_id == left.link_id() {
        Ok(left)
    } else if link_id == right.link_id() {
        Ok(right)
    } else {
        Err(GatewayError::UnsupportedLink { link_id })
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

fn validate_supported_links<const MAX_LINKS: usize>(
    config: &GatewayConfig<MAX_LINKS>,
) -> Result<(), GatewayError> {
    for link in config.links.as_slice().iter().flatten() {
        if link.enabled && link.link_id != LOOPBACK_LEFT_ID && link.link_id != LOOPBACK_RIGHT_ID {
            return Err(GatewayError::UnsupportedLink {
                link_id: link.link_id,
            });
        }
    }
    Ok(())
}

fn first_link_mtu<const MAX_LINKS: usize>(config: &GatewayConfig<MAX_LINKS>) -> usize {
    for link in config.links.as_slice().iter().flatten() {
        if link.enabled {
            return link.mtu;
        }
    }
    0
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
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_link::LinkId;
    use hyf_link_loopback::{LOOPBACK_LEFT_ID, LOOPBACK_RIGHT_ID};
    use hyf_store::StorePolicy;
    use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind};

    use super::GatewayRuntime;
    use crate::{GATEWAY_FRAME_BUFFER_LEN, GatewayError};

    type TestRuntime = GatewayRuntime<2, 8, 4, 4>;

    #[test]
    fn runtime_constructs_from_valid_config() -> Result<(), GatewayError> {
        let runtime = TestRuntime::new(valid_config())?;

        assert_eq!(runtime.metrics().submitted, 0);
        assert_eq!(runtime.stored_len(), 0);
        Ok(())
    }

    #[test]
    fn runtime_rejects_unsupported_link_and_capacity_mismatch() {
        let unsupported = GatewayConfig {
            links: LinkConfigSet::new([
                Some(LinkConfig::new(LinkId([9; 16]), 128)),
                Some(LinkConfig::new(LOOPBACK_RIGHT_ID, 128)),
            ]),
            ..valid_config()
        };
        let too_much_store = GatewayConfig {
            store: StoreConfig::new(8, StorePolicy::new()),
            ..valid_config()
        };

        assert!(matches!(
            TestRuntime::new(unsupported),
            Err(GatewayError::UnsupportedLink { link_id }) if link_id == LinkId([9; 16])
        ));
        assert!(matches!(
            TestRuntime::new(too_much_store),
            Err(GatewayError::RuntimeCapacity {
                name: "store",
                configured: 8,
                maximum: 4,
            })
        ));
    }

    #[test]
    fn runtime_submit_sends_when_link_is_up() -> Result<(), GatewayError> {
        let mut runtime = TestRuntime::new(valid_config())?;

        runtime.submit(sample_envelope(
            MessageId([1; 32]),
            remote(),
            100,
            200,
            b"payload",
        ))?;

        assert_eq!(runtime.metrics().submitted, 1);
        assert_eq!(runtime.metrics().sent, 1);
        assert!(runtime.metrics().bytes_sent > 0);
        Ok(())
    }

    #[test]
    fn runtime_submit_stores_when_links_are_down_and_flushes_on_recovery()
    -> Result<(), GatewayError> {
        let mut runtime = TestRuntime::new(valid_config())?;
        runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
        runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;

        runtime.submit(sample_envelope(
            MessageId([1; 32]),
            remote(),
            100,
            200,
            b"payload",
        ))?;
        assert_eq!(runtime.stored_len(), 1);
        assert_eq!(runtime.metrics().stored, 1);

        runtime.set_link_up(LOOPBACK_LEFT_ID, true)?;
        runtime.set_link_up(LOOPBACK_RIGHT_ID, true)?;
        assert_eq!(runtime.stored_len(), 0);
        assert_eq!(runtime.metrics().sent, 1);
        Ok(())
    }

    #[test]
    fn runtime_delivers_local_submissions_and_expires_store() -> Result<(), GatewayError> {
        let mut runtime = TestRuntime::new(valid_config())?;
        runtime.submit(sample_envelope(
            MessageId([1; 32]),
            local(),
            100,
            200,
            b"secret",
        ))?;

        assert_eq!(
            runtime.last_delivered_message_id(),
            Some(MessageId([1; 32]))
        );
        assert_eq!(runtime.last_delivered_payload_len(), b"secret".len());
        assert_eq!(runtime.metrics().delivered, 1);

        runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
        runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;
        runtime.submit(sample_envelope(
            MessageId([2; 32]),
            remote(),
            100,
            300,
            b"stored",
        ))?;
        runtime.tick(TimestampMs(300))?;

        assert_eq!(runtime.stored_len(), 0);
        assert_eq!(runtime.metrics().expired, 1);
        Ok(())
    }

    #[test]
    fn runtime_reports_current_time_and_empty_poll() -> Result<(), GatewayError> {
        let mut runtime = TestRuntime::new(valid_config())?;
        let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];

        assert_eq!(runtime.now_ms(), TimestampMs(0));
        runtime.tick(TimestampMs(42))?;
        runtime.tick(TimestampMs(7))?;

        assert_eq!(runtime.now_ms(), TimestampMs(42));
        assert!(!runtime.poll_loopback(LOOPBACK_RIGHT_ID, &mut frame)?);
        Ok(())
    }

    #[test]
    fn runtime_debug_redacts_last_delivered_payload() -> Result<(), GatewayError> {
        let mut runtime = TestRuntime::new(valid_config())?;
        runtime.submit(sample_envelope(
            MessageId([1; 32]),
            local(),
            100,
            200,
            b"secret",
        ))?;
        let debug = format!("{runtime:?}");

        assert!(debug.contains("GatewayRuntime"));
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
                Some(LinkConfig::new(LOOPBACK_LEFT_ID, 256)),
                Some(LinkConfig::new(LOOPBACK_RIGHT_ID, 256)),
            ]),
            policy: GatewayPolicyConfig::new(),
        }
    }

    fn sample_envelope<'a>(
        message_id: MessageId,
        destination: NodeId,
        created_at_ms: u64,
        expires_at_ms: u64,
        payload: &'a [u8],
    ) -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id,
            source: local(),
            destination: HyfDestination::Node(destination),
            created_at_ms: TimestampMs(created_at_ms),
            expires_at_ms: TimestampMs(expires_at_ms),
            hop_limit: 4,
            payload_kind: PayloadKind::HyfNativeV0,
            payload,
        }
    }

    const fn local() -> NodeId {
        NodeId([0x11; 32])
    }

    const fn remote() -> NodeId {
        NodeId([0x22; 32])
    }

    #[test]
    fn gateway_frame_buffer_matches_loopback_limit() {
        assert_eq!(
            GATEWAY_FRAME_BUFFER_LEN,
            hyf_link_loopback::LOOPBACK_MAX_FRAME_LEN
        );
    }
}
