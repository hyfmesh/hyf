use core::fmt;

use hyf_config::GatewayConfig;
use hyf_core::{MessageId, TimestampMs};
use hyf_link::LinkId;
use hyf_link_loopback::{
    LOOPBACK_LEFT_ID, LOOPBACK_MAX_FRAME_LEN, LOOPBACK_RIGHT_ID, LoopbackEndpoint, LoopbackPair,
};
use hyf_router::{DropReason, Router, RouterCommand, RouterEvent, RouterStoreCommand};
use hyf_store::Store;
use hyf_wire::{HyfEnvelopeRef, encode_envelope};

use crate::{GatewayError, GatewayMetrics};

pub const GATEWAY_FRAME_BUFFER_LEN: usize = LOOPBACK_MAX_FRAME_LEN;
const ROUTER_COMMAND_CAPACITY: usize = 4;

pub struct GatewayRuntime<
    'a,
    const MAX_LINKS: usize,
    const MAX_SEEN: usize,
    const STORE_CAPACITY: usize,
    const LOOPBACK_QUEUE: usize,
> {
    config: GatewayConfig<MAX_LINKS>,
    router: Router<MAX_LINKS, MAX_SEEN>,
    store: Store<'a, STORE_CAPACITY>,
    loopback: LoopbackPair<LOOPBACK_QUEUE>,
    metrics: GatewayMetrics,
    last_delivered: Option<HyfEnvelopeRef<'a>>,
}

impl<
    'a,
    const MAX_LINKS: usize,
    const MAX_SEEN: usize,
    const STORE_CAPACITY: usize,
    const LOOPBACK_QUEUE: usize,
> fmt::Debug for GatewayRuntime<'a, MAX_LINKS, MAX_SEEN, STORE_CAPACITY, LOOPBACK_QUEUE>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayRuntime")
            .field("metrics", &self.metrics)
            .field("store_len", &self.store.len())
            .field("last_delivered", &self.last_delivered.map(|_| "<redacted>"))
            .finish()
    }
}

impl<
    'a,
    const MAX_LINKS: usize,
    const MAX_SEEN: usize,
    const STORE_CAPACITY: usize,
    const LOOPBACK_QUEUE: usize,
> GatewayRuntime<'a, MAX_LINKS, MAX_SEEN, STORE_CAPACITY, LOOPBACK_QUEUE>
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
            last_delivered: None,
        };
        runtime.activate_configured_links()?;
        Ok(runtime)
    }

    pub fn metrics(&self) -> GatewayMetrics {
        self.metrics
    }

    pub fn last_delivered(&self) -> Option<HyfEnvelopeRef<'a>> {
        self.last_delivered
    }

    pub fn stored_len(&self) -> usize {
        self.store.len()
    }

    pub fn submit(&mut self, envelope: HyfEnvelopeRef<'a>) -> Result<(), GatewayError> {
        self.metrics.submitted = self.metrics.submitted.saturating_add(1);
        self.route_event(RouterEvent::LocalSubmit(envelope))?;
        self.flush_store(TimestampMs(0))
    }

    pub fn tick(&mut self, now: TimestampMs) -> Result<(), GatewayError> {
        self.route_event(RouterEvent::Tick { now_ms: now })?;
        self.flush_store(now)
    }

    pub fn set_link_up(&mut self, link_id: LinkId, up: bool) -> Result<(), GatewayError> {
        let event = {
            let (left, right) = self.loopback.split();
            endpoint_for_link(left, right, link_id)?.set_up(up)
        };
        self.route_event(RouterEvent::Link(event))?;
        if up {
            self.flush_store(TimestampMs(0))?;
        }
        Ok(())
    }

    fn route_event(&mut self, event: RouterEvent<'a>) -> Result<(), GatewayError> {
        let mut commands = [dummy_command(); ROUTER_COMMAND_CAPACITY];
        let count = self.router.handle_event(event, &mut commands)?;
        self.execute_commands(&commands[..count])
    }

    fn execute_commands(&mut self, commands: &[RouterCommand<'a>]) -> Result<(), GatewayError> {
        for command in commands {
            self.execute_command(*command)?;
        }
        Ok(())
    }

    fn execute_command(&mut self, command: RouterCommand<'a>) -> Result<(), GatewayError> {
        match command {
            RouterCommand::Send { link_id, envelope } => self.send_envelope(link_id, envelope),
            RouterCommand::Store(RouterStoreCommand::Put(envelope)) => {
                if self.config.policy.allow_store_and_forward {
                    self.store.put(envelope)?;
                    self.metrics.stored = self.metrics.stored.saturating_add(1);
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
                self.last_delivered = Some(envelope);
                self.metrics.delivered = self.metrics.delivered.saturating_add(1);
                Ok(())
            }
        }
    }

    fn send_envelope(
        &mut self,
        link_id: LinkId,
        envelope: HyfEnvelopeRef<'a>,
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

    fn flush_store(&mut self, _now: TimestampMs) -> Result<(), GatewayError> {
        while let Some(stored) = self.store.first_pending() {
            let Some(link_id) = self.first_up_link_id() else {
                break;
            };
            let message_id = stored.envelope.message_id;
            self.send_envelope(link_id, stored.envelope)?;
            self.store.remove(message_id)?;
        }
        Ok(())
    }

    fn first_up_link_id(&mut self) -> Option<LinkId> {
        let (left, right) = self.loopback.split();
        if left.is_up() && right.is_up() {
            Some(left.link_id())
        } else {
            None
        }
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

    type TestRuntime<'a> = GatewayRuntime<'a, 2, 8, 4, 4>;

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
            runtime.last_delivered().map(|envelope| envelope.message_id),
            Some(MessageId([1; 32]))
        );
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
        assert!(debug.contains("<redacted>"));
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
