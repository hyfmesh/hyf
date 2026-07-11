use core::fmt;

use hyf_config::GatewayConfig;
use hyf_core::{MessageId, TimestampMs};
use hyf_link::{LinkFrameRef, LinkId};
use hyf_link_loopback::{
    LOOPBACK_LEFT_ID, LOOPBACK_MAX_FRAME_LEN, LOOPBACK_RIGHT_ID, LoopbackDriver, LoopbackError,
};
use hyf_wire::HyfEnvelopeRef;

use crate::{GatewayCore, GatewayError, GatewayLinkExecutor, GatewayMetrics};

pub struct GatewayRuntime<
    const MAX_LINKS: usize,
    const MAX_SEEN: usize,
    const STORE_CAPACITY: usize,
    const LOOPBACK_QUEUE: usize,
> {
    core: GatewayCore<MAX_LINKS, MAX_SEEN, STORE_CAPACITY>,
    loopback: LoopbackDriver<LOOPBACK_QUEUE>,
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
            .field("core", &self.core)
            .field("loopback", &self.loopback)
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
        validate_supported_links(&config)?;
        let mtu = first_link_mtu(&config);
        let core = GatewayCore::new(config)?;
        let mut runtime = Self {
            core,
            loopback: LoopbackDriver::left(mtu),
        };
        runtime.activate_configured_links()?;
        Ok(runtime)
    }

    pub fn metrics(&self) -> GatewayMetrics {
        self.core.metrics()
    }

    pub fn now_ms(&self) -> TimestampMs {
        self.core.now_ms()
    }

    pub fn last_delivered_message_id(&self) -> Option<MessageId> {
        self.core.last_delivered_message_id()
    }

    pub fn last_delivered_payload_len(&self) -> usize {
        self.core.last_delivered_payload_len()
    }

    pub fn stored_len(&self) -> usize {
        self.core.stored_len()
    }

    pub fn loopback_queued_len(&self, link_id: LinkId) -> Result<usize, GatewayError> {
        self.loopback
            .queued_len(link_id)
            .map_err(map_loopback_error)
    }

    pub fn receive_loopback_frame<'b>(
        &mut self,
        link_id: LinkId,
        output: &'b mut [u8],
    ) -> Result<Option<LinkFrameRef<'b>>, GatewayError> {
        self.loopback
            .receive_link_frame(link_id, output)
            .map_err(map_loopback_error)
    }

    pub fn ingest_link_frame(&mut self, frame: LinkFrameRef<'_>) -> Result<(), GatewayError> {
        self.core.ingest_link_frame(frame, &mut self.loopback)
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
        self.core.submit(envelope, &mut self.loopback)
    }

    pub fn tick(&mut self, now: TimestampMs) -> Result<(), GatewayError> {
        self.core.tick(now, &mut self.loopback)
    }

    pub fn set_link_up(&mut self, link_id: LinkId, up: bool) -> Result<(), GatewayError> {
        let event = self
            .loopback
            .set_link_up(link_id, up)
            .map_err(map_loopback_error)?;
        self.core.handle_link_event(event, &mut self.loopback)
    }

    fn activate_configured_links(&mut self) -> Result<(), GatewayError> {
        let config = self.core.config();
        for link in config.links.as_slice().iter().flatten() {
            if link.enabled {
                self.set_link_up(link.link_id, true)?;
            }
        }
        Ok(())
    }
}

impl<const N: usize> GatewayLinkExecutor for LoopbackDriver<N> {
    fn send_link_bytes(
        &mut self,
        link_id: LinkId,
        bytes: &[u8],
        now_ms: TimestampMs,
    ) -> Result<(), GatewayError> {
        self.send_link_bytes(link_id, bytes, now_ms)
            .map_err(map_loopback_error)
    }
}

fn map_loopback_error(error: LoopbackError) -> GatewayError {
    match error {
        LoopbackError::LinkMismatch { actual, .. } => {
            GatewayError::UnsupportedLink { link_id: actual }
        }
        error => GatewayError::Loopback(error),
    }
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
    LOOPBACK_MAX_FRAME_LEN
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
        assert_eq!(runtime.stored_len(), 1);

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
    fn runtime_counts_received_frames() -> Result<(), GatewayError> {
        let mut runtime = TestRuntime::new(valid_config())?;
        let envelope = sample_envelope(MessageId([3; 32]), local(), 100, 200, b"inbound");
        let mut encoded = [0; GATEWAY_FRAME_BUFFER_LEN];
        let len = hyf_wire::encode_envelope(envelope, &mut encoded)?;

        runtime.ingest_link_frame(hyf_link::LinkFrameRef::new(
            LOOPBACK_LEFT_ID,
            TimestampMs(150),
            &encoded[..len],
        ))?;

        assert_eq!(runtime.metrics().received, 1);
        assert_eq!(runtime.metrics().delivered, 1);
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
        assert!(debug.contains("GatewayCore"));
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
