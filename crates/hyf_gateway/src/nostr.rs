use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{Link, LinkClass, LinkDriverErrorKind, LinkId};
use hyf_link_nostr::{
    FakeNostrRelay, HYF_NOSTR_MAX_CONTENT_CHARS, HyfNostrEventBuffers, NostrError, NostrPublicKey,
    NostrPublishOutcome, NostrSecretKey, NostrTagRef, sign_hyf_nostr_event,
};

use crate::{GatewayError, GatewayLinkExecutor};

pub struct NostrGatewayExecutor<R> {
    link_id: LinkId,
    mtu: usize,
    up: bool,
    author_secret: NostrSecretKey,
    recipient_pubkey: NostrPublicKey,
    relay: R,
}

impl<R> NostrGatewayExecutor<R> {
    pub const fn new(
        link_id: LinkId,
        mtu: usize,
        relay: R,
        author_secret: NostrSecretKey,
        recipient_pubkey: NostrPublicKey,
    ) -> Self {
        Self {
            link_id,
            mtu,
            up: false,
            author_secret,
            recipient_pubkey,
            relay,
        }
    }

    pub const fn link_id(&self) -> LinkId {
        self.link_id
    }

    pub const fn link_class(&self) -> LinkClass {
        LinkClass::Nostr
    }

    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    pub const fn is_up(&self) -> bool {
        self.up
    }

    pub const fn recipient_pubkey(&self) -> NostrPublicKey {
        self.recipient_pubkey
    }

    pub fn set_up(&mut self, up: bool) {
        self.up = up;
    }

    pub const fn relay(&self) -> &R {
        &self.relay
    }

    pub fn relay_mut(&mut self) -> &mut R {
        &mut self.relay
    }

    pub fn into_relay(self) -> R {
        self.relay
    }
}

impl<R> fmt::Debug for NostrGatewayExecutor<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrGatewayExecutor")
            .field("link_id", &self.link_id)
            .field("link_class", &LinkClass::Nostr)
            .field("mtu", &self.mtu)
            .field("up", &self.up)
            .field("recipient_pubkey", &self.recipient_pubkey)
            .finish()
    }
}

impl<R> Link for NostrGatewayExecutor<R> {
    fn link_id(&self) -> LinkId {
        self.link_id
    }

    fn link_class(&self) -> LinkClass {
        LinkClass::Nostr
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

impl<
    'a,
    const EVENT_CAPACITY: usize,
    const SUBSCRIPTION_CAPACITY: usize,
    const OUTPUT_CAPACITY: usize,
> GatewayLinkExecutor
    for NostrGatewayExecutor<
        FakeNostrRelay<'a, EVENT_CAPACITY, SUBSCRIPTION_CAPACITY, OUTPUT_CAPACITY>,
    >
{
    fn send_link_bytes(
        &mut self,
        link_id: LinkId,
        bytes: &[u8],
        now_ms: TimestampMs,
    ) -> Result<(), GatewayError> {
        if link_id != self.link_id {
            return Err(GatewayError::UnsupportedLink { link_id });
        }
        if !self.up {
            return Err(GatewayError::Driver {
                link_id,
                kind: LinkDriverErrorKind::LinkDown,
            });
        }
        if bytes.len() > self.mtu {
            return Err(GatewayError::Driver {
                link_id,
                kind: LinkDriverErrorKind::FrameTooLarge,
            });
        }

        let buffers = leaked_event_buffers(link_id)?;
        let event = sign_hyf_nostr_event(
            bytes,
            &self.author_secret,
            self.recipient_pubkey,
            now_ms.0 / 1000,
            buffers,
        )
        .map_err(|error| map_nostr_send_error(link_id, error))?;
        let mut decode_buffer = [0; crate::GATEWAY_FRAME_BUFFER_LEN];
        match self
            .relay
            .publish(event, &mut decode_buffer)
            .map_err(|error| map_nostr_send_error(link_id, error))?
        {
            NostrPublishOutcome::Accepted { .. }
            | NostrPublishOutcome::AcceptedDuplicate { .. } => Ok(()),
            NostrPublishOutcome::Rejected { .. } => Err(GatewayError::Driver {
                link_id,
                kind: LinkDriverErrorKind::Protocol,
            }),
        }
    }
}

fn leaked_event_buffers(link_id: LinkId) -> Result<HyfNostrEventBuffers<'static>, GatewayError> {
    let dummy_values = Box::leak(Box::new(["_"]));
    let dummy =
        NostrTagRef::new(dummy_values).map_err(|error| map_nostr_send_error(link_id, error))?;
    Ok(HyfNostrEventBuffers {
        content: Box::leak(Box::new([0; HYF_NOSTR_MAX_CONTENT_CHARS])),
        recipient_hex: Box::leak(Box::new([0; 64])),
        p_tag_values: Box::leak(Box::new(["", ""])),
        t_tag_values: Box::leak(Box::new(["", ""])),
        alt_tag_values: Box::leak(Box::new(["", ""])),
        tags: Box::leak(Box::new([dummy; 3])),
    })
}

fn map_nostr_send_error(link_id: LinkId, error: NostrError) -> GatewayError {
    let kind = match error {
        NostrError::RelayEventStoreFull { .. } | NostrError::RelayOutputFull { .. } => {
            LinkDriverErrorKind::Backpressure
        }
        NostrError::ContentTooLarge { .. }
        | NostrError::EnvelopeTooLarge { .. }
        | NostrError::OutputTooSmall { .. } => LinkDriverErrorKind::FrameTooLarge,
        _ => LinkDriverErrorKind::Protocol,
    };
    GatewayError::Driver { link_id, kind }
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_link::{Link, LinkDriverErrorKind, LinkId};
    use hyf_link_nostr::{
        FakeNostrRelay, HYF_NOSTR_ENVELOPE_KIND, NostrFilter, NostrPublicKey, NostrRelayStatus,
        NostrRelayStatusPrefix, NostrSecretKey, verify_and_decode_hyf_nostr_event,
    };
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, encode_envelope,
    };

    use super::NostrGatewayExecutor;
    use crate::{GatewayError, GatewayLinkExecutor};

    const NOSTR_LINK: LinkId = LinkId([0x51; 16]);
    const OTHER_LINK: LinkId = LinkId([0x52; 16]);
    const RECIPIENT: NostrPublicKey = NostrPublicKey::from_bytes([0x77; 32]);

    #[test]
    fn nostr_gateway_executor_exposes_link_metadata() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);

        assert_eq!(executor.link_id(), NOSTR_LINK);
        assert_eq!(Link::link_class(&executor), hyf_link::LinkClass::Nostr);
        assert_eq!(executor.mtu(), 2048);
        assert_eq!(executor.recipient_pubkey(), RECIPIENT);
        assert!(!executor.is_up());
        executor.set_up(true);
        assert!(executor.is_up());
        assert_eq!(executor.relay().event_capacity(), 1);
    }

    #[test]
    fn nostr_gateway_executor_debug_omits_relay_payloads() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let debug = format!("{executor:?}");

        assert!(debug.contains("NostrGatewayExecutor"));
        assert!(debug.contains("link_id"));
        assert!(!debug.contains("content"));
        assert!(!debug.contains("payload"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn nostr_gateway_executor_rejects_unsupported_link_ids() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);

        assert_eq!(
            executor.send_link_bytes(OTHER_LINK, b"frame", hyf_core::TimestampMs(1)),
            Err(GatewayError::UnsupportedLink {
                link_id: OTHER_LINK,
            })
        );
    }

    #[test]
    fn nostr_gateway_executor_rejects_wrong_state_and_oversize_frames() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 4, relay, fixture_secret(), RECIPIENT);

        assert_eq!(
            executor.send_link_bytes(NOSTR_LINK, b"frame", hyf_core::TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind: LinkDriverErrorKind::LinkDown,
            })
        );

        executor.set_up(true);
        assert_eq!(
            executor.send_link_bytes(NOSTR_LINK, b"frames", hyf_core::TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind: LinkDriverErrorKind::FrameTooLarge,
            })
        );
    }

    #[test]
    fn nostr_gateway_executor_publishes_signed_hyf_events() -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<2, 1, 4>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;

        executor.set_up(true);
        executor.send_link_bytes(NOSTR_LINK, &encoded[..len], TimestampMs(1_720_000_000_123))?;

        assert_eq!(executor.relay().stored_event_count(), 1);
        assert!(matches!(
            executor.relay_mut().pop_output(),
            Some(hyf_link_nostr::FakeNostrRelayOutput::Ok {
                accepted: true,
                status: NostrRelayStatus {
                    prefix: NostrRelayStatusPrefix::Unknown,
                    ..
                },
                ..
            })
        ));

        let kinds = [HYF_NOSTR_ENVELOPE_KIND];
        let filters = [NostrFilter {
            kinds: &kinds,
            ..NostrFilter::empty()
        }];
        if executor.relay_mut().subscribe("sub-1", &filters).is_err() {
            return Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind: LinkDriverErrorKind::Protocol,
            });
        }
        let event = match executor.relay_mut().pop_output() {
            Some(hyf_link_nostr::FakeNostrRelayOutput::Event { event, .. }) => event,
            _ => {
                return Err(GatewayError::Driver {
                    link_id: NOSTR_LINK,
                    kind: LinkDriverErrorKind::Protocol,
                });
            }
        };
        assert_eq!(event.created_at, 1_720_000_000);
        assert!(verify_and_decode_hyf_nostr_event(&event, &mut [0; 256]).is_ok());
        Ok(())
    }

    #[test]
    fn nostr_gateway_executor_maps_full_relay_to_recoverable_backpressure()
    -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<0, 0, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;

        executor.set_up(true);
        assert_eq!(
            executor.send_link_bytes(NOSTR_LINK, &encoded[..len], TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind: LinkDriverErrorKind::Backpressure,
            })
        );
        Ok(())
    }

    fn sample_envelope<'a>() -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([0x11; 32]),
            source: NodeId([0x22; 32]),
            destination: HyfDestination::Node(NodeId([0x33; 32])),
            created_at_ms: TimestampMs(1_720_000_000_123),
            expires_at_ms: TimestampMs(1_720_000_100_000),
            hop_limit: 4,
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"hello",
        }
    }

    fn fixture_secret() -> NostrSecretKey {
        let mut secret_key = [0; 32];
        secret_key[31] = 3;
        NostrSecretKey::from_bytes(secret_key)
    }
}
