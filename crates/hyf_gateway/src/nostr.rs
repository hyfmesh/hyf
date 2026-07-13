use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{Link, LinkClass, LinkDriverErrorKind, LinkFrameRef, LinkId};
use hyf_link_nostr::{
    FakeNostrRelay, FakeNostrRelayOutput, HYF_NOSTR_MAX_CONTENT_CHARS, HyfNostrEventBuffers,
    NostrError, NostrEvent, NostrPublicKey, NostrPublishOutcome, NostrSecretKey, NostrTagRef,
    sign_hyf_nostr_event, verify_and_decode_hyf_nostr_event,
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

impl<
    'a,
    const EVENT_CAPACITY: usize,
    const SUBSCRIPTION_CAPACITY: usize,
    const OUTPUT_CAPACITY: usize,
> NostrGatewayExecutor<FakeNostrRelay<'a, EVENT_CAPACITY, SUBSCRIPTION_CAPACITY, OUTPUT_CAPACITY>>
{
    pub fn poll_relay_frame<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<Option<LinkFrameRef<'out>>, GatewayError> {
        if !self.up {
            return Err(GatewayError::Driver {
                link_id: self.link_id,
                kind: LinkDriverErrorKind::LinkDown,
            });
        }

        while let Some(message) = self.relay.pop_output() {
            if let FakeNostrRelayOutput::Event { event, .. } = message {
                return self.decode_relay_event(event, output).map(Some);
            }
        }

        Ok(None)
    }

    fn decode_relay_event<'out>(
        &self,
        event: NostrEvent<'_>,
        output: &'out mut [u8],
    ) -> Result<LinkFrameRef<'out>, GatewayError> {
        let received_at_ms = event
            .created_at
            .checked_mul(1000)
            .ok_or(GatewayError::Driver {
                link_id: self.link_id,
                kind: LinkDriverErrorKind::Protocol,
            })?;
        verify_and_decode_hyf_nostr_event(&event, output)
            .map_err(|error| map_nostr_receive_error(self.link_id, error))?;
        Ok(LinkFrameRef::new(
            self.link_id,
            TimestampMs(received_at_ms),
            &output[..event.content.len() / 2],
        ))
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

fn map_nostr_receive_error(link_id: LinkId, error: NostrError) -> GatewayError {
    let kind = match error {
        NostrError::OutputTooSmall { .. } => LinkDriverErrorKind::OutputTooSmall,
        _ => LinkDriverErrorKind::Protocol,
    };
    GatewayError::Driver { link_id, kind }
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_link::{Link, LinkDriverErrorKind, LinkId};
    use hyf_link_nostr::{
        FakeNostrRelay, FakeNostrRelayOutput, HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS,
        NostrEvent, NostrFilter, NostrPublicKey, NostrRelayStatus, NostrRelayStatusPrefix,
        NostrSecretKey, NostrSignature, NostrTagRef, NostrTagsRef, NostrUnsignedEvent,
        derive_nostr_public_key, encode_hyf_envelope_content, sign_event, sign_hyf_nostr_event,
        verify_and_decode_hyf_nostr_event,
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
    fn nostr_gateway_executor_polls_verified_relay_events() -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<2, 1, 4>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;
        let kinds = [HYF_NOSTR_ENVELOPE_KIND];
        let filters = [NostrFilter {
            kinds: &kinds,
            ..NostrFilter::empty()
        }];
        let mut frame = [0; 256];

        executor.set_up(true);
        executor.send_link_bytes(NOSTR_LINK, &encoded[..len], TimestampMs(1_720_000_000_123))?;
        if executor.relay_mut().subscribe("sub-1", &filters).is_err() {
            return Err(protocol_error());
        }

        let inbound = match executor.poll_relay_frame(&mut frame)? {
            Some(frame) => frame,
            None => return Err(protocol_error()),
        };

        assert_eq!(inbound.link_id, NOSTR_LINK);
        assert_eq!(inbound.received_at_ms, TimestampMs(1_720_000_000_000));
        assert_eq!(inbound.bytes, &encoded[..len]);
        Ok(())
    }

    #[test]
    fn nostr_gateway_executor_rejects_invalid_inbound_events() -> Result<(), GatewayError> {
        assert_poll_rejects(tampered_signature_event()?, LinkDriverErrorKind::Protocol)?;

        let wrong_kind = signed_custom_content_event(1, valid_content_static()?, 1_720_000_000)?;
        assert_poll_rejects(wrong_kind, LinkDriverErrorKind::Protocol)?;

        assert_poll_rejects(
            signed_custom_content_event(HYF_NOSTR_ENVELOPE_KIND, "zz", 1_720_000_000)?,
            LinkDriverErrorKind::Protocol,
        )?;
        assert_poll_rejects(
            signed_custom_content_event(HYF_NOSTR_ENVELOPE_KIND, "00", 1_720_000_000)?,
            LinkDriverErrorKind::Protocol,
        )?;
        assert_poll_rejects(signed_valid_event(u64::MAX)?, LinkDriverErrorKind::Protocol)?;
        assert_poll_rejects_with_short_output(
            signed_valid_event(1_720_000_000)?,
            LinkDriverErrorKind::OutputTooSmall,
        )
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

    fn signed_valid_event(created_at: u64) -> Result<NostrEvent<'static>, GatewayError> {
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;
        sign_hyf_nostr_event(
            &encoded[..len],
            &fixture_secret(),
            RECIPIENT,
            created_at,
            super::leaked_event_buffers(NOSTR_LINK)?,
        )
        .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))
    }

    fn tampered_signature_event() -> Result<NostrEvent<'static>, GatewayError> {
        let event = signed_valid_event(1_720_000_000)?;
        let mut signature = *event.sig.as_bytes();
        signature[0] ^= 0x01;
        Ok(NostrEvent {
            sig: NostrSignature::from_bytes(signature),
            ..event
        })
    }

    fn signed_custom_content_event(
        kind: u16,
        content: &'static str,
        created_at: u64,
    ) -> Result<NostrEvent<'static>, GatewayError> {
        let secret = fixture_secret();
        let recipient_hex_buf = Box::leak(Box::new([0; 64]));
        let recipient_hex = RECIPIENT
            .write_hex(recipient_hex_buf)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        let p_tag_values = Box::leak(Box::new(["p", recipient_hex]));
        let p_tag = NostrTagRef::new(p_tag_values)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        let tags = Box::leak(Box::new([p_tag]));
        let unsigned = NostrUnsignedEvent::new(
            derive_nostr_public_key(&secret)
                .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?,
            created_at,
            kind,
            NostrTagsRef::new(tags),
            content,
        )
        .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        sign_event(unsigned, &secret)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))
    }

    fn assert_poll_rejects(
        event: NostrEvent<'static>,
        kind: LinkDriverErrorKind,
    ) -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<0, 0, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut frame = [0; 256];

        executor.set_up(true);
        executor
            .relay_mut()
            .enqueue_output(FakeNostrRelayOutput::Event {
                subscription_id: "sub-1",
                event,
            })
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        assert_eq!(
            executor.poll_relay_frame(&mut frame),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind,
            })
        );
        Ok(())
    }

    fn assert_poll_rejects_with_short_output(
        event: NostrEvent<'static>,
        kind: LinkDriverErrorKind,
    ) -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<0, 0, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut frame = [0; 1];

        executor.set_up(true);
        executor
            .relay_mut()
            .enqueue_output(FakeNostrRelayOutput::Event {
                subscription_id: "sub-1",
                event,
            })
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        assert_eq!(
            executor.poll_relay_frame(&mut frame),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind,
            })
        );
        Ok(())
    }

    fn valid_content_static() -> Result<&'static str, GatewayError> {
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;
        let content = Box::leak(Box::new([0; HYF_NOSTR_MAX_CONTENT_CHARS]));
        encode_hyf_envelope_content(&encoded[..len], content)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))
    }

    fn protocol_error() -> GatewayError {
        GatewayError::Driver {
            link_id: NOSTR_LINK,
            kind: LinkDriverErrorKind::Protocol,
        }
    }
}
