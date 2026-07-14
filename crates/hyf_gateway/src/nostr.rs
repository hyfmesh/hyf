use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{Link, LinkClass, LinkDriverErrorKind, LinkFrameRef, LinkId};
use hyf_link_nostr::{
    FakeNostrRelay, FakeNostrRelayControlOutput, FakeNostrRelayOutput, HyfNostrEventScratch,
    NostrError, NostrEvent, NostrPublicKey, NostrPublishOutcome, NostrRelayStatus,
    NostrRelayStatusPrefix, NostrSecretKey, verify_and_decode_hyf_nostr_event,
    with_signed_hyf_nostr_event,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrGatewayRelayOutput<'frame, 'control> {
    Frame(LinkFrameRef<'frame>),
    Ok {
        event_id: hyf_link_nostr::NostrEventId,
        accepted: bool,
        status: NostrRelayStatus<'control>,
    },
    Eose {
        subscription_id: &'control str,
    },
    Closed {
        subscription_id: &'control str,
        status: NostrRelayStatus<'control>,
    },
    Notice {
        message: &'control str,
    },
    Auth {
        challenge: &'control str,
    },
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
    pub fn poll_relay_output<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<Option<NostrGatewayRelayOutput<'out, 'a>>, GatewayError> {
        if !self.up {
            return Err(GatewayError::Driver {
                link_id: self.link_id,
                kind: LinkDriverErrorKind::LinkDown,
            });
        }

        let Some(is_event) = self
            .relay
            .with_next_output(|message| match message {
                FakeNostrRelayOutput::Event { .. } => true,
                _ => false,
            })
            .map_err(|error| map_nostr_receive_error(self.link_id, error))?
        else {
            return Ok(None);
        };

        if !is_event {
            let output = self.next_control_output()?;
            self.relay.consume_output();
            return Ok(Some(output));
        }

        let output = self
            .relay
            .with_next_output(|message| match message {
                FakeNostrRelayOutput::Event { event, .. } => {
                    decode_relay_event(self.link_id, event, output)
                        .map(NostrGatewayRelayOutput::Frame)
                }
                _ => Err(GatewayError::Driver {
                    link_id: self.link_id,
                    kind: LinkDriverErrorKind::Protocol,
                }),
            })
            .map_err(|error| map_nostr_receive_error(self.link_id, error))?
            .ok_or(GatewayError::Driver {
                link_id: self.link_id,
                kind: LinkDriverErrorKind::Protocol,
            })?;

        match output {
            Ok(output) => {
                self.relay.consume_output();
                Ok(Some(output))
            }
            Err(error) => {
                if !is_output_too_small(error) {
                    self.relay.consume_output();
                }
                Err(error)
            }
        }
    }

    fn next_control_output(&self) -> Result<NostrGatewayRelayOutput<'static, 'a>, GatewayError> {
        match self
            .relay
            .next_control_output()
            .ok_or(GatewayError::Driver {
                link_id: self.link_id,
                kind: LinkDriverErrorKind::Protocol,
            })? {
            FakeNostrRelayControlOutput::Ok {
                event_id,
                accepted,
                status,
            } => Ok(NostrGatewayRelayOutput::Ok {
                event_id,
                accepted,
                status,
            }),
            FakeNostrRelayControlOutput::Eose { subscription_id } => {
                Ok(NostrGatewayRelayOutput::Eose { subscription_id })
            }
            FakeNostrRelayControlOutput::Closed {
                subscription_id,
                status,
            } => Ok(NostrGatewayRelayOutput::Closed {
                subscription_id,
                status,
            }),
            FakeNostrRelayControlOutput::Notice { message } => {
                Ok(NostrGatewayRelayOutput::Notice { message })
            }
            FakeNostrRelayControlOutput::Auth { challenge } => {
                Ok(NostrGatewayRelayOutput::Auth { challenge })
            }
        }
    }
}

fn decode_relay_event<'out>(
    link_id: LinkId,
    event: NostrEvent<'_>,
    output: &'out mut [u8],
) -> Result<LinkFrameRef<'out>, GatewayError> {
    let received_at_ms = event
        .created_at
        .checked_mul(1000)
        .ok_or(GatewayError::Driver {
            link_id,
            kind: LinkDriverErrorKind::Protocol,
        })?;
    verify_and_decode_hyf_nostr_event(&event, output)
        .map_err(|error| map_nostr_receive_error(link_id, error))?;
    Ok(LinkFrameRef::new(
        link_id,
        TimestampMs(received_at_ms),
        &output[..event.content.len() / 2],
    ))
}

fn is_output_too_small(error: GatewayError) -> bool {
    matches!(
        error,
        GatewayError::Driver {
            kind: LinkDriverErrorKind::OutputTooSmall,
            ..
        }
    )
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

        let mut scratch = HyfNostrEventScratch::new();
        let mut decode_buffer = [0; crate::GATEWAY_FRAME_BUFFER_LEN];
        let author_secret = &self.author_secret;
        let recipient_pubkey = self.recipient_pubkey;
        let relay = &mut self.relay;

        with_signed_hyf_nostr_event(
            bytes,
            author_secret,
            recipient_pubkey,
            now_ms.0 / 1000,
            &mut scratch,
            |event| match relay
                .publish(event, &mut decode_buffer)
                .map_err(|error| map_nostr_send_error(link_id, error))?
            {
                NostrPublishOutcome::Accepted { .. }
                | NostrPublishOutcome::AcceptedDuplicate { .. } => Ok(()),
                NostrPublishOutcome::Rejected { status } => {
                    Err(map_relay_rejection(link_id, status))
                }
            },
        )
        .map_err(|error| map_nostr_send_error(link_id, error))?
    }
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

fn map_relay_rejection(link_id: LinkId, status: NostrRelayStatus<'_>) -> GatewayError {
    let kind = match status.prefix {
        NostrRelayStatusPrefix::RateLimited | NostrRelayStatusPrefix::Pow => {
            LinkDriverErrorKind::Backpressure
        }
        NostrRelayStatusPrefix::AuthRequired => LinkDriverErrorKind::LinkDown,
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
        HyfNostrEventScratch, NostrEventId, NostrFilter, NostrPublicKey, NostrRelayStatus,
        NostrRelayStatusPrefix, NostrSecretKey, NostrSignature, NostrTagRef, NostrTagsRef,
        NostrUnsignedEvent, derive_nostr_public_key, encode_hyf_envelope_content, sign_event,
        verify_and_decode_hyf_nostr_event, with_signed_hyf_nostr_event,
    };
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, encode_envelope,
    };

    use super::{NostrGatewayExecutor, NostrGatewayRelayOutput};
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
        assert_eq!(
            executor
                .relay_mut()
                .pop_next_output(|output| matches!(
                    output,
                    hyf_link_nostr::FakeNostrRelayOutput::Ok {
                        accepted: true,
                        status: NostrRelayStatus {
                            prefix: NostrRelayStatusPrefix::Unknown,
                            ..
                        },
                        ..
                    }
                ))
                .map_err(|error| super::map_nostr_receive_error(NOSTR_LINK, error))?,
            Some(true)
        );

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
        let replay_valid = executor
            .relay_mut()
            .pop_next_output(|output| match output {
                hyf_link_nostr::FakeNostrRelayOutput::Event { event, .. } => {
                    event.created_at == 1_720_000_000
                        && verify_and_decode_hyf_nostr_event(&event, &mut [0; 256]).is_ok()
                }
                _ => false,
            })
            .map_err(|error| super::map_nostr_receive_error(NOSTR_LINK, error))?;
        assert_eq!(replay_valid, Some(true));
        Ok(())
    }

    #[test]
    fn nostr_gateway_executor_repeated_sends_use_bounded_scratch() -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<3, 1, 4>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;

        executor.set_up(true);
        executor.send_link_bytes(NOSTR_LINK, &encoded[..len], TimestampMs(1_720_000_000_123))?;
        executor.send_link_bytes(NOSTR_LINK, &encoded[..len], TimestampMs(1_720_000_001_123))?;

        assert_eq!(executor.relay().stored_event_count(), 2);
        assert_eq!(executor.relay().metrics().stored_events, 2);
        Ok(())
    }

    #[test]
    fn nostr_gateway_production_source_has_no_leak_helpers() {
        let source = include_str!("nostr.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(!production.contains("Box::leak"));
        assert!(!production.contains("leaked_event_buffers"));
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
        assert!(matches!(
            executor.poll_relay_output(&mut frame)?,
            Some(NostrGatewayRelayOutput::Ok { accepted: true, .. })
        ));
        if executor.relay_mut().subscribe("sub-1", &filters).is_err() {
            return Err(protocol_error());
        }

        let inbound = match executor.poll_relay_output(&mut frame)? {
            Some(NostrGatewayRelayOutput::Frame(frame)) => frame,
            None => return Err(protocol_error()),
            _ => return Err(protocol_error()),
        };

        assert_eq!(inbound.link_id, NOSTR_LINK);
        assert_eq!(inbound.received_at_ms, TimestampMs(1_720_000_000_000));
        assert_eq!(inbound.bytes, &encoded[..len]);
        Ok(())
    }

    #[test]
    fn nostr_gateway_executor_surfaces_typed_control_outputs() -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<0, 0, 8>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let status = NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::AuthRequired,
            raw_prefix: "auth-required",
            detail: "auth needed",
        };
        let event_id = NostrEventId::from_bytes([0x44; 32]);
        let mut frame = [0; 256];

        executor.set_up(true);
        executor
            .relay_mut()
            .enqueue_output(FakeNostrRelayOutput::Ok {
                event_id,
                accepted: true,
                status,
            })
            .map_err(|error| super::map_nostr_receive_error(NOSTR_LINK, error))?;
        executor
            .relay_mut()
            .enqueue_output(FakeNostrRelayOutput::Eose {
                subscription_id: "sub-1",
            })
            .map_err(|error| super::map_nostr_receive_error(NOSTR_LINK, error))?;
        executor
            .relay_mut()
            .inject_closed("sub-1", status)
            .map_err(|error| super::map_nostr_receive_error(NOSTR_LINK, error))?;
        executor
            .relay_mut()
            .enqueue_notice("relay notice")
            .map_err(|error| super::map_nostr_receive_error(NOSTR_LINK, error))?;
        executor
            .relay_mut()
            .inject_auth_challenge("challenge-token")
            .map_err(|error| super::map_nostr_receive_error(NOSTR_LINK, error))?;

        assert_eq!(
            executor.poll_relay_output(&mut frame)?,
            Some(NostrGatewayRelayOutput::Ok {
                event_id,
                accepted: true,
                status,
            })
        );
        assert_eq!(
            executor.poll_relay_output(&mut frame)?,
            Some(NostrGatewayRelayOutput::Eose {
                subscription_id: "sub-1",
            })
        );
        assert_eq!(
            executor.poll_relay_output(&mut frame)?,
            Some(NostrGatewayRelayOutput::Closed {
                subscription_id: "sub-1",
                status,
            })
        );
        assert_eq!(
            executor.poll_relay_output(&mut frame)?,
            Some(NostrGatewayRelayOutput::Notice {
                message: "relay notice",
            })
        );
        assert_eq!(
            executor.poll_relay_output(&mut frame)?,
            Some(NostrGatewayRelayOutput::Auth {
                challenge: "challenge-token",
            })
        );
        assert_eq!(executor.poll_relay_output(&mut frame)?, None);
        Ok(())
    }

    #[test]
    fn nostr_gateway_executor_rejects_invalid_inbound_events() -> Result<(), GatewayError> {
        assert_poll_rejects_with(
            |executor| enqueue_tampered_signature_event(executor),
            LinkDriverErrorKind::Protocol,
        )?;
        assert_poll_rejects_with(
            |executor| enqueue_signed_valid_content_event(executor, 1, 1_720_000_000),
            LinkDriverErrorKind::Protocol,
        )?;
        assert_poll_rejects_with(
            |executor| {
                enqueue_signed_custom_content_event(
                    executor,
                    HYF_NOSTR_ENVELOPE_KIND,
                    "zz",
                    1_720_000_000,
                )
            },
            LinkDriverErrorKind::Protocol,
        )?;
        assert_poll_rejects_with(
            |executor| {
                enqueue_signed_custom_content_event(
                    executor,
                    HYF_NOSTR_ENVELOPE_KIND,
                    "00",
                    1_720_000_000,
                )
            },
            LinkDriverErrorKind::Protocol,
        )?;
        assert_poll_rejects_with(
            |executor| enqueue_signed_valid_event(executor, u64::MAX),
            LinkDriverErrorKind::Protocol,
        )?;
        assert_poll_rejects_with_short_output(
            |executor| enqueue_signed_valid_event(executor, 1_720_000_000),
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

    fn enqueue_signed_valid_event(
        executor: &mut NostrGatewayExecutor<FakeNostrRelay<'static, 0, 0, 1>>,
        created_at: u64,
    ) -> Result<(), GatewayError> {
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;
        let mut scratch = HyfNostrEventScratch::new();
        with_signed_hyf_nostr_event(
            &encoded[..len],
            &fixture_secret(),
            RECIPIENT,
            created_at,
            &mut scratch,
            |event| executor.relay_mut().enqueue_event_output("sub-1", event),
        )
        .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?
        .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))
    }

    fn enqueue_tampered_signature_event(
        executor: &mut NostrGatewayExecutor<FakeNostrRelay<'static, 0, 0, 1>>,
    ) -> Result<(), GatewayError> {
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;
        let mut scratch = HyfNostrEventScratch::new();
        with_signed_hyf_nostr_event(
            &encoded[..len],
            &fixture_secret(),
            RECIPIENT,
            1_720_000_000,
            &mut scratch,
            |event| {
                let mut signature = *event.sig.as_bytes();
                signature[0] ^= 0x01;
                executor.relay_mut().enqueue_event_output(
                    "sub-1",
                    hyf_link_nostr::NostrEvent {
                        sig: NostrSignature::from_bytes(signature),
                        ..event
                    },
                )
            },
        )
        .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?
        .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))
    }

    fn enqueue_signed_valid_content_event(
        executor: &mut NostrGatewayExecutor<FakeNostrRelay<'static, 0, 0, 1>>,
        kind: u16,
        created_at: u64,
    ) -> Result<(), GatewayError> {
        let mut encoded = [0; 128];
        let len = encode_envelope(sample_envelope(), &mut encoded)?;
        let mut content = [0; HYF_NOSTR_MAX_CONTENT_CHARS];
        let content = encode_hyf_envelope_content(&encoded[..len], &mut content)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        enqueue_signed_custom_content_event(executor, kind, content, created_at)
    }

    fn enqueue_signed_custom_content_event(
        executor: &mut NostrGatewayExecutor<FakeNostrRelay<'static, 0, 0, 1>>,
        kind: u16,
        content: &str,
        created_at: u64,
    ) -> Result<(), GatewayError> {
        let secret = fixture_secret();
        let mut recipient_hex_buf = [0; 64];
        let recipient_hex = RECIPIENT
            .write_hex(&mut recipient_hex_buf)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        let p_tag_values = ["p", recipient_hex];
        let p_tag = NostrTagRef::new(&p_tag_values)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        let tags = [p_tag];
        let unsigned = NostrUnsignedEvent::new(
            derive_nostr_public_key(&secret)
                .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?,
            created_at,
            kind,
            NostrTagsRef::new(&tags),
            content,
        )
        .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        let event = sign_event(unsigned, &secret)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))?;
        executor
            .relay_mut()
            .enqueue_event_output("sub-1", event)
            .map_err(|error| super::map_nostr_send_error(NOSTR_LINK, error))
    }

    fn assert_poll_rejects_with(
        enqueue: impl FnOnce(
            &mut NostrGatewayExecutor<FakeNostrRelay<'static, 0, 0, 1>>,
        ) -> Result<(), GatewayError>,
        kind: LinkDriverErrorKind,
    ) -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<0, 0, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut frame = [0; 256];

        executor.set_up(true);
        enqueue(&mut executor)?;
        assert_eq!(
            executor.poll_relay_output(&mut frame),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind,
            })
        );
        assert_eq!(executor.poll_relay_output(&mut frame)?, None);
        Ok(())
    }

    fn assert_poll_rejects_with_short_output(
        enqueue: impl FnOnce(
            &mut NostrGatewayExecutor<FakeNostrRelay<'static, 0, 0, 1>>,
        ) -> Result<(), GatewayError>,
        kind: LinkDriverErrorKind,
    ) -> Result<(), GatewayError> {
        let relay = FakeNostrRelay::<0, 0, 1>::new();
        let mut executor =
            NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay, fixture_secret(), RECIPIENT);
        let mut frame = [0; 1];

        executor.set_up(true);
        enqueue(&mut executor)?;
        assert_eq!(
            executor.poll_relay_output(&mut frame),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind,
            })
        );
        let mut retry_frame = [0; 256];
        assert!(matches!(
            executor.poll_relay_output(&mut retry_frame)?,
            Some(NostrGatewayRelayOutput::Frame(_))
        ));
        assert_eq!(executor.poll_relay_output(&mut retry_frame)?, None);
        Ok(())
    }

    fn protocol_error() -> GatewayError {
        GatewayError::Driver {
            link_id: NOSTR_LINK,
            kind: LinkDriverErrorKind::Protocol,
        }
    }
}
