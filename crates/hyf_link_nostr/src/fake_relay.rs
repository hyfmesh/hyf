use crate::{
    NostrError, NostrEvent, NostrEventId, NostrFilter, NostrPublishOutcome, NostrRelayStatus,
    NostrRelayStatusPrefix, validate_subscription_id, verify_and_decode_hyf_nostr_event,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeNostrRelayMetrics {
    pub stored_events: usize,
    pub active_subscriptions: usize,
    pub queued_outputs: usize,
    pub output_overflows: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeNostrSubscription<'a> {
    pub subscription_id: &'a str,
    pub filters: &'a [NostrFilter<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeNostrRelayOutput<'a> {
    Ok {
        event_id: NostrEventId,
        accepted: bool,
        status: NostrRelayStatus<'a>,
    },
    Event {
        subscription_id: &'a str,
        event: NostrEvent<'a>,
    },
    Eose {
        subscription_id: &'a str,
    },
    Closed {
        subscription_id: &'a str,
        status: NostrRelayStatus<'a>,
    },
    Notice {
        message: &'a str,
    },
    Auth {
        challenge: &'a str,
    },
}

pub struct FakeNostrRelay<
    'a,
    const EVENT_CAPACITY: usize,
    const SUBSCRIPTION_CAPACITY: usize,
    const OUTPUT_CAPACITY: usize,
> {
    events: [Option<NostrEvent<'a>>; EVENT_CAPACITY],
    subscriptions: [Option<FakeNostrSubscription<'a>>; SUBSCRIPTION_CAPACITY],
    outputs: [Option<FakeNostrRelayOutput<'a>>; OUTPUT_CAPACITY],
    metrics: FakeNostrRelayMetrics,
}

impl<
    'a,
    const EVENT_CAPACITY: usize,
    const SUBSCRIPTION_CAPACITY: usize,
    const OUTPUT_CAPACITY: usize,
> FakeNostrRelay<'a, EVENT_CAPACITY, SUBSCRIPTION_CAPACITY, OUTPUT_CAPACITY>
{
    pub const fn new() -> Self {
        Self {
            events: [None; EVENT_CAPACITY],
            subscriptions: [None; SUBSCRIPTION_CAPACITY],
            outputs: [None; OUTPUT_CAPACITY],
            metrics: FakeNostrRelayMetrics {
                stored_events: 0,
                active_subscriptions: 0,
                queued_outputs: 0,
                output_overflows: 0,
            },
        }
    }

    pub const fn event_capacity(&self) -> usize {
        EVENT_CAPACITY
    }

    pub const fn subscription_capacity(&self) -> usize {
        SUBSCRIPTION_CAPACITY
    }

    pub const fn output_capacity(&self) -> usize {
        OUTPUT_CAPACITY
    }

    pub const fn metrics(&self) -> FakeNostrRelayMetrics {
        self.metrics
    }

    pub fn stored_event_count(&self) -> usize {
        self.events.iter().filter(|event| event.is_some()).count()
    }

    pub fn remember_subscription(
        &mut self,
        subscription_id: &'a str,
        filters: &'a [NostrFilter<'a>],
    ) -> Result<(), NostrError> {
        validate_subscription_id(subscription_id)?;
        let slot = self
            .subscriptions
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(NostrError::RelaySubscriptionFull {
                capacity: SUBSCRIPTION_CAPACITY,
            })?;
        *slot = Some(FakeNostrSubscription {
            subscription_id,
            filters,
        });
        self.metrics.active_subscriptions += 1;
        Ok(())
    }

    pub fn publish(
        &mut self,
        event: NostrEvent<'a>,
        decode_buffer: &mut [u8],
    ) -> Result<NostrPublishOutcome<'static>, NostrError> {
        if verify_and_decode_hyf_nostr_event(&event, decode_buffer).is_err() {
            let status = invalid_status();
            self.enqueue_output(FakeNostrRelayOutput::Ok {
                event_id: event.id,
                accepted: false,
                status,
            })?;
            return Ok(NostrPublishOutcome::Rejected { status });
        }

        if self.contains_event(event.id) {
            let status = duplicate_status();
            self.enqueue_output(FakeNostrRelayOutput::Ok {
                event_id: event.id,
                accepted: true,
                status,
            })?;
            return Ok(NostrPublishOutcome::AcceptedDuplicate { status });
        }

        self.store_event(event)?;
        let status = empty_status();
        self.enqueue_output(FakeNostrRelayOutput::Ok {
            event_id: event.id,
            accepted: true,
            status,
        })?;
        Ok(NostrPublishOutcome::Accepted { message: "" })
    }

    pub fn enqueue_notice(&mut self, message: &'a str) -> Result<(), NostrError> {
        self.enqueue_output(FakeNostrRelayOutput::Notice { message })
    }

    pub fn enqueue_output(&mut self, output: FakeNostrRelayOutput<'a>) -> Result<(), NostrError> {
        let Some(slot) = self.outputs.iter_mut().find(|slot| slot.is_none()) else {
            self.metrics.output_overflows += 1;
            return Err(NostrError::RelayOutputFull {
                capacity: OUTPUT_CAPACITY,
            });
        };
        *slot = Some(output);
        self.metrics.queued_outputs += 1;
        Ok(())
    }

    pub fn pop_output(&mut self) -> Option<FakeNostrRelayOutput<'a>> {
        let output = self.outputs.first_mut()?.take()?;
        if OUTPUT_CAPACITY > 1 {
            self.outputs.rotate_left(1);
            self.outputs[OUTPUT_CAPACITY - 1] = None;
        }
        self.metrics.queued_outputs -= 1;
        Some(output)
    }

    fn contains_event(&self, event_id: NostrEventId) -> bool {
        self.events
            .iter()
            .flatten()
            .any(|event| event.id == event_id)
    }

    fn store_event(&mut self, event: NostrEvent<'a>) -> Result<(), NostrError> {
        let slot = self.events.iter_mut().find(|slot| slot.is_none()).ok_or(
            NostrError::RelayEventStoreFull {
                capacity: EVENT_CAPACITY,
            },
        )?;
        *slot = Some(event);
        self.metrics.stored_events += 1;
        Ok(())
    }
}

const fn empty_status() -> NostrRelayStatus<'static> {
    NostrRelayStatus {
        prefix: NostrRelayStatusPrefix::Unknown,
        raw_prefix: "",
        detail: "",
    }
}

const fn duplicate_status() -> NostrRelayStatus<'static> {
    NostrRelayStatus {
        prefix: NostrRelayStatusPrefix::Duplicate,
        raw_prefix: "duplicate",
        detail: "already stored",
    }
}

const fn invalid_status() -> NostrRelayStatus<'static> {
    NostrRelayStatus {
        prefix: NostrRelayStatusPrefix::Invalid,
        raw_prefix: "invalid",
        detail: "invalid event",
    }
}

impl<
    'a,
    const EVENT_CAPACITY: usize,
    const SUBSCRIPTION_CAPACITY: usize,
    const OUTPUT_CAPACITY: usize,
> Default for FakeNostrRelay<'a, EVENT_CAPACITY, SUBSCRIPTION_CAPACITY, OUTPUT_CAPACITY>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{FakeNostrRelay, FakeNostrRelayOutput};
    use crate::{
        HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS, HyfNostrEventBuffers, NostrError,
        NostrEvent, NostrFilter, NostrPublicKey, NostrPublishOutcome, NostrRelayStatus,
        NostrRelayStatusPrefix, NostrSecretKey, NostrSignature, NostrTagRef, NostrTagsRef,
        NostrUnsignedEvent, encode_hyf_envelope_content, sign_event, sign_hyf_nostr_event,
    };
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, encode_envelope,
    };

    #[test]
    fn fake_relay_starts_empty_with_fixed_capacities() {
        let relay = FakeNostrRelay::<2, 3, 4>::new();

        assert_eq!(relay.event_capacity(), 2);
        assert_eq!(relay.subscription_capacity(), 3);
        assert_eq!(relay.output_capacity(), 4);
        assert_eq!(relay.stored_event_count(), 0);
        assert_eq!(relay.metrics().stored_events, 0);
        assert_eq!(relay.metrics().active_subscriptions, 0);
        assert_eq!(relay.metrics().queued_outputs, 0);
    }

    #[test]
    fn fake_relay_subscription_storage_is_bounded() -> Result<(), NostrError> {
        let mut relay = FakeNostrRelay::<0, 1, 0>::new();
        let filters = [NostrFilter::empty()];

        relay.remember_subscription("sub-1", &filters)?;
        assert_eq!(relay.metrics().active_subscriptions, 1);
        assert_eq!(
            relay.remember_subscription("sub-2", &filters),
            Err(NostrError::RelaySubscriptionFull { capacity: 1 })
        );
        assert_eq!(
            relay.remember_subscription("", &filters),
            Err(NostrError::InvalidSubscriptionId)
        );
        Ok(())
    }

    #[test]
    fn fake_relay_output_queue_is_bounded_and_fifo() -> Result<(), NostrError> {
        let mut relay = FakeNostrRelay::<0, 0, 2>::new();

        relay.enqueue_notice("first")?;
        relay.enqueue_notice("second")?;
        assert_eq!(relay.metrics().queued_outputs, 2);
        assert_eq!(
            relay.enqueue_notice("third"),
            Err(NostrError::RelayOutputFull { capacity: 2 })
        );
        assert_eq!(relay.metrics().output_overflows, 1);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Notice { message: "first" })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Notice { message: "second" })
        );
        assert_eq!(relay.pop_output(), None);
        assert_eq!(relay.metrics().queued_outputs, 0);
        Ok(())
    }

    #[test]
    fn fake_relay_publish_accepts_valid_events_and_detects_duplicates() -> Result<(), NostrError> {
        let encoded = encoded_sample_envelope()?;
        let mut buffers = publish_buffers()?;
        let event = sign_hyf_nostr_event(
            &encoded,
            &fixture_secret(),
            NostrPublicKey::from_bytes([0x77; 32]),
            1720000000,
            buffers.as_event_buffers(),
        )?;
        let mut relay = FakeNostrRelay::<2, 0, 4>::new();
        let mut decode = [0; 256];

        assert_eq!(
            relay.publish(event, &mut decode)?,
            NostrPublishOutcome::Accepted { message: "" }
        );
        assert_eq!(relay.stored_event_count(), 1);
        assert_eq!(relay.metrics().stored_events, 1);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Ok {
                event_id: event.id,
                accepted: true,
                status: empty_test_status(),
            })
        );

        assert_eq!(
            relay.publish(event, &mut decode)?,
            NostrPublishOutcome::AcceptedDuplicate {
                status: duplicate_test_status(),
            }
        );
        assert_eq!(relay.stored_event_count(), 1);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Ok {
                event_id: event.id,
                accepted: true,
                status: duplicate_test_status(),
            })
        );
        Ok(())
    }

    #[test]
    fn fake_relay_publish_rejects_invalid_events() -> Result<(), NostrError> {
        let mut relay = FakeNostrRelay::<2, 0, 4>::new();
        let mut decode = [0; 256];
        let bad_signature = tampered_signature_event()?;

        assert_eq!(
            relay.publish(bad_signature, &mut decode)?,
            NostrPublishOutcome::Rejected {
                status: invalid_test_status(),
            }
        );
        assert_eq!(relay.stored_event_count(), 0);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Ok {
                event_id: bad_signature.id,
                accepted: false,
                status: invalid_test_status(),
            })
        );

        let wrong_kind = wrong_kind_event()?;
        assert_eq!(
            relay.publish(wrong_kind, &mut decode)?,
            NostrPublishOutcome::Rejected {
                status: invalid_test_status(),
            }
        );

        let malformed_content = malformed_content_event()?;
        assert_eq!(
            relay.publish(malformed_content, &mut decode)?,
            NostrPublishOutcome::Rejected {
                status: invalid_test_status(),
            }
        );
        Ok(())
    }

    #[test]
    fn fake_relay_publish_reports_full_event_store() -> Result<(), NostrError> {
        let encoded = encoded_sample_envelope()?;
        let mut buffers = publish_buffers()?;
        let first = sign_hyf_nostr_event(
            &encoded,
            &fixture_secret(),
            NostrPublicKey::from_bytes([0x77; 32]),
            1720000000,
            buffers.as_event_buffers(),
        )?;
        let second = valid_static_event(1720000001)?;
        let mut relay = FakeNostrRelay::<1, 0, 4>::new();
        let mut decode = [0; 256];

        relay.publish(first, &mut decode)?;
        assert_eq!(
            relay.publish(second, &mut decode),
            Err(NostrError::RelayEventStoreFull { capacity: 1 })
        );
        Ok(())
    }

    struct PublishBuffers<'a> {
        content: [u8; HYF_NOSTR_MAX_CONTENT_CHARS],
        recipient_hex: [u8; 64],
        p_tag_values: [&'a str; 2],
        t_tag_values: [&'a str; 2],
        alt_tag_values: [&'a str; 2],
        tags: [NostrTagRef<'a>; 3],
    }

    impl<'a> PublishBuffers<'a> {
        fn as_event_buffers(&'a mut self) -> HyfNostrEventBuffers<'a> {
            HyfNostrEventBuffers {
                content: &mut self.content,
                recipient_hex: &mut self.recipient_hex,
                p_tag_values: &mut self.p_tag_values,
                t_tag_values: &mut self.t_tag_values,
                alt_tag_values: &mut self.alt_tag_values,
                tags: &mut self.tags,
            }
        }
    }

    fn publish_buffers<'a>() -> Result<PublishBuffers<'a>, NostrError> {
        static DUMMY_VALUES: [&str; 1] = ["_"];
        let dummy = NostrTagRef::new(&DUMMY_VALUES)?;
        Ok(PublishBuffers {
            content: [0; HYF_NOSTR_MAX_CONTENT_CHARS],
            recipient_hex: [0; 64],
            p_tag_values: ["", ""],
            t_tag_values: ["", ""],
            alt_tag_values: ["", ""],
            tags: [dummy; 3],
        })
    }

    fn wrong_kind_event() -> Result<NostrEvent<'static>, NostrError> {
        let content = encoded_content_static()?;
        signed_static_event(1, content)
    }

    fn malformed_content_event() -> Result<NostrEvent<'static>, NostrError> {
        signed_static_event(HYF_NOSTR_ENVELOPE_KIND, "zz")
    }

    fn tampered_signature_event() -> Result<NostrEvent<'static>, NostrError> {
        let event = valid_static_event(1720000000)?;
        let mut signature = *event.sig.as_bytes();
        signature[0] ^= 0x01;
        Ok(NostrEvent {
            sig: NostrSignature::from_bytes(signature),
            ..event
        })
    }

    fn valid_static_event(created_at: u64) -> Result<NostrEvent<'static>, NostrError> {
        let content = encoded_content_static()?;
        signed_static_event_with_created_at(HYF_NOSTR_ENVELOPE_KIND, content, created_at)
    }

    fn signed_static_event(
        kind: u16,
        content: &'static str,
    ) -> Result<NostrEvent<'static>, NostrError> {
        signed_static_event_with_created_at(kind, content, 1720000000)
    }

    fn signed_static_event_with_created_at(
        kind: u16,
        content: &'static str,
        created_at: u64,
    ) -> Result<NostrEvent<'static>, NostrError> {
        let tag_values = Box::leak(Box::new(["p", "77"]));
        let tag = NostrTagRef::new(tag_values)?;
        let tags = Box::leak(Box::new([tag]));
        sign_event(
            NostrUnsignedEvent::new(
                crate::derive_nostr_public_key(&fixture_secret())?,
                created_at,
                kind,
                NostrTagsRef::new(tags),
                content,
            )?,
            &fixture_secret(),
        )
    }

    fn encoded_content_static() -> Result<&'static str, NostrError> {
        let encoded = encoded_sample_envelope()?;
        let mut content = [0; HYF_NOSTR_MAX_CONTENT_CHARS];
        let content_len = encode_hyf_envelope_content(&encoded, &mut content)?.len();
        let leaked = Box::leak(Box::new(content));
        core::str::from_utf8(&leaked[..content_len]).map_err(|_| NostrError::Utf8)
    }

    fn encoded_sample_envelope() -> Result<[u8; 123], NostrError> {
        let envelope = sample_envelope();
        let mut encoded = [0; 123];
        let len =
            encode_envelope(envelope, &mut encoded).map_err(|_| NostrError::MalformedEnvelope)?;
        assert_eq!(len, encoded.len());
        Ok(encoded)
    }

    fn sample_envelope<'a>() -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([0x11; 32]),
            source: NodeId([0x22; 32]),
            destination: HyfDestination::Node(NodeId([0x33; 32])),
            created_at_ms: TimestampMs(1000),
            expires_at_ms: TimestampMs(2000),
            hop_limit: 8,
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"hello",
        }
    }

    fn fixture_secret() -> NostrSecretKey {
        let mut secret_key = [0; 32];
        secret_key[31] = 3;
        NostrSecretKey::from_bytes(secret_key)
    }

    const fn empty_test_status() -> NostrRelayStatus<'static> {
        NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::Unknown,
            raw_prefix: "",
            detail: "",
        }
    }

    const fn duplicate_test_status() -> NostrRelayStatus<'static> {
        NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::Duplicate,
            raw_prefix: "duplicate",
            detail: "already stored",
        }
    }

    const fn invalid_test_status() -> NostrRelayStatus<'static> {
        NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::Invalid,
            raw_prefix: "invalid",
            detail: "invalid event",
        }
    }
}
