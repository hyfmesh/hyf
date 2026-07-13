use core::fmt;

use crate::{
    NostrError, NostrEvent, NostrEventId, NostrFilter, NostrFilterTarget, NostrPublicKey,
    NostrPublishOutcome, NostrRelayStatus, NostrRelayStatusPrefix, matches_any_filter,
    validate_subscription_id, verify_and_decode_hyf_nostr_event,
};

const EVENT_P_TAG_SCAN_CAPACITY: usize = 8;

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
    next_publish_rejection: Option<NostrRelayStatus<'a>>,
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
            next_publish_rejection: None,
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

        if let Some(subscription) = self
            .subscriptions
            .iter_mut()
            .flatten()
            .find(|subscription| subscription.subscription_id == subscription_id)
        {
            *subscription = FakeNostrSubscription {
                subscription_id,
                filters,
            };
            return Ok(());
        }

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

    pub fn subscribe(
        &mut self,
        subscription_id: &'a str,
        filters: &'a [NostrFilter<'a>],
    ) -> Result<(), NostrError> {
        self.remember_subscription(subscription_id, filters)?;
        self.replay_subscription(subscription_id, filters)
    }

    pub fn reject_next_publish(&mut self, status: NostrRelayStatus<'a>) {
        self.next_publish_rejection = Some(status);
    }

    pub fn close_subscription(&mut self, subscription_id: &str) -> Result<bool, NostrError> {
        validate_subscription_id(subscription_id)?;
        for slot in &mut self.subscriptions {
            if slot
                .as_ref()
                .is_some_and(|subscription| subscription.subscription_id == subscription_id)
            {
                *slot = None;
                self.metrics.active_subscriptions -= 1;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn publish(
        &mut self,
        event: NostrEvent<'a>,
        decode_buffer: &mut [u8],
    ) -> Result<NostrPublishOutcome<'a>, NostrError> {
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

        if let Some(status) = self.next_publish_rejection {
            self.next_publish_rejection = None;
            self.enqueue_output(FakeNostrRelayOutput::Ok {
                event_id: event.id,
                accepted: false,
                status,
            })?;
            return Ok(NostrPublishOutcome::Rejected { status });
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

    pub fn inject_closed(
        &mut self,
        subscription_id: &'a str,
        status: NostrRelayStatus<'a>,
    ) -> Result<(), NostrError> {
        validate_subscription_id(subscription_id)?;
        self.enqueue_output(FakeNostrRelayOutput::Closed {
            subscription_id,
            status,
        })
    }

    pub fn inject_auth_challenge(&mut self, challenge: &'a str) -> Result<(), NostrError> {
        self.enqueue_output(FakeNostrRelayOutput::Auth { challenge })
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

    fn replay_subscription(
        &mut self,
        subscription_id: &'a str,
        filters: &'a [NostrFilter<'a>],
    ) -> Result<(), NostrError> {
        let mut emitted = [false; EVENT_CAPACITY];
        let replay_limit = replay_limit(filters);
        let mut emitted_count = 0;

        while replay_limit.is_none_or(|limit| emitted_count < limit) {
            let Some((index, event)) = self.next_replay_event(filters, &emitted) else {
                break;
            };
            self.enqueue_output(FakeNostrRelayOutput::Event {
                subscription_id,
                event,
            })?;
            emitted[index] = true;
            emitted_count += 1;
        }

        self.enqueue_output(FakeNostrRelayOutput::Eose { subscription_id })
    }

    fn next_replay_event(
        &self,
        filters: &[NostrFilter<'_>],
        emitted: &[bool; EVENT_CAPACITY],
    ) -> Option<(usize, NostrEvent<'a>)> {
        let mut best = None;
        for (index, event) in self.events.iter().enumerate() {
            if emitted[index] {
                continue;
            }
            let Some(event) = *event else {
                continue;
            };
            if !event_matches_filters(event, filters) {
                continue;
            }

            match best {
                Some((_, current)) if !event_sorts_before(event, current) => {}
                _ => best = Some((index, event)),
            }
        }
        best
    }
}

impl<
    'a,
    const EVENT_CAPACITY: usize,
    const SUBSCRIPTION_CAPACITY: usize,
    const OUTPUT_CAPACITY: usize,
> fmt::Debug for FakeNostrRelay<'a, EVENT_CAPACITY, SUBSCRIPTION_CAPACITY, OUTPUT_CAPACITY>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeNostrRelay")
            .field("event_capacity", &EVENT_CAPACITY)
            .field("subscription_capacity", &SUBSCRIPTION_CAPACITY)
            .field("output_capacity", &OUTPUT_CAPACITY)
            .field("stored_event_count", &self.stored_event_count())
            .field("metrics", &self.metrics)
            .field(
                "has_pending_publish_rejection",
                &self.next_publish_rejection.is_some(),
            )
            .finish()
    }
}

fn replay_limit(filters: &[NostrFilter<'_>]) -> Option<usize> {
    let mut limit = Some(0usize);
    for filter in filters {
        let Some(filter_limit) = filter.limit else {
            return None;
        };
        if let Some(total) = &mut limit {
            *total = total.saturating_add(filter_limit);
        }
    }
    limit
}

fn event_matches_filters(event: NostrEvent<'_>, filters: &[NostrFilter<'_>]) -> bool {
    let mut p_tags = [NostrPublicKey::from_bytes([0; 32]); EVENT_P_TAG_SCAN_CAPACITY];
    let p_tag_count = collect_event_p_tags(event, &mut p_tags);
    matches_any_filter(
        filters,
        NostrFilterTarget {
            kind: event.kind,
            author: event.pubkey,
            p_tags: &p_tags[..p_tag_count],
            created_at: event.created_at,
        },
    )
}

fn collect_event_p_tags(event: NostrEvent<'_>, out: &mut [NostrPublicKey]) -> usize {
    let mut count = 0;
    for tag in event.tags.as_slice() {
        if tag.name() != "p" || count == out.len() {
            continue;
        }
        let Some(value) = tag.value() else {
            continue;
        };
        let Ok(public_key) = NostrPublicKey::from_hex(value) else {
            continue;
        };
        out[count] = public_key;
        count += 1;
    }
    count
}

fn event_sorts_before(candidate: NostrEvent<'_>, current: NostrEvent<'_>) -> bool {
    candidate.created_at > current.created_at
        || (candidate.created_at == current.created_at
            && candidate.id.as_bytes() < current.id.as_bytes())
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
        NostrEvent, NostrEventId, NostrFilter, NostrPublicKey, NostrPublishOutcome,
        NostrRelayStatus, NostrRelayStatusPrefix, NostrSecretKey, NostrSignature, NostrTagRef,
        NostrTagsRef, NostrUnsignedEvent, encode_hyf_envelope_content, sign_event,
        sign_hyf_nostr_event,
    };
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, encode_envelope,
    };

    const RECIPIENT_A: NostrPublicKey = NostrPublicKey::from_bytes([0x77; 32]);
    const RECIPIENT_B: NostrPublicKey = NostrPublicKey::from_bytes([0x88; 32]);

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
        relay.remember_subscription("sub-1", &[])?;
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
    fn fake_relay_close_removes_subscription_state() -> Result<(), NostrError> {
        let mut relay = FakeNostrRelay::<0, 1, 0>::new();
        let filters = [NostrFilter::empty()];

        relay.remember_subscription("sub-1", &filters)?;
        assert_eq!(relay.metrics().active_subscriptions, 1);
        assert_eq!(relay.close_subscription("sub-1")?, true);
        assert_eq!(relay.metrics().active_subscriptions, 0);
        assert_eq!(relay.close_subscription("sub-1")?, false);
        assert_eq!(
            relay.close_subscription(""),
            Err(NostrError::InvalidSubscriptionId)
        );

        relay.remember_subscription("sub-2", &filters)?;
        assert_eq!(relay.metrics().active_subscriptions, 1);
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
    fn fake_relay_control_messages_are_injected_in_order() -> Result<(), NostrError> {
        let mut relay = FakeNostrRelay::<0, 0, 3>::new();
        let status = NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::AuthRequired,
            raw_prefix: "auth-required",
            detail: "challenge required",
        };

        relay.enqueue_notice("relay notice")?;
        relay.inject_closed("sub-1", status)?;
        relay.inject_auth_challenge("challenge-token")?;

        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Notice {
                message: "relay notice",
            })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Closed {
                subscription_id: "sub-1",
                status,
            })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Auth {
                challenge: "challenge-token",
            })
        );
        assert_eq!(relay.pop_output(), None);
        assert_eq!(
            relay.inject_closed("", status),
            Err(NostrError::InvalidSubscriptionId)
        );
        Ok(())
    }

    #[test]
    fn fake_relay_debug_redacts_queued_events_and_control_messages() -> Result<(), NostrError> {
        let tag_values = ["p", "secret-tag-value"];
        let tag = NostrTagRef::new(&tag_values)?;
        let tags = [tag];
        let event = NostrEvent::new(
            NostrEventId::from_bytes([0x11; 32]),
            NostrPublicKey::from_bytes([0x22; 32]),
            1,
            HYF_NOSTR_ENVELOPE_KIND,
            NostrTagsRef::new(&tags),
            "secret-event-content",
            NostrSignature::from_bytes([0x33; 64]),
        )?;
        let mut relay = FakeNostrRelay::<0, 0, 2>::new();

        relay.enqueue_output(FakeNostrRelayOutput::Event {
            subscription_id: "secret-subscription",
            event,
        })?;
        relay.enqueue_notice("secret-notice")?;
        let debug = format!("{relay:?}");

        assert!(debug.contains("FakeNostrRelay"));
        assert!(debug.contains("queued_outputs"));
        assert!(!debug.contains("secret-event-content"));
        assert!(!debug.contains("secret-tag-value"));
        assert!(!debug.contains("secret-subscription"));
        assert!(!debug.contains("secret-notice"));
        Ok(())
    }

    #[test]
    fn fake_relay_subscribe_replays_matching_events_in_deterministic_order()
    -> Result<(), NostrError> {
        let author_secret = secret_with_last_byte(3);
        let author = crate::derive_nostr_public_key(&author_secret)?;
        let tie_a = signed_static_hyf_event(20, secret_with_last_byte(3), RECIPIENT_A)?;
        let tie_b = signed_static_hyf_event(20, secret_with_last_byte(3), RECIPIENT_B)?;
        let old = signed_static_hyf_event(10, secret_with_last_byte(3), RECIPIENT_A)?;
        let wrong_author = signed_static_hyf_event(19, secret_with_last_byte(4), RECIPIENT_A)?;
        let too_new = signed_static_hyf_event(30, secret_with_last_byte(3), RECIPIENT_A)?;
        let mut relay = FakeNostrRelay::<5, 1, 8>::new();
        let mut decode = [0; 256];

        relay.publish(old, &mut decode)?;
        relay.publish(wrong_author, &mut decode)?;
        relay.publish(tie_b, &mut decode)?;
        relay.publish(too_new, &mut decode)?;
        relay.publish(tie_a, &mut decode)?;
        drain_outputs(&mut relay);

        let kinds = [HYF_NOSTR_ENVELOPE_KIND];
        let authors = [author];
        let p_tags = [RECIPIENT_A, RECIPIENT_B];
        let filters = [NostrFilter {
            kinds: &kinds,
            authors: &authors,
            p_tags: &p_tags,
            since: Some(10),
            until: Some(20),
            limit: Some(2),
        }];
        relay.subscribe("sub-1", &filters)?;

        let (first, second) = ordered_pair(tie_a, tie_b);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Event {
                subscription_id: "sub-1",
                event: first,
            })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Event {
                subscription_id: "sub-1",
                event: second,
            })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Eose {
                subscription_id: "sub-1",
            })
        );
        assert_eq!(relay.pop_output(), None);
        Ok(())
    }

    #[test]
    fn fake_relay_subscribe_filters_kind_author_p_and_time_ranges() -> Result<(), NostrError> {
        let author_secret = secret_with_last_byte(3);
        let author = crate::derive_nostr_public_key(&author_secret)?;
        let matching = signed_static_hyf_event(20, secret_with_last_byte(3), RECIPIENT_A)?;
        let wrong_recipient = signed_static_hyf_event(20, secret_with_last_byte(3), RECIPIENT_B)?;
        let old = signed_static_hyf_event(9, secret_with_last_byte(3), RECIPIENT_A)?;
        let wrong_author = signed_static_hyf_event(20, secret_with_last_byte(4), RECIPIENT_A)?;
        let mut relay = FakeNostrRelay::<4, 1, 8>::new();
        let mut decode = [0; 256];

        relay.publish(wrong_recipient, &mut decode)?;
        relay.publish(old, &mut decode)?;
        relay.publish(wrong_author, &mut decode)?;
        relay.publish(matching, &mut decode)?;
        drain_outputs(&mut relay);

        let kinds = [HYF_NOSTR_ENVELOPE_KIND];
        let authors = [author];
        let p_tags = [RECIPIENT_A];
        let filters = [NostrFilter {
            kinds: &kinds,
            authors: &authors,
            p_tags: &p_tags,
            since: Some(10),
            until: Some(20),
            limit: None,
        }];
        relay.subscribe("sub-1", &filters)?;

        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Event {
                subscription_id: "sub-1",
                event: matching,
            })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Eose {
                subscription_id: "sub-1",
            })
        );

        drain_outputs(&mut relay);
        let wrong_kind = [1];
        let filters = [NostrFilter {
            kinds: &wrong_kind,
            ..NostrFilter::empty()
        }];
        relay.subscribe("sub-1", &filters)?;
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Eose {
                subscription_id: "sub-1",
            })
        );
        assert_eq!(relay.pop_output(), None);
        Ok(())
    }

    #[test]
    fn fake_relay_subscribe_replaces_repeated_subscription_id() -> Result<(), NostrError> {
        let first = signed_static_hyf_event(20, secret_with_last_byte(3), RECIPIENT_A)?;
        let second = signed_static_hyf_event(21, secret_with_last_byte(3), RECIPIENT_B)?;
        let mut relay = FakeNostrRelay::<2, 1, 8>::new();
        let mut decode = [0; 256];

        relay.publish(first, &mut decode)?;
        relay.publish(second, &mut decode)?;
        drain_outputs(&mut relay);

        let first_filter_p_tags = [RECIPIENT_A];
        let first_filters = [NostrFilter {
            p_tags: &first_filter_p_tags,
            ..NostrFilter::empty()
        }];
        relay.subscribe("sub-1", &first_filters)?;
        assert_eq!(relay.metrics().active_subscriptions, 1);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Event {
                subscription_id: "sub-1",
                event: first,
            })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Eose {
                subscription_id: "sub-1",
            })
        );

        let second_filter_p_tags = [RECIPIENT_B];
        let second_filters = [NostrFilter {
            p_tags: &second_filter_p_tags,
            ..NostrFilter::empty()
        }];
        relay.subscribe("sub-1", &second_filters)?;
        assert_eq!(relay.metrics().active_subscriptions, 1);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Event {
                subscription_id: "sub-1",
                event: second,
            })
        );
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Eose {
                subscription_id: "sub-1",
            })
        );
        assert_eq!(relay.pop_output(), None);
        Ok(())
    }

    #[test]
    fn fake_relay_publish_accepts_valid_events_and_detects_duplicates() -> Result<(), NostrError> {
        let encoded = encoded_sample_envelope()?;
        let mut buffers = publish_buffers()?;
        let event = sign_hyf_nostr_event(
            &encoded,
            &fixture_secret(),
            RECIPIENT_A,
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
            RECIPIENT_A,
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

    #[test]
    fn fake_relay_can_reject_next_valid_publish() -> Result<(), NostrError> {
        let event = valid_static_event(1720000000)?;
        let status = rate_limited_test_status();
        let mut relay = FakeNostrRelay::<1, 0, 2>::new();
        let mut decode = [0; 256];

        relay.reject_next_publish(status);
        assert_eq!(
            relay.publish(event, &mut decode)?,
            NostrPublishOutcome::Rejected { status }
        );
        assert_eq!(relay.stored_event_count(), 0);
        assert_eq!(
            relay.pop_output(),
            Some(FakeNostrRelayOutput::Ok {
                event_id: event.id,
                accepted: false,
                status,
            })
        );

        assert_eq!(
            relay.publish(event, &mut decode)?,
            NostrPublishOutcome::Accepted { message: "" }
        );
        assert_eq!(relay.stored_event_count(), 1);
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
        signed_static_hyf_event(created_at, fixture_secret(), RECIPIENT_A)
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
        let recipient_hex_buf = Box::leak(Box::new([0; 64]));
        let recipient_hex = RECIPIENT_A.write_hex(recipient_hex_buf)?;
        let tag_values = Box::leak(Box::new(["p", recipient_hex]));
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

    fn signed_static_hyf_event(
        created_at: u64,
        secret: NostrSecretKey,
        recipient: NostrPublicKey,
    ) -> Result<NostrEvent<'static>, NostrError> {
        let content = encoded_content_static()?;
        let recipient_hex_buf = Box::leak(Box::new([0; 64]));
        let recipient_hex = recipient.write_hex(recipient_hex_buf)?;
        let tag_values = Box::leak(Box::new(["p", recipient_hex]));
        let tag = NostrTagRef::new(tag_values)?;
        let tags = Box::leak(Box::new([tag]));
        sign_event(
            NostrUnsignedEvent::new(
                crate::derive_nostr_public_key(&secret)?,
                created_at,
                HYF_NOSTR_ENVELOPE_KIND,
                NostrTagsRef::new(tags),
                content,
            )?,
            &secret,
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
        secret_with_last_byte(3)
    }

    fn secret_with_last_byte(last_byte: u8) -> NostrSecretKey {
        let mut secret_key = [0; 32];
        secret_key[31] = last_byte;
        NostrSecretKey::from_bytes(secret_key)
    }

    fn ordered_pair(
        first: NostrEvent<'static>,
        second: NostrEvent<'static>,
    ) -> (NostrEvent<'static>, NostrEvent<'static>) {
        if first.id.as_bytes() < second.id.as_bytes() {
            (first, second)
        } else {
            (second, first)
        }
    }

    fn drain_outputs<
        const EVENT_CAPACITY: usize,
        const SUBSCRIPTION_CAPACITY: usize,
        const OUTPUT_CAPACITY: usize,
    >(
        relay: &mut FakeNostrRelay<'_, EVENT_CAPACITY, SUBSCRIPTION_CAPACITY, OUTPUT_CAPACITY>,
    ) {
        while relay.pop_output().is_some() {}
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

    const fn rate_limited_test_status() -> NostrRelayStatus<'static> {
        NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::RateLimited,
            raw_prefix: "rate-limited",
            detail: "slow down",
        }
    }
}
