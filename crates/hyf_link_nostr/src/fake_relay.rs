use crate::{
    NostrError, NostrEvent, NostrEventId, NostrFilter, NostrRelayStatus, validate_subscription_id,
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
    use crate::{NostrError, NostrFilter};

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
}
