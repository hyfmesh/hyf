#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct TimestampMs(pub u64);

pub trait Clock {
    fn now_ms(&self) -> TimestampMs;
}

#[cfg(test)]
mod tests {
    use super::{Clock, TimestampMs};

    struct FixedClock(TimestampMs);

    impl Clock for FixedClock {
        fn now_ms(&self) -> TimestampMs {
            self.0
        }
    }

    #[test]
    fn timestamp_preserves_milliseconds() {
        let timestamp = TimestampMs(42);

        assert_eq!(timestamp.0, 42);
    }

    #[test]
    fn clock_returns_timestamp() {
        let clock = FixedClock(TimestampMs(123));

        assert_eq!(clock.now_ms(), TimestampMs(123));
    }
}
