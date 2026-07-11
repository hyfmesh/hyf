use hyf_core::TimestampMs;
use hyf_link::LinkEvent;
use hyf_wire::HyfEnvelopeRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterEvent<'a> {
    Link(LinkEvent<'a>),
    LocalSubmit(HyfEnvelopeRef<'a>),
    Tick { now_ms: TimestampMs },
}

#[cfg(test)]
mod tests {
    use hyf_core::TimestampMs;

    use super::RouterEvent;

    #[test]
    fn tick_event_preserves_timestamp() {
        assert_eq!(
            RouterEvent::Tick {
                now_ms: TimestampMs(7),
            },
            RouterEvent::Tick {
                now_ms: TimestampMs(7),
            }
        );
    }
}
