use hyf_core::{MessageId, TimestampMs};
use hyf_link::LinkId;
use hyf_wire::HyfEnvelopeRef;

pub const ROUTER_COMMAND_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    Duplicate,
    Expired,
    HopLimitExhausted,
    InvalidEnvelope,
    MalformedFrame,
    NoRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterStoreCommand<'a> {
    Put(HyfEnvelopeRef<'a>),
    Remove(MessageId),
    ExpireBefore(TimestampMs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterCommand<'a> {
    Send {
        link_id: LinkId,
        envelope: HyfEnvelopeRef<'a>,
    },
    Store(RouterStoreCommand<'a>),
    Drop {
        message_id: MessageId,
        reason: DropReason,
    },
    DropFrame {
        link_id: LinkId,
        reason: DropReason,
    },
    DeliverLocal(HyfEnvelopeRef<'a>),
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, TimestampMs};
    use hyf_link::LinkId;

    use super::{DropReason, RouterCommand, RouterStoreCommand};
    use crate::router::tests::sample_envelope;

    #[test]
    fn router_commands_are_copyable_boundaries() {
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, 1, b"payload");
        let send = RouterCommand::Send {
            link_id: LinkId([3; 16]),
            envelope,
        };

        assert_eq!(send, send);
        assert_eq!(
            RouterCommand::Store(RouterStoreCommand::ExpireBefore(TimestampMs(9))),
            RouterCommand::Store(RouterStoreCommand::ExpireBefore(TimestampMs(9)))
        );
        assert_eq!(
            RouterCommand::Drop {
                message_id: MessageId([1; 32]),
                reason: DropReason::Duplicate,
            },
            RouterCommand::Drop {
                message_id: MessageId([1; 32]),
                reason: DropReason::Duplicate,
            }
        );
    }
}
