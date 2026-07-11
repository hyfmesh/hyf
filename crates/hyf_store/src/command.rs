use hyf_core::{MessageId, TimestampMs};
use hyf_wire::HyfEnvelopeRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreCommand<'a> {
    Put(HyfEnvelopeRef<'a>),
    Remove(MessageId),
    ExpireBefore(TimestampMs),
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind};

    use super::StoreCommand;

    #[test]
    fn store_commands_preserve_payloads() {
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, b"payload");

        assert_eq!(StoreCommand::Put(envelope), StoreCommand::Put(envelope));
        assert_eq!(
            StoreCommand::Remove(MessageId([2; 32])),
            StoreCommand::Remove(MessageId([2; 32]))
        );
        assert_eq!(
            StoreCommand::ExpireBefore(TimestampMs(9)),
            StoreCommand::ExpireBefore(TimestampMs(9))
        );
    }

    fn sample_envelope<'a>(
        message_id: MessageId,
        created_at_ms: u64,
        expires_at_ms: u64,
        payload: &'a [u8],
    ) -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id,
            source: NodeId([0x22; 32]),
            destination: HyfDestination::Node(NodeId([0x44; 32])),
            created_at_ms: TimestampMs(created_at_ms),
            expires_at_ms: TimestampMs(expires_at_ms),
            hop_limit: 9,
            payload_kind: PayloadKind::HyfNativeV0,
            payload,
        }
    }
}
