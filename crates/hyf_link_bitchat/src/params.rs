use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_wire::HyfDestination;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitchatWrapParams {
    pub message_id: MessageId,
    pub source_node: NodeId,
    pub destination: HyfDestination,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: TimestampMs,
    pub hop_limit: u8,
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::HyfDestination;

    use super::BitchatWrapParams;

    #[test]
    fn params_are_copyable_public_contract_values() {
        let params = BitchatWrapParams {
            message_id: MessageId([9; 32]),
            source_node: NodeId([1; 32]),
            destination: HyfDestination::Node(NodeId([2; 32])),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
        };

        assert_eq!(params, params);
        assert_eq!(params.message_id, MessageId([9; 32]));
        assert_eq!(params.destination, HyfDestination::Node(NodeId([2; 32])));
    }
}
