use hyf_core::{MessageId, NodeId, TimestampMs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LxmfWrapParams {
    pub source_node: NodeId,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: TimestampMs,
    pub hop_limit: u8,
    pub message_id: MessageId,
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};

    use super::LxmfWrapParams;

    #[test]
    fn params_are_copyable_public_contract_values() {
        let params = LxmfWrapParams {
            source_node: NodeId([1; 32]),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
            message_id: MessageId([3; 32]),
        };

        assert_eq!(params, params);
        assert_eq!(params.hop_limit, 4);
    }
}
