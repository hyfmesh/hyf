use hyf_core::{NodeId, TimestampMs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LxmfWrapParams {
    pub source_node: NodeId,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: TimestampMs,
    pub hop_limit: u8,
}

#[cfg(test)]
mod tests {
    use hyf_core::{NodeId, TimestampMs};

    use super::LxmfWrapParams;

    #[test]
    fn params_are_copyable_public_contract_values() {
        let params = LxmfWrapParams {
            source_node: NodeId([1; 32]),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
        };

        assert_eq!(params, params);
        assert_eq!(params.hop_limit, 4);
    }
}
