use hyf_core::NodeId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouterPolicy {
    pub local_node_id: NodeId,
}

impl RouterPolicy {
    pub const fn new(local_node_id: NodeId) -> Self {
        Self { local_node_id }
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::NodeId;

    use super::RouterPolicy;

    #[test]
    fn router_policy_records_local_node() {
        let policy = RouterPolicy::new(NodeId([1; 32]));

        assert_eq!(policy.local_node_id, NodeId([1; 32]));
    }
}
