use hyf_core::{CommunityId, NodeId};

pub const ROUTER_LOCAL_COMMUNITY_CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouterPolicy {
    pub local_node_id: NodeId,
    pub local_communities: [Option<CommunityId>; ROUTER_LOCAL_COMMUNITY_CAPACITY],
}

impl RouterPolicy {
    pub const fn new(
        local_node_id: NodeId,
        local_communities: [Option<CommunityId>; ROUTER_LOCAL_COMMUNITY_CAPACITY],
    ) -> Self {
        Self {
            local_node_id,
            local_communities,
        }
    }

    pub fn is_local_community(&self, community_id: CommunityId) -> bool {
        self.local_communities
            .iter()
            .any(|configured| configured.is_some_and(|local| local == community_id))
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::{CommunityId, NodeId};

    use super::{ROUTER_LOCAL_COMMUNITY_CAPACITY, RouterPolicy};

    #[test]
    fn router_policy_records_local_node_and_communities() {
        let mut communities = [None; ROUTER_LOCAL_COMMUNITY_CAPACITY];
        communities[0] = Some(CommunityId([2; 16]));
        let policy = RouterPolicy::new(NodeId([1; 32]), communities);

        assert_eq!(policy.local_node_id, NodeId([1; 32]));
        assert!(policy.is_local_community(CommunityId([2; 16])));
        assert!(!policy.is_local_community(CommunityId([3; 16])));
    }
}
