use hyf_core::{CommunityId, ForeignEndpointId, NodeId};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HyfDestination {
    Node(NodeId),
    Community(CommunityId),
    Foreign(ForeignEndpointId),
}

impl HyfDestination {
    pub const fn wire_tag(&self) -> u8 {
        match self {
            Self::Node(_) => 0,
            Self::Community(_) => 1,
            Self::Foreign(_) => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::{CommunityId, ForeignEndpointId, ForeignNetworkKind, NodeId};

    use super::HyfDestination;

    #[test]
    fn destination_tags_are_stable() {
        assert_eq!(HyfDestination::Node(NodeId([1; 32])).wire_tag(), 0);
        assert_eq!(
            HyfDestination::Community(CommunityId([2; 16])).wire_tag(),
            1
        );
        assert_eq!(
            HyfDestination::Foreign(ForeignEndpointId::from_fixed_16(
                ForeignNetworkKind::Fips,
                [3; 16],
            ))
            .wire_tag(),
            2
        );
    }
}
