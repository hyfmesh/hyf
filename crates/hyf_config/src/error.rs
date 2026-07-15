use core::fmt;

use hyf_core::CommunityId;
use hyf_link::LinkId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidNodeId,
    InvalidRouterLinkCapacity,
    InvalidRouterDedupeCapacity,
    InvalidStoreCapacity,
    InvalidLocalCommunity,
    DuplicateLocalCommunity { community_id: CommunityId },
    InvalidLinkMtu { link_id: LinkId },
    DuplicateLinkId { link_id: LinkId },
    LinkCountExceedsRouter { links: usize, maximum: usize },
    LinkCountExceedsRouterCommandCapacity { links: usize, maximum: usize },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeId => formatter.write_str("invalid gateway node id"),
            Self::InvalidRouterLinkCapacity => formatter.write_str("invalid router link capacity"),
            Self::InvalidRouterDedupeCapacity => {
                formatter.write_str("invalid router dedupe capacity")
            }
            Self::InvalidStoreCapacity => formatter.write_str("invalid store capacity"),
            Self::InvalidLocalCommunity => formatter.write_str("invalid local community id"),
            Self::DuplicateLocalCommunity { community_id } => {
                write!(formatter, "duplicate local community id {community_id:?}")
            }
            Self::InvalidLinkMtu { link_id } => {
                write!(formatter, "invalid link mtu for {link_id:?}")
            }
            Self::DuplicateLinkId { link_id } => {
                write!(formatter, "duplicate link id {link_id:?}")
            }
            Self::LinkCountExceedsRouter { links, maximum } => {
                write!(
                    formatter,
                    "link count exceeds router capacity: links {links}, maximum {maximum}"
                )
            }
            Self::LinkCountExceedsRouterCommandCapacity { links, maximum } => {
                write!(
                    formatter,
                    "link count exceeds router command capacity: links {links}, maximum {maximum}"
                )
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use hyf_core::CommunityId;
    use hyf_link::LinkId;

    use super::ConfigError;

    #[test]
    fn config_errors_have_stable_display_text() {
        assert_eq!(
            ConfigError::InvalidNodeId.to_string(),
            "invalid gateway node id"
        );
        assert_eq!(
            ConfigError::DuplicateLinkId {
                link_id: LinkId([1; 16]),
            }
            .to_string(),
            "duplicate link id LinkId([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])"
        );
        assert_eq!(
            ConfigError::LinkCountExceedsRouter {
                links: 3,
                maximum: 2,
            }
            .to_string(),
            "link count exceeds router capacity: links 3, maximum 2"
        );
        assert_eq!(
            ConfigError::InvalidLocalCommunity.to_string(),
            "invalid local community id"
        );
        assert_eq!(
            ConfigError::DuplicateLocalCommunity {
                community_id: CommunityId([2; 16]),
            }
            .to_string(),
            "duplicate local community id CommunityId([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])"
        );
        assert_eq!(
            ConfigError::LinkCountExceedsRouterCommandCapacity {
                links: 15,
                maximum: 14,
            }
            .to_string(),
            "link count exceeds router command capacity: links 15, maximum 14"
        );
    }
}
