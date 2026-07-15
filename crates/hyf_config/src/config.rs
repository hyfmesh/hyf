use hyf_core::{CommunityId, NodeId};
use hyf_link::LinkId;
use hyf_router::{ROUTER_COMMAND_CAPACITY, ROUTER_LOCAL_COMMUNITY_CAPACITY, RouterPolicy};
use hyf_store::StorePolicy;

use crate::ConfigError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayConfig<const MAX_LINKS: usize> {
    pub node_id: NodeId,
    pub router: RouterConfig,
    pub store: StoreConfig,
    pub links: LinkConfigSet<MAX_LINKS>,
    pub policy: GatewayPolicyConfig,
}

impl<const MAX_LINKS: usize> GatewayConfig<MAX_LINKS> {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_node_id(self.node_id)?;
        self.router.validate()?;
        self.store.validate()?;
        self.policy.validate()?;
        self.links.validate()?;
        let enabled_links = self.links.enabled_count();
        if enabled_links > self.router.max_links {
            return Err(ConfigError::LinkCountExceedsRouter {
                links: enabled_links,
                maximum: self.router.max_links,
            });
        }
        let fanout_link_max = ROUTER_COMMAND_CAPACITY - 2;
        if enabled_links > fanout_link_max {
            return Err(ConfigError::LinkCountExceedsRouterCommandCapacity {
                links: enabled_links,
                maximum: fanout_link_max,
            });
        }
        Ok(())
    }

    pub fn router_policy(&self) -> RouterPolicy {
        RouterPolicy::new(self.node_id, self.policy.local_communities)
    }

    pub fn store_policy(&self) -> StorePolicy {
        self.store.policy
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouterConfig {
    pub max_links: usize,
    pub max_seen_messages: usize,
}

impl RouterConfig {
    pub const fn new(max_links: usize, max_seen_messages: usize) -> Self {
        Self {
            max_links,
            max_seen_messages,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_links == 0 {
            return Err(ConfigError::InvalidRouterLinkCapacity);
        }
        if self.max_seen_messages == 0 {
            return Err(ConfigError::InvalidRouterDedupeCapacity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    pub capacity: usize,
    pub policy: StorePolicy,
}

impl StoreConfig {
    pub const fn new(capacity: usize, policy: StorePolicy) -> Self {
        Self { capacity, policy }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.capacity == 0 {
            return Err(ConfigError::InvalidStoreCapacity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkConfig {
    pub link_id: LinkId,
    pub mtu: usize,
    pub enabled: bool,
}

impl LinkConfig {
    pub const fn new(link_id: LinkId, mtu: usize) -> Self {
        Self {
            link_id,
            mtu,
            enabled: true,
        }
    }

    pub const fn disabled(link_id: LinkId, mtu: usize) -> Self {
        Self {
            link_id,
            mtu,
            enabled: false,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.mtu == 0 {
            return Err(ConfigError::InvalidLinkMtu {
                link_id: self.link_id,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkConfigSet<const N: usize> {
    links: [Option<LinkConfig>; N],
}

impl<const N: usize> LinkConfigSet<N> {
    pub const fn new(links: [Option<LinkConfig>; N]) -> Self {
        Self { links }
    }

    pub const fn as_slice(&self) -> &[Option<LinkConfig>] {
        &self.links
    }

    pub fn enabled_count(&self) -> usize {
        self.links
            .iter()
            .filter(|link| link.is_some_and(|config| config.enabled))
            .count()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for (index, link) in self.links.iter().enumerate() {
            let Some(config) = link else {
                continue;
            };
            config.validate()?;
            if config.enabled && self.has_duplicate_enabled_link(index, config.link_id) {
                return Err(ConfigError::DuplicateLinkId {
                    link_id: config.link_id,
                });
            }
        }
        Ok(())
    }

    fn has_duplicate_enabled_link(&self, index: usize, link_id: LinkId) -> bool {
        for other in self.links.iter().skip(index + 1) {
            if other.is_some_and(|config| config.enabled && config.link_id == link_id) {
                return true;
            }
        }
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayPolicyConfig {
    pub allow_store_and_forward: bool,
    pub local_communities: [Option<CommunityId>; ROUTER_LOCAL_COMMUNITY_CAPACITY],
}

impl GatewayPolicyConfig {
    pub const fn new() -> Self {
        Self {
            allow_store_and_forward: true,
            local_communities: [None; ROUTER_LOCAL_COMMUNITY_CAPACITY],
        }
    }

    pub const fn with_local_communities(
        local_communities: [Option<CommunityId>; ROUTER_LOCAL_COMMUNITY_CAPACITY],
    ) -> Self {
        Self {
            allow_store_and_forward: true,
            local_communities,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for (index, community) in self.local_communities.iter().enumerate() {
            let Some(community_id) = community else {
                continue;
            };
            if community_id.0 == [0; 16] {
                return Err(ConfigError::InvalidLocalCommunity);
            }
            if self
                .local_communities
                .iter()
                .skip(index + 1)
                .any(|other| other.is_some_and(|other_id| other_id == *community_id))
            {
                return Err(ConfigError::DuplicateLocalCommunity {
                    community_id: *community_id,
                });
            }
        }
        Ok(())
    }
}

impl Default for GatewayPolicyConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_node_id(node_id: NodeId) -> Result<(), ConfigError> {
    if node_id.0 == [0; 32] {
        return Err(ConfigError::InvalidNodeId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyf_core::{CommunityId, NodeId};
    use hyf_link::LinkId;
    use hyf_store::StorePolicy;

    use super::{
        GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
    };
    use crate::ConfigError;

    #[test]
    fn valid_gateway_config_derives_runtime_policies() -> Result<(), ConfigError> {
        let config = valid_config();

        config.validate()?;

        assert_eq!(config.router_policy().local_node_id, NodeId([1; 32]));
        assert_eq!(
            config.router_policy().local_communities,
            [None; hyf_router::ROUTER_LOCAL_COMMUNITY_CAPACITY]
        );
        assert_eq!(config.store_policy(), StorePolicy::new());
        assert_eq!(config.links.enabled_count(), 2);
        Ok(())
    }

    #[test]
    fn gateway_config_rejects_invalid_capacities_and_node_id() {
        let zero_node = GatewayConfig {
            node_id: NodeId([0; 32]),
            ..valid_config()
        };
        let bad_router_links = GatewayConfig {
            router: RouterConfig::new(0, 8),
            ..valid_config()
        };
        let bad_router_dedupe = GatewayConfig {
            router: RouterConfig::new(2, 0),
            ..valid_config()
        };
        let bad_store = GatewayConfig {
            store: StoreConfig::new(0, StorePolicy::new()),
            ..valid_config()
        };

        assert_eq!(zero_node.validate(), Err(ConfigError::InvalidNodeId));
        assert_eq!(
            bad_router_links.validate(),
            Err(ConfigError::InvalidRouterLinkCapacity)
        );
        assert_eq!(
            bad_router_dedupe.validate(),
            Err(ConfigError::InvalidRouterDedupeCapacity)
        );
        assert_eq!(bad_store.validate(), Err(ConfigError::InvalidStoreCapacity));
    }

    #[test]
    fn link_config_rejects_enabled_zero_mtu_and_duplicate_enabled_ids() {
        let bad_mtu = GatewayConfig {
            links: LinkConfigSet::new([
                Some(LinkConfig::new(LinkId([1; 16]), 0)),
                Some(LinkConfig::new(LinkId([2; 16]), 256)),
            ]),
            ..valid_config()
        };
        let duplicate = GatewayConfig {
            links: LinkConfigSet::new([
                Some(LinkConfig::new(LinkId([1; 16]), 256)),
                Some(LinkConfig::new(LinkId([1; 16]), 512)),
            ]),
            ..valid_config()
        };
        let disabled_duplicate = GatewayConfig {
            links: LinkConfigSet::new([
                Some(LinkConfig::new(LinkId([1; 16]), 256)),
                Some(LinkConfig::disabled(LinkId([1; 16]), 0)),
            ]),
            ..valid_config()
        };

        assert_eq!(
            bad_mtu.validate(),
            Err(ConfigError::InvalidLinkMtu {
                link_id: LinkId([1; 16]),
            })
        );
        assert_eq!(
            duplicate.validate(),
            Err(ConfigError::DuplicateLinkId {
                link_id: LinkId([1; 16]),
            })
        );
        assert_eq!(disabled_duplicate.validate(), Ok(()));
    }

    #[test]
    fn gateway_config_rejects_more_enabled_links_than_router_capacity() {
        let config = GatewayConfig {
            router: RouterConfig::new(1, 8),
            ..valid_config()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::LinkCountExceedsRouter {
                links: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn gateway_policy_config_rejects_zero_and_duplicate_local_communities() {
        let mut zero_communities = [None; hyf_router::ROUTER_LOCAL_COMMUNITY_CAPACITY];
        zero_communities[0] = Some(CommunityId([0; 16]));
        let zero = GatewayConfig {
            policy: GatewayPolicyConfig::with_local_communities(zero_communities),
            ..valid_config()
        };

        let mut duplicate_communities = [None; hyf_router::ROUTER_LOCAL_COMMUNITY_CAPACITY];
        duplicate_communities[0] = Some(CommunityId([2; 16]));
        duplicate_communities[1] = Some(CommunityId([2; 16]));
        let duplicate = GatewayConfig {
            policy: GatewayPolicyConfig::with_local_communities(duplicate_communities),
            ..valid_config()
        };

        assert_eq!(zero.validate(), Err(ConfigError::InvalidLocalCommunity));
        assert_eq!(
            duplicate.validate(),
            Err(ConfigError::DuplicateLocalCommunity {
                community_id: CommunityId([2; 16]),
            })
        );
    }

    fn valid_config() -> GatewayConfig<2> {
        GatewayConfig {
            node_id: NodeId([1; 32]),
            router: RouterConfig::new(2, 8),
            store: StoreConfig::new(4, StorePolicy::new()),
            links: LinkConfigSet::new([
                Some(LinkConfig::new(LinkId([1; 16]), 256)),
                Some(LinkConfig::new(LinkId([2; 16]), 512)),
            ]),
            policy: GatewayPolicyConfig::new(),
        }
    }
}
