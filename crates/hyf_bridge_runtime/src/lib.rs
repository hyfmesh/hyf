#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod command;
mod dedupe;
mod error;
mod orchestrator;
mod policy;
mod types;

pub use command::{BridgeDropReason, BridgeRuntimeCommand};
pub use dedupe::BridgeDedupeSet;
pub use error::BridgeRuntimeError;
pub use hyf_bridge_core::{BridgeMessageKey, BridgeProtocol};
pub use orchestrator::{
    BridgeOrchestrator, BridgeRuntimeDispatchParams, BridgeRuntimeEgressParams,
    BridgeRuntimeScratch,
};
pub use policy::BridgeRoutePolicy;
pub use types::BridgeOrigin;

#[cfg(test)]
mod tests {
    use super::{BridgeDedupeSet, BridgeProtocol, BridgeRoutePolicy};

    #[test]
    fn crate_builds() {
        let dedupe: BridgeDedupeSet<4> = BridgeDedupeSet::new();
        let policy = BridgeRoutePolicy::new(false, [Some(BridgeProtocol::BitChat)]);

        assert_eq!(dedupe.capacity(), 4);
        assert!(!policy.allow_echo);
    }
}
