#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod role;
mod time;
mod types;

pub use role::NodeRole;
pub use time::{Clock, TimestampMs};
pub use types::{
    CommunityId, ForeignEndpointError, ForeignEndpointId, ForeignNetworkKind, MessageId, NodeId,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
