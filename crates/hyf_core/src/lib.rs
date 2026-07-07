#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod types;

pub use types::{CommunityId, MessageId, NodeId};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
