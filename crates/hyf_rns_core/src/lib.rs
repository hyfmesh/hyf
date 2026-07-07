#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod constants;
mod destination;
mod error;
mod hash;
mod types;

pub use constants::{
    RNS_HEADER_1_LEN, RNS_HEADER_2_LEN, RNS_MDU, RNS_MTU, RNS_NAME_HASH_LEN, RNS_TRUNCATED_HASH_LEN,
};
pub use destination::{destination_name_hash, validate_destination_name};
pub use error::RnsCoreError;
pub use hash::{full_hash, truncated_hash};
pub use types::{RnsDestinationHash, RnsFullHash, RnsIdentityHash, RnsNameHash, RnsTruncatedHash};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
