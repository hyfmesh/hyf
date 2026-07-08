#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod error;
mod identity;

pub use error::RnsCryptoError;
pub use identity::{
    RNS_IDENTITY_KEY_LEN, RNS_PUBLIC_IDENTITY_LEN, RNS_SECRET_IDENTITY_LEN, RnsPublicIdentity,
    RnsSecretIdentity, identity_hash, public_identity_from_bytes, public_identity_to_bytes,
    secret_identity_from_bytes,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
