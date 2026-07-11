#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod command;
mod error;
mod policy;
mod store;

pub use command::StoreCommand;
pub use error::StoreError;
pub use policy::StorePolicy;
pub use store::{Store, StoredEnvelopeRef};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
