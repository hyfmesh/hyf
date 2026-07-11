#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod command;
mod error;
mod event;
mod policy;
mod router;

pub use command::{DropReason, RouterCommand, RouterStoreCommand};
pub use error::RouterError;
pub use event::RouterEvent;
pub use policy::RouterPolicy;
pub use router::Router;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
