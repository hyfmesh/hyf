#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod driver;
mod error;
mod frame;
mod link;

pub use driver::{LinkDriver, LinkDriverError, LinkDriverErrorKind};
pub use error::LinkError;
pub use frame::{LinkCommand, LinkEvent, LinkFrameRef, validate_frame_mtu};
pub use link::{Link, LinkClass, LinkId};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
