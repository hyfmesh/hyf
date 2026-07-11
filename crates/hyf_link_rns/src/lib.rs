#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod error;
mod packet;
mod wrap;

pub use error::HyfLinkRnsError;
pub use packet::{RnsPacketRef, validate_rns_packet};
pub use wrap::{RnsWrapParams, unwrap_rns_packet, wrap_rns_packet};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
