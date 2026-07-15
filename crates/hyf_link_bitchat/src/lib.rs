#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod error;
mod params;
mod wrap;

pub use error::HyfLinkBitchatError;
pub use params::BitchatWrapParams;
pub use wrap::{unwrap_bitchat_packet, validate_bitchat_packet, wrap_bitchat_packet};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
