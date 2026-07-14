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

pub use error::HyfLinkLxmfError;
pub use params::LxmfWrapParams;
pub use wrap::{unwrap_lxmf_message, validate_lxmf_message, wrap_lxmf_message};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
