#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod convert;
mod error;
mod params;

pub use convert::{
    LxmfBridgeIngress, decode_lxmf_bridge_ingress, encode_bridge_message_to_lxmf_message,
};
pub use error::LxmfBridgeError;
pub use params::{LxmfBridgeEgressParams, LxmfBridgeIngressParams};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
