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
    BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE, BitchatBridgeIngress, decode_bitchat_bridge_ingress,
    encode_bridge_message_to_bitchat_packet,
};
pub use error::BitchatBridgeError;
pub use params::{
    BITCHAT_BRIDGE_DEFAULT_TTL, BitchatBridgeEgressParams, BitchatBridgeIngressParams,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
