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
    BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE, BitchatBridgeIngress,
    bitchat_packet_to_bridge_message, bridge_message_to_bitchat_packet_v2,
};
pub use error::BitchatBridgeError;
pub use params::{
    BITCHAT_BRIDGE_DEFAULT_TTL, BITCHAT_BRIDGE_PACKET_MAX_LEN, BitchatBridgeEgressParams,
    BitchatBridgeIngressParams,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
