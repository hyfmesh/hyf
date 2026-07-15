#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod codec;
mod constants;
mod error;
mod flags;
mod packet;
mod types;

pub use constants::{
    BITCHAT_CARRIER_PACKET_MAX_LEN, BITCHAT_CORE_PACKET_MAX_LEN, BITCHAT_PAYLOAD_MAX_LEN,
    BITCHAT_PEER_ID_LEN, BITCHAT_ROUTE_MAX_HOPS, BITCHAT_SIGNATURE_LEN, BITCHAT_V1_HEADER_LEN,
    BITCHAT_V2_HEADER_LEN,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
