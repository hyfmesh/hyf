#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod announce;
mod context;
mod error;
mod flags;
#[cfg(feature = "ifac")]
mod ifac;
mod packet;
mod packet_hash;

pub use announce::{
    RNS_ANNOUNCE_RANDOM_HASH_LEN, RNS_ANNOUNCE_RATCHET_LEN, RNS_ANNOUNCE_SIGNATURE_LEN,
    RnsAnnounceEncodeParams, RnsAnnounceRef, RnsClock, build_announce_signed_data,
    decode_announce_packet, encode_announce_packet, validate_announce_packet,
};
pub use context::{
    RNS_CONTEXT_CACHE_REQUEST, RNS_CONTEXT_CHANNEL, RNS_CONTEXT_COMMAND,
    RNS_CONTEXT_COMMAND_STATUS, RNS_CONTEXT_KEEPALIVE, RNS_CONTEXT_LINKCLOSE,
    RNS_CONTEXT_LINKIDENTIFY, RNS_CONTEXT_LINKPROOF, RNS_CONTEXT_LRPROOF, RNS_CONTEXT_LRRTT,
    RNS_CONTEXT_NONE, RNS_CONTEXT_PATH_RESPONSE, RNS_CONTEXT_REQUEST, RNS_CONTEXT_RESOURCE,
    RNS_CONTEXT_RESOURCE_ADV, RNS_CONTEXT_RESOURCE_HMU, RNS_CONTEXT_RESOURCE_ICL,
    RNS_CONTEXT_RESOURCE_PRF, RNS_CONTEXT_RESOURCE_RCL, RNS_CONTEXT_RESOURCE_REQ,
    RNS_CONTEXT_RESPONSE,
};
pub use error::RnsWireError;
pub use flags::{
    RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketType, RnsTransportType,
    decode_flags, encode_flags,
};
#[cfg(feature = "ifac")]
pub use ifac::{RNS_IFAC_MAX_SIZE, RNS_IFAC_MIN_SIZE, ifac_apply_outbound, ifac_verify_inbound};
pub use packet::{RnsPacketRef, decode_packet, encode_packet};
pub use packet_hash::{packet_hash, packet_truncated_hash, write_packet_hashable_part};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
