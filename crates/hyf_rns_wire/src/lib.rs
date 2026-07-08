#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod context;
mod error;
mod flags;

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
pub use flags::{RnsDestinationType, RnsHeaderType, RnsPacketType, RnsTransportType};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
