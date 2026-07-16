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
mod types;
mod wrap;

pub use codec::{bridge_message_encoded_len, decode_bridge_message, encode_bridge_message};
pub use constants::{
    HYF_BRIDGE_AUTHOR_ID_MAX_LEN, HYF_BRIDGE_BITCHAT_AUTHOR_ID_LEN,
    HYF_BRIDGE_HYF_NODE_AUTHOR_ID_LEN, HYF_BRIDGE_LXMF_AUTHOR_ID_LEN, HYF_BRIDGE_MESSAGE_MAX_LEN,
    HYF_BRIDGE_MESSAGE_VERSION_0, HYF_BRIDGE_NOSTR_AUTHOR_ID_LEN, HYF_BRIDGE_PAYLOAD_MAX_LEN,
};
pub use error::BridgeError;
pub use types::{
    BridgeEndpointKind, BridgeEndpointRef, BridgeIngressMeta, BridgeMessageKey, BridgeMessageRef,
    BridgePayloadKind, BridgeProtocol, BridgeVerificationState,
};
pub use wrap::{
    BridgeWrapParams, unwrap_bridge_message, validate_bridge_message, wrap_bridge_message,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
