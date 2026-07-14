#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod constants;
mod error;
mod hash;
mod message;
mod msgpack;
mod payload;
mod types;

pub use constants::{
    LXMF_CONTENT_MAX_LEN, LXMF_DESTINATION_HASH_LEN, LXMF_FIELDS_MAX_LEN, LXMF_FIXED_HEADER_LEN,
    LXMF_MESSAGE_ID_LEN, LXMF_MESSAGE_MAX_LEN, LXMF_MSGPACK_MAX_DEPTH, LXMF_PAYLOAD_MAX_LEN,
    LXMF_SIGNATURE_LEN, LXMF_SOURCE_HASH_LEN, LXMF_STAMP_MAX_LEN, LXMF_TITLE_MAX_LEN,
};
pub use error::LxmfError;
pub use hash::{lxmf_message_id, lxmf_signature_input_len, write_lxmf_signature_input};
pub use message::{decode_lxmf_message, encode_lxmf_message};
pub use payload::{decode_lxmf_payload, encode_lxmf_payload, lxmf_payload_encoded_len};
pub use types::{
    LxmfDestinationHash, LxmfMessageId, LxmfMessageRef, LxmfPayloadRef, LxmfRawMapRef,
    LxmfSignature, LxmfSourceHash, LxmfStampRef,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
