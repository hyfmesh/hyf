#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod destination;
mod envelope;
mod error;
mod payload;

pub use destination::HyfDestination;
pub use envelope::{
    HYF_ENVELOPE_MAX_PAYLOAD_LEN, HyfEnvelopeRef, decode_envelope, encode_envelope,
    envelope_encoded_len, validate_envelope,
};
pub use error::HyfWireError;
pub use payload::PayloadKind;

pub const HYF_WIRE_VERSION_0: u8 = 0;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
