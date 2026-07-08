#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod constants;
mod decode;
mod encode;
mod error;

pub use constants::{KISS_CMD_DATA, KISS_CMD_READY, KISS_FEND, KISS_FESC, KISS_TFEND, KISS_TFESC};
pub use decode::{KissDecoder, KissFrameRef};
pub use encode::{
    encode_command_frame, encode_data_frame, max_encoded_command_len, max_encoded_data_len,
};
pub use error::KissError;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
