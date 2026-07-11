#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod error;
mod loopback;

pub use error::LoopbackError;
pub use loopback::{
    LOOPBACK_LEFT_ID, LOOPBACK_MAX_FRAME_LEN, LOOPBACK_RIGHT_ID, LoopbackEndpoint, LoopbackPair,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
