#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod config;
mod error;
mod event;
mod io;
mod link;

pub use config::{RNodeDataMode, RNodeSerialConfig};
pub use error::RNodeSerialError;
pub use event::RNodeSerialEvent;
pub use io::{FakeSerial, SerialIo};
pub use link::RNodeSerialLink;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
