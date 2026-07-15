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

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
