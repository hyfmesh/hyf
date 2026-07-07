#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

pub const HYF_WIRE_VERSION_0: u8 = 0;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PayloadKind {
    HyfNativeV0 = 0,
    ForeignRnsPacket = 16,
}

#[cfg(test)]
mod tests {
    use super::{HYF_WIRE_VERSION_0, PayloadKind};

    #[test]
    fn crate_builds() {}

    #[test]
    fn version_zero_is_initial_wire_version() {
        assert_eq!(HYF_WIRE_VERSION_0, 0);
    }

    #[test]
    fn payload_kind_discriminants_are_stable() {
        assert_eq!(PayloadKind::HyfNativeV0 as u8, 0);
        assert_eq!(PayloadKind::ForeignRnsPacket as u8, 16);
    }
}
