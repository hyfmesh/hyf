#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod constants;
mod error;

pub use constants::{
    HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES, HYF_FIPS_DEFAULT_FRAME_MAX, HYF_FIPS_DEFAULT_MTU,
    HYF_FIPS_DEFAULT_PEERS, HYF_FIPS_DEFAULT_QUEUE,
};
pub use error::FipsError;

#[cfg(test)]
mod tests {
    use super::{
        FipsError, HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES, HYF_FIPS_DEFAULT_FRAME_MAX,
        HYF_FIPS_DEFAULT_MTU, HYF_FIPS_DEFAULT_PEERS, HYF_FIPS_DEFAULT_QUEUE,
    };

    #[test]
    fn constants_match_public_contract() {
        assert_eq!(HYF_FIPS_DEFAULT_MTU, 1024);
        assert_eq!(HYF_FIPS_DEFAULT_FRAME_MAX, 2048);
        assert_eq!(HYF_FIPS_DEFAULT_PEERS, 8);
        assert_eq!(HYF_FIPS_DEFAULT_QUEUE, 16);
        assert_eq!(HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES, 4096);
    }

    #[test]
    fn typed_errors_describe_failure_class() {
        assert_eq!(
            FipsError::FrameTooLarge {
                len: 2049,
                mtu: 1024
            }
            .to_string(),
            "FIPS frame length 2049 exceeds MTU 1024"
        );
        assert_eq!(
            FipsError::OutputTooSmall {
                needed: 4,
                available: 3,
            }
            .to_string(),
            "FIPS output buffer length 3 is smaller than required length 4"
        );
    }

    #[test]
    fn manifest_keeps_live_runtime_dependencies_out() {
        let manifest = include_str!("../Cargo.toml");

        assert!(manifest.contains("default = []"));
        assert!(manifest.contains("control_json"));
        assert!(!manifest.contains("tokio"));
        assert!(!manifest.contains("tun"));
        assert!(!manifest.contains("rtnetlink"));
        assert!(!manifest.contains("rustables"));
        assert!(!manifest.contains("nftables"));
        assert!(!manifest.contains("serialport"));
    }
}
