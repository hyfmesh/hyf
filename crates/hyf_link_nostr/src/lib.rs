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
    HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS, HYF_NOSTR_MAX_ENVELOPE_BYTES,
};
pub use error::NostrError;

#[cfg(test)]
mod tests {
    use super::{HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS};

    #[test]
    fn crate_builds() {
        assert_eq!(HYF_NOSTR_ENVELOPE_KIND, 9775);
        assert_eq!(HYF_NOSTR_MAX_CONTENT_CHARS, 4096);
    }
}
