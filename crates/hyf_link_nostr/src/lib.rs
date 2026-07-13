#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod canonical;
mod constants;
mod error;
mod event;
mod filter;
mod hex;
mod keys;
mod signing;
mod signing_spike;

pub use canonical::{event_id, write_canonical_event};
pub use constants::{
    HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS, HYF_NOSTR_MAX_ENVELOPE_BYTES,
};
pub use error::NostrError;
pub use event::{NostrEvent, NostrUnsignedEvent, validate_content_len};
pub use filter::{
    NOSTR_SUBSCRIPTION_ID_MAX_LEN, NostrFilter, NostrFilterTarget, NostrTagRef, NostrTagsRef,
    matches_any_filter, validate_subscription_id,
};
pub use hex::{decode_fixed_lower_hex, decode_lower_hex, encode_lower_hex};
pub use keys::{NostrEventId, NostrPublicKey, NostrSecretKey, NostrSignature};
pub use signing::{derive_nostr_public_key, sign_event};

#[cfg(test)]
mod tests {
    use super::{HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS};

    #[test]
    fn crate_builds() {
        assert_eq!(HYF_NOSTR_ENVELOPE_KIND, 9775);
        assert_eq!(HYF_NOSTR_MAX_CONTENT_CHARS, 4096);
    }
}
