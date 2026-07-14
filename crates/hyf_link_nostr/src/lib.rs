#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

mod canonical;
mod constants;
mod content;
mod error;
mod event;
mod fake_relay;
mod filter;
mod hex;
mod hyf;
mod keys;
#[cfg(any(test, feature = "alloc"))]
mod messages;
mod signing;
mod signing_spike;
mod status;
mod stored;
mod stored_event;

pub use canonical::{event_id, write_canonical_event};
pub use constants::{
    HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS, HYF_NOSTR_MAX_ENVELOPE_BYTES,
    HYF_NOSTR_MAX_P_TAGS, HYF_NOSTR_MAX_RELAY_STATUS_CHARS, HYF_NOSTR_MAX_TAG_VALUE_CHARS,
    HYF_NOSTR_MAX_TAG_VALUES, HYF_NOSTR_MAX_TAGS,
};
pub use content::{decode_hyf_envelope_content, encode_hyf_envelope_content};
pub use error::NostrError;
pub use event::{NostrEvent, NostrUnsignedEvent, validate_content_len};
pub use fake_relay::{
    FakeNostrRelay, FakeNostrRelayMetrics, FakeNostrRelayOutput, FakeNostrSubscription,
};
pub use filter::{
    NOSTR_SUBSCRIPTION_ID_MAX_LEN, NostrFilter, NostrFilterTarget, NostrTagRef, NostrTagsRef,
    matches_any_filter, validate_subscription_id,
};
pub use hex::{decode_fixed_lower_hex, decode_lower_hex, encode_lower_hex};
pub use hyf::{
    HYF_NOSTR_ALT_TAG, HYF_NOSTR_TOPIC_TAG, HyfNostrEventBuffers, sign_hyf_nostr_event,
    verify_and_decode_hyf_nostr_event,
};
pub use keys::{NostrEventId, NostrPublicKey, NostrSecretKey, NostrSignature};
#[cfg(any(test, feature = "alloc"))]
pub use messages::{
    NostrClientMessage, NostrOwnedClientMessage, NostrOwnedEvent, NostrOwnedFilter,
    NostrOwnedRelayMessage, NostrRelayMessage, decode_client_message, decode_relay_message,
    write_client_message, write_relay_message,
};
pub use signing::{derive_nostr_public_key, sign_event, verify_event};
pub use status::{
    NostrPublishOutcome, NostrRelayStatus, NostrRelayStatusPrefix, classify_closed_message,
    classify_ok_message, parse_relay_status,
};

#[cfg(test)]
mod tests {
    use super::{HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS};

    #[test]
    fn crate_builds() {
        assert_eq!(HYF_NOSTR_ENVELOPE_KIND, 9775);
        assert_eq!(HYF_NOSTR_MAX_CONTENT_CHARS, 4096);
    }

    #[test]
    fn websocket_runtime_remains_deferred_without_placeholder_features() {
        let manifest = include_str!("../Cargo.toml");

        assert!(!manifest.contains("websocket_runtime"));
        assert!(!manifest.contains("nostr-sdk"));
        assert!(!manifest.contains("tokio-tungstenite"));
        assert!(manifest.contains("default = []"));
    }
}
