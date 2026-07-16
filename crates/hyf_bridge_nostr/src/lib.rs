#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod content;
mod error;
mod event;

pub use content::{decode_bridge_nostr_content, encode_bridge_nostr_content};
pub use error::NostrBridgeError;
pub use event::{
    HYF_NOSTR_BRIDGE_ALT_TAG, HYF_NOSTR_BRIDGE_EVENT_JSON_MAX_LEN, HYF_NOSTR_BRIDGE_EVENT_KIND,
    HYF_NOSTR_BRIDGE_HYF_TAG, HYF_NOSTR_BRIDGE_VERSION_TAG, NostrBridgeEgressParams,
    NostrBridgeEventScratch, NostrBridgeIngress, bridge_message_to_nostr_event,
    bridge_message_to_nostr_event_json, nostr_event_to_bridge_message,
};
pub use hyf_link_nostr::{NostrEvent, NostrSecretKey};

#[cfg(test)]
mod tests {
    use super::HYF_NOSTR_BRIDGE_EVENT_KIND;

    #[test]
    fn crate_builds() {
        assert_eq!(HYF_NOSTR_BRIDGE_EVENT_KIND, 9109);
    }
}
