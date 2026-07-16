use core::fmt;

use hyf_bridge_core::{
    BridgeEndpointKind, BridgeIngressMeta, BridgeMessageRef, BridgeProtocol,
    BridgeVerificationState, HYF_BRIDGE_MESSAGE_MAX_LEN, decode_bridge_message,
    validate_bridge_message,
};
use hyf_core::{CommunityId, ForeignNetworkKind};
use hyf_link_nostr::{
    NostrEvent, NostrPublicKey, NostrSecretKey, NostrTagRef, NostrTagsRef, NostrUnsignedEvent,
    decode_fixed_lower_hex, derive_nostr_public_key, encode_lower_hex, sign_event, verify_event,
};

use crate::{NostrBridgeError, decode_bridge_nostr_content, encode_bridge_nostr_content};

pub const HYF_NOSTR_BRIDGE_EVENT_KIND: u16 = 9109;
pub const HYF_NOSTR_BRIDGE_HYF_TAG: &str = "hyf";
pub const HYF_NOSTR_BRIDGE_VERSION_TAG: &str = "v0";
pub const HYF_NOSTR_BRIDGE_ALT_TAG: &str = "HYF bridge message";

pub struct NostrBridgeEventScratch {
    content: [u8; HYF_BRIDGE_MESSAGE_MAX_LEN * 2],
    community_hex: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NostrBridgeIngress<'a> {
    pub raw_bridge_message: &'a [u8],
    pub bridge_message: BridgeMessageRef<'a>,
    pub ingress_meta: BridgeIngressMeta,
}

impl NostrBridgeEventScratch {
    pub const fn new() -> Self {
        Self {
            content: [0; HYF_BRIDGE_MESSAGE_MAX_LEN * 2],
            community_hex: [0; 32],
        }
    }
}

impl Default for NostrBridgeEventScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NostrBridgeEventScratch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrBridgeEventScratch")
            .field("content_capacity", &self.content.len())
            .field("community_hex_capacity", &self.community_hex.len())
            .finish()
    }
}

impl fmt::Debug for NostrBridgeIngress<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrBridgeIngress")
            .field("raw_bridge_message", &"<redacted>")
            .field("raw_bridge_message_len", &self.raw_bridge_message.len())
            .field("bridge_message", &self.bridge_message)
            .field("ingress_meta", &self.ingress_meta)
            .finish()
    }
}

pub fn bridge_message_to_nostr_event<T>(
    raw_bridge_message: &[u8],
    author_secret: &NostrSecretKey,
    created_at: u64,
    scratch: &mut NostrBridgeEventScratch,
    f: impl for<'event> FnOnce(NostrEvent<'event>) -> T,
) -> Result<T, NostrBridgeError> {
    let bridge_message = validate_bridge_message(raw_bridge_message)?;
    let content = encode_bridge_nostr_content(raw_bridge_message, &mut scratch.content)?;
    let community_hex = encode_lower_hex(&bridge_message.room_id.0, &mut scratch.community_hex)?;
    let hyf_values = [
        HYF_NOSTR_BRIDGE_HYF_TAG,
        "bridge",
        HYF_NOSTR_BRIDGE_VERSION_TAG,
    ];
    let community_values = ["community", community_hex];
    let alt_values = ["alt", HYF_NOSTR_BRIDGE_ALT_TAG];
    let tags = [
        NostrTagRef::new(&hyf_values)?,
        NostrTagRef::new(&community_values)?,
        NostrTagRef::new(&alt_values)?,
    ];
    let pubkey = derive_nostr_public_key(author_secret)?;
    let unsigned = NostrUnsignedEvent::new(
        pubkey,
        created_at,
        HYF_NOSTR_BRIDGE_EVENT_KIND,
        NostrTagsRef::new(&tags),
        content,
    )?;
    Ok(f(sign_event(unsigned, author_secret)?))
}

pub fn nostr_event_to_bridge_message<'out>(
    event: &NostrEvent<'_>,
    output: &'out mut [u8],
) -> Result<NostrBridgeIngress<'out>, NostrBridgeError> {
    verify_event(event)?;
    if event.kind != HYF_NOSTR_BRIDGE_EVENT_KIND {
        return Err(NostrBridgeError::WrongKind { actual: event.kind });
    }
    require_static_tag(
        event.tags,
        &[
            HYF_NOSTR_BRIDGE_HYF_TAG,
            "bridge",
            HYF_NOSTR_BRIDGE_VERSION_TAG,
        ],
        "hyf",
    )?;
    require_static_tag(event.tags, &["alt", HYF_NOSTR_BRIDGE_ALT_TAG], "alt")?;
    let community_id = require_community_tag(event.tags)?;
    let raw = decode_bridge_nostr_content(event.content, output)?;
    let bridge_message = decode_bridge_message(raw)?;
    if community_id != bridge_message.room_id {
        return Err(NostrBridgeError::CommunityTagMismatch);
    }
    validate_nostr_author_rule(event.pubkey, bridge_message)?;

    Ok(NostrBridgeIngress {
        raw_bridge_message: raw,
        bridge_message,
        ingress_meta: BridgeIngressMeta {
            origin_protocol: BridgeProtocol::Nostr,
            verification_state: BridgeVerificationState::TransportSigned,
        },
    })
}

fn require_static_tag(
    tags: NostrTagsRef<'_>,
    expected: &[&str],
    missing_name: &'static str,
) -> Result<(), NostrBridgeError> {
    if tags.as_slice().iter().any(|tag| tag.values() == expected) {
        return Ok(());
    }
    Err(NostrBridgeError::MissingRequiredTag { tag: missing_name })
}

fn require_community_tag(tags: NostrTagsRef<'_>) -> Result<CommunityId, NostrBridgeError> {
    for tag in tags.as_slice() {
        let values = tag.values();
        if values.len() == 2 && values[0] == "community" {
            return Ok(CommunityId(decode_fixed_lower_hex(values[1])?));
        }
    }
    Err(NostrBridgeError::MissingRequiredTag { tag: "community" })
}

fn validate_nostr_author_rule(
    pubkey: NostrPublicKey,
    bridge_message: BridgeMessageRef<'_>,
) -> Result<(), NostrBridgeError> {
    if bridge_message.author.kind == BridgeEndpointKind::Foreign(ForeignNetworkKind::Nostr)
        && bridge_message.author.id != pubkey.as_bytes()
    {
        return Err(NostrBridgeError::NostrAuthorPubkeyMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeMessageRef, BridgePayloadKind, BridgeProtocol,
        BridgeVerificationState, HYF_BRIDGE_MESSAGE_VERSION_0, encode_bridge_message,
    };
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};
    use hyf_link_nostr::{
        FakeNostrPublishProfile, FakeNostrRelay, FakeNostrRelayOutput, NostrError, NostrFilter,
        NostrPublicKey, NostrSecretKey, NostrTagRef, NostrTagsRef, NostrUnsignedEvent,
        derive_nostr_public_key, encode_lower_hex, sign_event,
    };

    use super::{
        HYF_NOSTR_BRIDGE_ALT_TAG, HYF_NOSTR_BRIDGE_EVENT_KIND, NostrBridgeEventScratch,
        bridge_message_to_nostr_event, nostr_event_to_bridge_message,
    };
    use crate::NostrBridgeError;

    const ROOM: CommunityId = CommunityId([0x51; 16]);
    const MESSAGE: MessageId = MessageId([0x52; 32]);

    #[test]
    fn signed_bridge_event_sets_kind_tags_content_and_decodes() -> Result<(), NostrBridgeError> {
        let secret = fixture_secret();
        let pubkey = derive_nostr_public_key(&secret)?;
        let raw = raw_bridge_message(pubkey.as_bytes())?;
        let mut scratch = NostrBridgeEventScratch::new();

        bridge_message_to_nostr_event(&raw, &secret, 1720000000, &mut scratch, |event| {
            assert_eq!(event.kind, HYF_NOSTR_BRIDGE_EVENT_KIND);
            assert!(
                event
                    .tags
                    .as_slice()
                    .iter()
                    .any(|tag| tag.values() == ["hyf", "bridge", "v0"])
            );
            assert!(
                event
                    .tags
                    .as_slice()
                    .iter()
                    .any(|tag| tag.values() == ["alt", HYF_NOSTR_BRIDGE_ALT_TAG])
            );
            let mut output = [0; 256];
            let decoded = nostr_event_to_bridge_message(&event, &mut output)?;
            assert_eq!(decoded.raw_bridge_message, raw.as_slice());
            assert_eq!(decoded.bridge_message.room_id, ROOM);
            assert_eq!(decoded.bridge_message.message_id, MESSAGE);
            assert_eq!(decoded.ingress_meta.origin_protocol, BridgeProtocol::Nostr);
            assert_eq!(
                decoded.ingress_meta.verification_state,
                BridgeVerificationState::TransportSigned
            );
            Ok::<(), NostrBridgeError>(())
        })??;
        Ok(())
    }

    #[test]
    fn bridge_events_store_and_replay_through_fake_relay_profile() -> Result<(), NostrBridgeError> {
        let secret = fixture_secret();
        let pubkey = derive_nostr_public_key(&secret)?;
        let raw = raw_bridge_message(pubkey.as_bytes())?;
        let mut scratch = NostrBridgeEventScratch::new();

        bridge_message_to_nostr_event(&raw, &secret, 1720000000, &mut scratch, |event| {
            let mut relay = FakeNostrRelay::<2, 1, 4>::new();
            let mut decode = [0; 256];
            let outcome = relay.publish_with_profile(
                event,
                &mut decode,
                FakeNostrPublishProfile::SignedKind {
                    kind: HYF_NOSTR_BRIDGE_EVENT_KIND,
                },
            )?;
            assert!(matches!(
                outcome,
                hyf_link_nostr::NostrPublishOutcome::Accepted { .. }
            ));
            relay.consume_output();

            let kinds = [HYF_NOSTR_BRIDGE_EVENT_KIND];
            let filter = [NostrFilter {
                kinds: &kinds,
                ..NostrFilter::empty()
            }];
            relay.subscribe("bridge", &filter)?;
            let replayed = relay.pop_next_output(|output| match output {
                FakeNostrRelayOutput::Event { event, .. } => {
                    nostr_event_to_bridge_message(&event, &mut decode)?;
                    Ok::<bool, NostrBridgeError>(true)
                }
                _ => Ok::<bool, NostrBridgeError>(false),
            })?;

            assert_eq!(replayed, Some(Ok(true)));
            Ok::<(), NostrBridgeError>(())
        })??;
        Ok(())
    }

    #[test]
    fn decode_rejects_wrong_kind_missing_tags_bad_content_and_mismatch()
    -> Result<(), NostrBridgeError> {
        let secret = fixture_secret();
        let pubkey = derive_nostr_public_key(&secret)?;
        let raw = raw_bridge_message(pubkey.as_bytes())?;
        let mut scratch = NostrBridgeEventScratch::new();

        bridge_message_to_nostr_event(&raw, &secret, 1720000000, &mut scratch, |event| {
            let wrong_kind = signed_event(event.pubkey, 1, event.tags, event.content)?;
            assert_eq!(
                nostr_event_to_bridge_message(&wrong_kind, &mut [0; 256]),
                Err(NostrBridgeError::WrongKind { actual: 1 })
            );

            let missing_tags = signed_event(
                event.pubkey,
                HYF_NOSTR_BRIDGE_EVENT_KIND,
                NostrTagsRef::new(&[]),
                event.content,
            )?;
            assert_eq!(
                nostr_event_to_bridge_message(&missing_tags, &mut [0; 256]),
                Err(NostrBridgeError::MissingRequiredTag { tag: "hyf" })
            );

            let malformed_content =
                signed_event(event.pubkey, HYF_NOSTR_BRIDGE_EVENT_KIND, event.tags, "zz")?;
            assert!(matches!(
                nostr_event_to_bridge_message(&malformed_content, &mut [0; 256]),
                Err(NostrBridgeError::Nostr(NostrError::InvalidHexChar { .. }))
            ));

            let mut wrong_room_hex = [0; 32];
            let wrong_room = encode_lower_hex(&[0x99; 16], &mut wrong_room_hex)?;
            let hyf_values = ["hyf", "bridge", "v0"];
            let community_values = ["community", wrong_room];
            let alt_values = ["alt", HYF_NOSTR_BRIDGE_ALT_TAG];
            let tags = [
                NostrTagRef::new(&hyf_values)?,
                NostrTagRef::new(&community_values)?,
                NostrTagRef::new(&alt_values)?,
            ];
            let community_mismatch = signed_event(
                event.pubkey,
                HYF_NOSTR_BRIDGE_EVENT_KIND,
                NostrTagsRef::new(&tags),
                event.content,
            )?;
            assert_eq!(
                nostr_event_to_bridge_message(&community_mismatch, &mut [0; 256]),
                Err(NostrBridgeError::CommunityTagMismatch)
            );

            Ok::<(), NostrBridgeError>(())
        })??;
        Ok(())
    }

    #[test]
    fn decode_rejects_nostr_author_pubkey_mismatch() -> Result<(), NostrBridgeError> {
        let secret = fixture_secret();
        let raw = raw_bridge_message(&[0x99; 32])?;
        let mut scratch = NostrBridgeEventScratch::new();

        bridge_message_to_nostr_event(&raw, &secret, 1720000000, &mut scratch, |event| {
            assert_eq!(
                nostr_event_to_bridge_message(&event, &mut [0; 256]),
                Err(NostrBridgeError::NostrAuthorPubkeyMismatch)
            );
            Ok::<(), NostrBridgeError>(())
        })??;
        Ok(())
    }

    fn raw_bridge_message(author_id: &[u8; 32]) -> Result<Vec<u8>, NostrBridgeError> {
        let mut raw = vec![0; 128];
        let len = encode_bridge_message(bridge_message(author_id), &mut raw)?;
        raw.truncate(len);
        Ok(raw)
    }

    fn bridge_message(author_id: &[u8; 32]) -> BridgeMessageRef<'_> {
        BridgeMessageRef {
            version: HYF_BRIDGE_MESSAGE_VERSION_0,
            room_id: ROOM,
            message_id: MESSAGE,
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::Nostr),
                id: author_id,
            },
            created_at_ms: TimestampMs(1000),
            payload_kind: BridgePayloadKind::TextUtf8,
            payload: b"hello",
        }
    }

    fn signed_event<'a>(
        pubkey: NostrPublicKey,
        kind: u16,
        tags: NostrTagsRef<'a>,
        content: &'a str,
    ) -> Result<hyf_link_nostr::NostrEvent<'a>, NostrBridgeError> {
        Ok(sign_event(
            NostrUnsignedEvent::new(pubkey, 1720000000, kind, tags, content)?,
            &fixture_secret(),
        )?)
    }

    fn fixture_secret() -> NostrSecretKey {
        let mut secret = [0; 32];
        secret[31] = 3;
        NostrSecretKey::from_bytes(secret)
    }
}
