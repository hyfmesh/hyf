use hyf_wire::{HyfEnvelopeRef, decode_envelope};

use crate::{
    HYF_NOSTR_ENVELOPE_KIND, NostrError, NostrEvent, NostrPublicKey, NostrSecretKey, NostrTagRef,
    NostrTagsRef, NostrUnsignedEvent, decode_hyf_envelope_content, derive_nostr_public_key,
    encode_hyf_envelope_content, sign_event, verify_event,
};

pub const HYF_NOSTR_TOPIC_TAG: &str = "hyf";
pub const HYF_NOSTR_ALT_TAG: &str = "hyf gateway envelope";

pub struct HyfNostrEventScratch {
    content: [u8; crate::HYF_NOSTR_MAX_CONTENT_CHARS],
    recipient_hex: [u8; 64],
}

impl HyfNostrEventScratch {
    pub const fn new() -> Self {
        Self {
            content: [0; crate::HYF_NOSTR_MAX_CONTENT_CHARS],
            recipient_hex: [0; 64],
        }
    }
}

impl Default for HyfNostrEventScratch {
    fn default() -> Self {
        Self::new()
    }
}

pub fn with_signed_hyf_nostr_event<T>(
    encoded_envelope: &[u8],
    author_secret: &NostrSecretKey,
    recipient_pubkey: NostrPublicKey,
    created_at: u64,
    scratch: &mut HyfNostrEventScratch,
    f: impl for<'event> FnOnce(NostrEvent<'event>) -> T,
) -> Result<T, NostrError> {
    let content = encode_hyf_envelope_content(encoded_envelope, &mut scratch.content)?;
    let recipient_hex = recipient_pubkey.write_hex(&mut scratch.recipient_hex)?;

    let p_tag_values = ["p", recipient_hex];
    let t_tag_values = ["t", HYF_NOSTR_TOPIC_TAG];
    let alt_tag_values = ["alt", HYF_NOSTR_ALT_TAG];
    let tags = [
        NostrTagRef::new(&p_tag_values)?,
        NostrTagRef::new(&t_tag_values)?,
        NostrTagRef::new(&alt_tag_values)?,
    ];

    let author_pubkey = derive_nostr_public_key(author_secret)?;
    let unsigned = NostrUnsignedEvent::new(
        author_pubkey,
        created_at,
        HYF_NOSTR_ENVELOPE_KIND,
        NostrTagsRef::new(&tags),
        content,
    )?;
    Ok(f(sign_event(unsigned, author_secret)?))
}

pub fn verify_and_decode_hyf_nostr_event<'out>(
    event: &NostrEvent<'_>,
    out: &'out mut [u8],
) -> Result<HyfEnvelopeRef<'out>, NostrError> {
    verify_event(event)?;
    if event.kind != HYF_NOSTR_ENVELOPE_KIND {
        return Err(NostrError::UnexpectedKind {
            expected: HYF_NOSTR_ENVELOPE_KIND,
            actual: event.kind,
        });
    }
    if !has_p_tag(event.tags) {
        return Err(NostrError::MissingRequiredTag { tag: "p" });
    }

    let len = decode_hyf_envelope_content(event.content, out)?;
    decode_envelope(&out[..len]).map_err(|_| NostrError::MalformedEnvelope)
}

fn has_p_tag(tags: NostrTagsRef<'_>) -> bool {
    tags.as_slice()
        .iter()
        .any(|tag| tag.name() == "p" && tag.value().is_some_and(|value| !value.is_empty()))
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, encode_envelope,
    };

    use super::{
        HYF_NOSTR_ALT_TAG, HYF_NOSTR_TOPIC_TAG, HyfNostrEventScratch,
        verify_and_decode_hyf_nostr_event, with_signed_hyf_nostr_event,
    };
    use crate::{
        HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS, NostrError, NostrEvent,
        NostrPublicKey, NostrSecretKey, NostrSignature, NostrTagRef, NostrTagsRef,
        NostrUnsignedEvent, encode_hyf_envelope_content, sign_event,
    };

    #[test]
    fn hyf_event_helper_builds_and_decodes_signed_event() -> Result<(), NostrError> {
        let encoded = encoded_sample_envelope()?;
        let author_secret = fixture_secret();
        let recipient = NostrPublicKey::from_bytes([0x77; 32]);
        let mut scratch = HyfNostrEventScratch::new();

        with_signed_hyf_nostr_event(
            &encoded,
            &author_secret,
            recipient,
            1720000000,
            &mut scratch,
            |event| {
                assert_eq!(event.kind, HYF_NOSTR_ENVELOPE_KIND);
                assert_eq!(event.tags.as_slice()[0].name(), "p");
                assert_eq!(
                    event.tags.as_slice()[1].values(),
                    &["t", HYF_NOSTR_TOPIC_TAG]
                );
                assert_eq!(
                    event.tags.as_slice()[2].values(),
                    &["alt", HYF_NOSTR_ALT_TAG]
                );

                let mut decoded = [0; 256];
                let envelope = verify_and_decode_hyf_nostr_event(&event, &mut decoded)?;
                assert_eq!(envelope, sample_envelope());
                Ok::<(), NostrError>(())
            },
        )?
    }

    #[test]
    fn hyf_event_helper_rejects_wrong_kind_bad_signature_and_missing_p() -> Result<(), NostrError> {
        let encoded = encoded_sample_envelope()?;
        let mut content_buf = [0; HYF_NOSTR_MAX_CONTENT_CHARS];
        let content = encode_hyf_envelope_content(&encoded, &mut content_buf)?;
        let p_tag_values = ["p", "77"];
        let p_tag = NostrTagRef::new(&p_tag_values)?;
        let tags = [p_tag];
        let tags = NostrTagsRef::new(&tags);
        let secret = fixture_secret();
        let author_pubkey = crate::derive_nostr_public_key(&secret)?;

        let wrong_kind = sign_event(
            NostrUnsignedEvent::new(author_pubkey, 1720000000, 1, tags, content)?,
            &secret,
        )?;
        assert_eq!(
            verify_and_decode_hyf_nostr_event(&wrong_kind, &mut [0; 256]),
            Err(NostrError::UnexpectedKind {
                expected: HYF_NOSTR_ENVELOPE_KIND,
                actual: 1,
            })
        );

        let valid = sign_event(
            NostrUnsignedEvent::new(
                author_pubkey,
                1720000000,
                HYF_NOSTR_ENVELOPE_KIND,
                tags,
                content,
            )?,
            &secret,
        )?;
        let mut bad_sig_bytes = *valid.sig.as_bytes();
        bad_sig_bytes[0] ^= 0x01;
        let bad_sig = NostrEvent {
            sig: NostrSignature::from_bytes(bad_sig_bytes),
            ..valid
        };
        assert_eq!(
            verify_and_decode_hyf_nostr_event(&bad_sig, &mut [0; 256]),
            Err(NostrError::InvalidSignature)
        );

        let no_p = sign_event(
            NostrUnsignedEvent::new(
                author_pubkey,
                1720000000,
                HYF_NOSTR_ENVELOPE_KIND,
                NostrTagsRef::new(&[]),
                content,
            )?,
            &secret,
        )?;
        assert_eq!(
            verify_and_decode_hyf_nostr_event(&no_p, &mut [0; 256]),
            Err(NostrError::MissingRequiredTag { tag: "p" })
        );
        Ok(())
    }

    #[test]
    fn hyf_event_helper_rejects_malformed_content_and_envelope() -> Result<(), NostrError> {
        let p_tag_values = ["p", "77"];
        let p_tag = NostrTagRef::new(&p_tag_values)?;
        let tags = [p_tag];
        let tags = NostrTagsRef::new(&tags);
        let secret = fixture_secret();
        let author_pubkey = crate::derive_nostr_public_key(&secret)?;

        let malformed_content = sign_event(
            NostrUnsignedEvent::new(
                author_pubkey,
                1720000000,
                HYF_NOSTR_ENVELOPE_KIND,
                tags,
                "zz",
            )?,
            &secret,
        )?;
        assert!(matches!(
            verify_and_decode_hyf_nostr_event(&malformed_content, &mut [0; 256]),
            Err(NostrError::InvalidHexChar {
                index: 0,
                byte: b'z'
            })
        ));

        let malformed_envelope = sign_event(
            NostrUnsignedEvent::new(
                author_pubkey,
                1720000000,
                HYF_NOSTR_ENVELOPE_KIND,
                tags,
                "00",
            )?,
            &secret,
        )?;
        assert_eq!(
            verify_and_decode_hyf_nostr_event(&malformed_envelope, &mut [0; 256]),
            Err(NostrError::MalformedEnvelope)
        );
        Ok(())
    }

    fn encoded_sample_envelope() -> Result<[u8; 123], NostrError> {
        let envelope = sample_envelope();
        let mut encoded = [0; 123];
        let len =
            encode_envelope(envelope, &mut encoded).map_err(|_| NostrError::MalformedEnvelope)?;
        assert_eq!(len, encoded.len());
        Ok(encoded)
    }

    fn sample_envelope<'a>() -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([0x11; 32]),
            source: NodeId([0x22; 32]),
            destination: HyfDestination::Node(NodeId([0x33; 32])),
            created_at_ms: TimestampMs(1000),
            expires_at_ms: TimestampMs(2000),
            hop_limit: 8,
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"hello",
        }
    }

    fn fixture_secret() -> NostrSecretKey {
        let mut secret_key = [0; 32];
        secret_key[31] = 3;
        NostrSecretKey::from_bytes(secret_key)
    }
}
