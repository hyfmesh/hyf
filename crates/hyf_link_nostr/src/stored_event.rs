use core::fmt;

use crate::stored::{StoredNostrTags, StoredString};
use crate::{
    HYF_NOSTR_MAX_CONTENT_CHARS, HYF_NOSTR_MAX_TAG_VALUE_CHARS, HYF_NOSTR_MAX_TAG_VALUES,
    HYF_NOSTR_MAX_TAGS, NostrError, NostrEvent, NostrEventId, NostrPublicKey, NostrSignature,
    NostrTagRef, NostrTagsRef,
};

const DUMMY_TAG_VALUES: [&str; 1] = ["_"];

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct FakeNostrEventRecord {
    id: NostrEventId,
    pubkey: NostrPublicKey,
    created_at: u64,
    kind: u16,
    sig: NostrSignature,
    content: StoredString<HYF_NOSTR_MAX_CONTENT_CHARS>,
    tags: StoredNostrTags<
        HYF_NOSTR_MAX_TAGS,
        HYF_NOSTR_MAX_TAG_VALUES,
        HYF_NOSTR_MAX_TAG_VALUE_CHARS,
    >,
}

impl FakeNostrEventRecord {
    pub(crate) fn from_event(event: &NostrEvent<'_>) -> Result<Self, NostrError> {
        Ok(Self {
            id: event.id,
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            sig: event.sig,
            content: StoredString::from_str(event.content)?,
            tags: StoredNostrTags::from_ref(event.tags)?,
        })
    }

    pub(crate) const fn id(&self) -> NostrEventId {
        self.id
    }

    pub(crate) const fn pubkey(&self) -> NostrPublicKey {
        self.pubkey
    }

    pub(crate) const fn created_at(&self) -> u64 {
        self.created_at
    }

    pub(crate) const fn kind(&self) -> u16 {
        self.kind
    }

    pub(crate) fn collect_p_tags(&self, out: &mut [NostrPublicKey]) -> Result<usize, NostrError> {
        let mut count = 0;
        for index in 0..self.tags.len() {
            let Some(tag) = self.tags.tag(index) else {
                break;
            };
            if tag.value(0)? != Some("p") || count == out.len() {
                continue;
            }
            let Some(value) = tag.value(1)? else {
                continue;
            };
            let Ok(public_key) = NostrPublicKey::from_hex(value) else {
                continue;
            };
            out[count] = public_key;
            count += 1;
        }
        Ok(count)
    }

    pub(crate) fn with_event<T>(
        &self,
        f: impl for<'event> FnOnce(NostrEvent<'event>) -> Result<T, NostrError>,
    ) -> Result<T, NostrError> {
        let dummy = NostrTagRef::new(&DUMMY_TAG_VALUES)?;
        let mut tag_values = [[""; HYF_NOSTR_MAX_TAG_VALUES]; HYF_NOSTR_MAX_TAGS];
        let mut tag_value_counts = [0usize; HYF_NOSTR_MAX_TAGS];
        let mut tag_refs = [dummy; HYF_NOSTR_MAX_TAGS];

        for tag_index in 0..self.tags.len() {
            let Some(tag) = self.tags.tag(tag_index) else {
                break;
            };
            for (value_index, value_slot) in
                tag_values[tag_index].iter_mut().enumerate().take(tag.len())
            {
                let Some(value) = tag.value(value_index)? else {
                    break;
                };
                *value_slot = value;
            }
            tag_value_counts[tag_index] = tag.len();
        }

        for tag_index in 0..self.tags.len() {
            tag_refs[tag_index] =
                NostrTagRef::new(&tag_values[tag_index][..tag_value_counts[tag_index]])?;
        }

        let content = self.content.as_str()?;
        let event = NostrEvent::new(
            self.id,
            self.pubkey,
            self.created_at,
            self.kind,
            NostrTagsRef::new(&tag_refs[..self.tags.len()]),
            content,
            self.sig,
        )?;
        f(event)
    }
}

impl fmt::Debug for FakeNostrEventRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeNostrEventRecord")
            .field("id", &self.id)
            .field("pubkey", &self.pubkey)
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("sig", &self.sig)
            .field("content_len", &self.content.len())
            .field("tag_count", &self.tags.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::FakeNostrEventRecord;
    use crate::{
        HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_TAG_VALUE_CHARS, HYF_NOSTR_MAX_TAG_VALUES,
        HYF_NOSTR_MAX_TAGS, NostrError, NostrEvent, NostrEventId, NostrPublicKey, NostrSecretKey,
        NostrSignature, NostrTagRef, NostrTagsRef, NostrUnsignedEvent, derive_nostr_public_key,
        sign_event, verify_event,
    };

    const RECIPIENT: NostrPublicKey = NostrPublicKey::from_bytes([0x77; 32]);

    #[test]
    fn stored_event_record_preserves_canonical_event_view() -> Result<(), NostrError> {
        with_base_tags(|tags| {
            let event = signed_event("abcd", tags)?;
            let record = FakeNostrEventRecord::from_event(&event)?;

            assert_eq!(record.id(), event.id);
            assert_eq!(record.pubkey(), event.pubkey);
            assert_eq!(record.created_at(), event.created_at);
            assert_eq!(record.kind(), event.kind);
            record.with_event(|view| {
                assert_eq!(view, event);
                verify_event(&view)
            })
        })
    }

    #[test]
    fn stored_event_record_extracts_p_tags() -> Result<(), NostrError> {
        with_base_tags(|tags| {
            let event = signed_event("abcd", tags)?;
            let record = FakeNostrEventRecord::from_event(&event)?;
            let mut p_tags = [NostrPublicKey::from_bytes([0; 32]); 2];

            let count = record.collect_p_tags(&mut p_tags)?;

            assert_eq!(count, 1);
            assert_eq!(p_tags[0], RECIPIENT);
            Ok(())
        })
    }

    #[test]
    fn stored_event_record_rejects_over_limit_tags() -> Result<(), NostrError> {
        let mut hex = [0; 64];
        let values = ["p", RECIPIENT.write_hex(&mut hex)?];
        let tag = NostrTagRef::new(&values)?;
        let tags = [tag; HYF_NOSTR_MAX_TAGS + 1];
        let event = signed_event("abcd", NostrTagsRef::new(&tags))?;

        assert_eq!(
            FakeNostrEventRecord::from_event(&event),
            Err(NostrError::TagCountTooLarge {
                actual: HYF_NOSTR_MAX_TAGS + 1,
                maximum: HYF_NOSTR_MAX_TAGS,
            })
        );
        Ok(())
    }

    #[test]
    fn stored_event_record_rejects_over_limit_tag_values() -> Result<(), NostrError> {
        let values = ["p"; HYF_NOSTR_MAX_TAG_VALUES + 1];
        let tag = NostrTagRef::new(&values)?;
        let tags = [tag];
        let event = signed_event("abcd", NostrTagsRef::new(&tags))?;

        assert_eq!(
            FakeNostrEventRecord::from_event(&event),
            Err(NostrError::TagValueCountTooLarge {
                actual: HYF_NOSTR_MAX_TAG_VALUES + 1,
                maximum: HYF_NOSTR_MAX_TAG_VALUES,
            })
        );
        Ok(())
    }

    #[test]
    fn stored_event_record_rejects_over_limit_tag_value_length() -> Result<(), NostrError> {
        let value = "a".repeat(HYF_NOSTR_MAX_TAG_VALUE_CHARS + 1);
        let values = ["p", value.as_str()];
        let tag = NostrTagRef::new(&values)?;
        let tags = [tag];
        let event = signed_event("abcd", NostrTagsRef::new(&tags))?;

        assert_eq!(
            FakeNostrEventRecord::from_event(&event),
            Err(NostrError::TagValueTooLarge {
                actual: HYF_NOSTR_MAX_TAG_VALUE_CHARS + 1,
                maximum: HYF_NOSTR_MAX_TAG_VALUE_CHARS,
            })
        );
        Ok(())
    }

    #[test]
    fn stored_event_record_debug_redacts_content() -> Result<(), NostrError> {
        with_base_tags(|tags| {
            let event = signed_event("secret-content", tags)?;
            let record = FakeNostrEventRecord::from_event(&event)?;
            let debug = format!("{record:?}");

            assert!(debug.contains("content_len"));
            assert!(!debug.contains("secret-content"));
            Ok(())
        })
    }

    fn signed_event<'a>(
        content: &'a str,
        tags: NostrTagsRef<'a>,
    ) -> Result<NostrEvent<'a>, NostrError> {
        let secret = fixture_secret();
        let unsigned = NostrUnsignedEvent::new(
            derive_nostr_public_key(&secret)?,
            1_720_000_000,
            HYF_NOSTR_ENVELOPE_KIND,
            tags,
            content,
        )?;
        sign_event(unsigned, &secret)
    }

    fn with_base_tags<T>(
        f: impl for<'tags> FnOnce(NostrTagsRef<'tags>) -> Result<T, NostrError>,
    ) -> Result<T, NostrError> {
        let mut recipient_hex = [0; 64];
        let recipient_hex = RECIPIENT.write_hex(&mut recipient_hex)?;
        let values = ["p", recipient_hex];
        let tag = NostrTagRef::new(&values)?;
        let tags = [tag];
        f(NostrTagsRef::new(&tags))
    }

    fn fixture_secret() -> NostrSecretKey {
        let mut secret_key = [0; 32];
        secret_key[31] = 3;
        NostrSecretKey::from_bytes(secret_key)
    }

    #[test]
    fn stored_event_record_preserves_manual_event() -> Result<(), NostrError> {
        let tag_values = ["t", "hyf"];
        let tag = NostrTagRef::new(&tag_values)?;
        let tags = [tag];
        let event = NostrEvent::new(
            NostrEventId::from_bytes([0x11; 32]),
            NostrPublicKey::from_bytes([0x22; 32]),
            1,
            HYF_NOSTR_ENVELOPE_KIND,
            NostrTagsRef::new(&tags),
            "00",
            NostrSignature::from_bytes([0x33; 64]),
        )?;
        let record = FakeNostrEventRecord::from_event(&event)?;

        record.with_event(|view| {
            assert_eq!(view, event);
            Ok(())
        })
    }
}
