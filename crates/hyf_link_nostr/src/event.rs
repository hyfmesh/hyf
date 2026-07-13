use core::fmt;

use crate::{
    HYF_NOSTR_MAX_CONTENT_CHARS, NostrError, NostrEventId, NostrPublicKey, NostrSignature,
    NostrTagsRef,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NostrUnsignedEvent<'a> {
    pub pubkey: NostrPublicKey,
    pub created_at: u64,
    pub kind: u16,
    pub tags: NostrTagsRef<'a>,
    pub content: &'a str,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NostrEvent<'a> {
    pub id: NostrEventId,
    pub pubkey: NostrPublicKey,
    pub created_at: u64,
    pub kind: u16,
    pub tags: NostrTagsRef<'a>,
    pub content: &'a str,
    pub sig: NostrSignature,
}

impl<'a> NostrUnsignedEvent<'a> {
    pub fn new(
        pubkey: NostrPublicKey,
        created_at: u64,
        kind: u16,
        tags: NostrTagsRef<'a>,
        content: &'a str,
    ) -> Result<Self, NostrError> {
        validate_content_len(content)?;
        Ok(Self {
            pubkey,
            created_at,
            kind,
            tags,
            content,
        })
    }
}

impl<'a> NostrEvent<'a> {
    pub fn new(
        id: NostrEventId,
        pubkey: NostrPublicKey,
        created_at: u64,
        kind: u16,
        tags: NostrTagsRef<'a>,
        content: &'a str,
        sig: NostrSignature,
    ) -> Result<Self, NostrError> {
        validate_content_len(content)?;
        Ok(Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        })
    }

    pub fn unsigned(&self) -> NostrUnsignedEvent<'a> {
        NostrUnsignedEvent {
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags,
            content: self.content,
        }
    }
}

impl fmt::Debug for NostrUnsignedEvent<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrUnsignedEvent")
            .field("pubkey", &self.pubkey)
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("tags", &self.tags)
            .field("content_len", &self.content.len())
            .finish()
    }
}

impl fmt::Debug for NostrEvent<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrEvent")
            .field("id", &self.id)
            .field("pubkey", &self.pubkey)
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("tags", &self.tags)
            .field("content_len", &self.content.len())
            .field("sig", &self.sig)
            .finish()
    }
}

pub fn validate_content_len(content: &str) -> Result<(), NostrError> {
    let actual = content.len();
    if actual > HYF_NOSTR_MAX_CONTENT_CHARS {
        return Err(NostrError::ContentTooLarge {
            actual,
            maximum: HYF_NOSTR_MAX_CONTENT_CHARS,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NostrEvent, NostrUnsignedEvent};
    use crate::{
        HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS, NostrError, NostrEventId,
        NostrPublicKey, NostrSignature, NostrTagsRef,
    };

    const PUBLIC_KEY: NostrPublicKey = NostrPublicKey::from_bytes([0x11; 32]);
    const EVENT_ID: NostrEventId = NostrEventId::from_bytes([0x22; 32]);
    const SIGNATURE: NostrSignature = NostrSignature::from_bytes([0x33; 64]);

    #[test]
    fn unsigned_event_preserves_fields() -> Result<(), NostrError> {
        let event = NostrUnsignedEvent::new(
            PUBLIC_KEY,
            1720000000,
            HYF_NOSTR_ENVELOPE_KIND,
            NostrTagsRef::new(&[]),
            "abcd",
        )?;

        assert_eq!(event.pubkey, PUBLIC_KEY);
        assert_eq!(event.created_at, 1720000000);
        assert_eq!(event.kind, HYF_NOSTR_ENVELOPE_KIND);
        assert_eq!(event.content, "abcd");
        Ok(())
    }

    #[test]
    fn signed_event_preserves_fields_and_unsigned_view() -> Result<(), NostrError> {
        let event = NostrEvent::new(
            EVENT_ID,
            PUBLIC_KEY,
            1720000001,
            HYF_NOSTR_ENVELOPE_KIND,
            NostrTagsRef::new(&[]),
            "abcd",
            SIGNATURE,
        )?;

        let unsigned = event.unsigned();
        assert_eq!(event.id, EVENT_ID);
        assert_eq!(event.sig, SIGNATURE);
        assert_eq!(unsigned.pubkey, PUBLIC_KEY);
        assert_eq!(unsigned.created_at, 1720000001);
        assert_eq!(unsigned.kind, HYF_NOSTR_ENVELOPE_KIND);
        assert_eq!(unsigned.content, "abcd");
        Ok(())
    }

    #[test]
    fn events_reject_oversized_content() {
        let content = "a".repeat(HYF_NOSTR_MAX_CONTENT_CHARS + 1);
        assert!(matches!(
            NostrUnsignedEvent::new(
                PUBLIC_KEY,
                1,
                HYF_NOSTR_ENVELOPE_KIND,
                NostrTagsRef::new(&[]),
                &content,
            ),
            Err(NostrError::ContentTooLarge {
                actual,
                maximum: HYF_NOSTR_MAX_CONTENT_CHARS
            }) if actual == HYF_NOSTR_MAX_CONTENT_CHARS + 1
        ));
    }

    #[test]
    fn event_debug_redacts_content() -> Result<(), NostrError> {
        let event = NostrEvent::new(
            EVENT_ID,
            PUBLIC_KEY,
            1,
            HYF_NOSTR_ENVELOPE_KIND,
            NostrTagsRef::new(&[]),
            "secret-content",
            SIGNATURE,
        )?;

        let debug = format!("{event:?}");
        assert!(debug.contains("content_len"));
        assert!(!debug.contains("secret-content"));
        Ok(())
    }
}
