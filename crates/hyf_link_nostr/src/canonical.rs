use core::str;

use sha2::{Digest, Sha256};

use crate::{NostrError, NostrEventId, NostrUnsignedEvent};

pub fn event_id(event: &NostrUnsignedEvent<'_>) -> Result<NostrEventId, NostrError> {
    let mut sink = HashSink::new();
    write_canonical_to(event, &mut sink)?;
    Ok(NostrEventId::from_bytes(sink.finish()))
}

pub fn write_canonical_event<'out>(
    event: &NostrUnsignedEvent<'_>,
    out: &'out mut [u8],
) -> Result<&'out str, NostrError> {
    let mut sink = BufferSink::new(out);
    write_canonical_to(event, &mut sink)?;
    sink.finish()
}

fn write_canonical_to<S: CanonicalSink>(
    event: &NostrUnsignedEvent<'_>,
    sink: &mut S,
) -> Result<(), NostrError> {
    let mut pubkey_hex = [0; 64];
    let pubkey_hex = event.pubkey.write_hex(&mut pubkey_hex)?;

    push_byte(sink, b'[')?;
    push_byte(sink, b'0')?;
    push_byte(sink, b',')?;
    write_json_string(sink, pubkey_hex)?;
    push_byte(sink, b',')?;
    write_u64(sink, event.created_at)?;
    push_byte(sink, b',')?;
    write_u64(sink, u64::from(event.kind))?;
    push_byte(sink, b',')?;
    write_tags(sink, event.tags.as_slice())?;
    push_byte(sink, b',')?;
    write_json_string(sink, event.content)?;
    push_byte(sink, b']')
}

trait CanonicalSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), NostrError>;
}

struct BufferSink<'out> {
    out: &'out mut [u8],
    len: usize,
}

impl<'out> BufferSink<'out> {
    fn new(out: &'out mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn finish(self) -> Result<&'out str, NostrError> {
        str::from_utf8(&self.out[..self.len]).map_err(|_| NostrError::Utf8)
    }
}

impl CanonicalSink for BufferSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), NostrError> {
        let needed = self
            .len
            .checked_add(bytes.len())
            .ok_or(NostrError::OutputTooSmall {
                needed: usize::MAX,
                available: self.out.len(),
            })?;
        if needed > self.out.len() {
            return Err(NostrError::OutputTooSmall {
                needed,
                available: self.out.len(),
            });
        }
        self.out[self.len..needed].copy_from_slice(bytes);
        self.len = needed;
        Ok(())
    }
}

struct HashSink {
    hasher: Sha256,
}

impl HashSink {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> [u8; 32] {
        let digest = self.hasher.finalize();
        let mut event_id = [0; 32];
        event_id.copy_from_slice(&digest);
        event_id
    }
}

impl CanonicalSink for HashSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), NostrError> {
        self.hasher.update(bytes);
        Ok(())
    }
}

fn push_byte<S: CanonicalSink>(sink: &mut S, byte: u8) -> Result<(), NostrError> {
    sink.write(&[byte])
}

fn push_str<S: CanonicalSink>(sink: &mut S, value: &str) -> Result<(), NostrError> {
    sink.write(value.as_bytes())
}

fn write_json_string<S: CanonicalSink>(sink: &mut S, value: &str) -> Result<(), NostrError> {
    push_byte(sink, b'"')?;
    for character in value.chars() {
        match character {
            '"' => push_str(sink, r#"\""#)?,
            '\\' => push_str(sink, r#"\\"#)?,
            '\n' => push_str(sink, r#"\n"#)?,
            '\r' => push_str(sink, r#"\r"#)?,
            '\t' => push_str(sink, r#"\t"#)?,
            '\u{08}' => push_str(sink, r#"\b"#)?,
            '\u{0c}' => push_str(sink, r#"\f"#)?,
            '\u{00}'..='\u{1f}' => write_control_escape(sink, character)?,
            _ => {
                let mut scratch = [0; 4];
                push_str(sink, character.encode_utf8(&mut scratch))?;
            }
        }
    }
    push_byte(sink, b'"')
}

fn write_control_escape<S: CanonicalSink>(sink: &mut S, character: char) -> Result<(), NostrError> {
    let value = character as u8;
    sink.write(&[
        b'\\',
        b'u',
        b'0',
        b'0',
        hex_nibble(value >> 4),
        hex_nibble(value & 0x0f),
    ])
}

fn write_tags<S: CanonicalSink>(
    sink: &mut S,
    tags: &[crate::NostrTagRef<'_>],
) -> Result<(), NostrError> {
    push_byte(sink, b'[')?;
    for (tag_index, tag) in tags.iter().enumerate() {
        if tag_index > 0 {
            push_byte(sink, b',')?;
        }
        push_byte(sink, b'[')?;
        for (value_index, value) in tag.values().iter().enumerate() {
            if value_index > 0 {
                push_byte(sink, b',')?;
            }
            write_json_string(sink, value)?;
        }
        push_byte(sink, b']')?;
    }
    push_byte(sink, b']')
}

fn write_u64<S: CanonicalSink>(sink: &mut S, mut value: u64) -> Result<(), NostrError> {
    if value == 0 {
        return push_byte(sink, b'0');
    }

    let mut scratch = [0; 20];
    let mut cursor = scratch.len();
    while value > 0 {
        cursor -= 1;
        scratch[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    sink.write(&scratch[cursor..])
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::{event_id, write_canonical_event};
    use crate::{
        HYF_NOSTR_ENVELOPE_KIND, NostrError, NostrEventId, NostrPublicKey, NostrTagRef,
        NostrTagsRef,
    };

    const PUBLIC_KEY: NostrPublicKey = NostrPublicKey::from_bytes([0x11; 32]);
    const PUBLIC_KEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn canonical_event_serializes_basic_vector() -> Result<(), NostrError> {
        let event = event(NostrTagsRef::new(&[]), "abcd", 1720000000);
        let mut out = [0; 160];

        let serialized = write_canonical_event(&event, &mut out)?;

        assert_eq!(
            serialized,
            concat!(
                r#"[0,"#,
                r#""1111111111111111111111111111111111111111111111111111111111111111","#,
                r#"1720000000,9775,[],"abcd"]"#
            )
        );
        Ok(())
    }

    #[test]
    fn event_id_hashes_known_vector() -> Result<(), NostrError> {
        let event = event(NostrTagsRef::new(&[]), "abcd", 1720000000);

        assert_eq!(
            event_id(&event)?,
            NostrEventId::from_hex(
                "3422f301716b9b2af14b2f3dc3e258eddba9a312ef2fe5ecbe148ac1ffe5580a"
            )?
        );
        Ok(())
    }

    #[test]
    fn event_id_changes_when_canonical_fields_change() -> Result<(), NostrError> {
        let base = event(NostrTagsRef::new(&[]), "abcd", 1720000000);
        let base_id = event_id(&base)?;

        let changed_content = event(NostrTagsRef::new(&[]), "abce", 1720000000);
        assert_ne!(event_id(&changed_content)?, base_id);

        let changed_kind = crate::NostrUnsignedEvent { kind: 1, ..base };
        assert_ne!(event_id(&changed_kind)?, base_id);

        let tag_values = [
            "p",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        let tag = NostrTagRef::new(&tag_values)?;
        let tags = [tag];
        let changed_tags = crate::NostrUnsignedEvent {
            tags: NostrTagsRef::new(&tags),
            ..base
        };
        assert_ne!(event_id(&changed_tags)?, base_id);

        let changed_pubkey = crate::NostrUnsignedEvent {
            pubkey: NostrPublicKey::from_bytes([0x22; 32]),
            ..base
        };
        assert_ne!(event_id(&changed_pubkey)?, base_id);
        Ok(())
    }

    #[test]
    fn canonical_event_preserves_tag_order_and_values() -> Result<(), NostrError> {
        let tag_public_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let p_values = ["p", tag_public_key, "wss://relay.example"];
        let alt_values = ["alt", "HYF envelope"];
        let p_tag = NostrTagRef::new(&p_values)?;
        let alt_tag = NostrTagRef::new(&alt_values)?;
        let tags = [p_tag, alt_tag];
        let tags = NostrTagsRef::new(&tags);
        let event = event(tags, "00", 1720000001);
        let mut out = [0; 260];

        let serialized = write_canonical_event(&event, &mut out)?;

        assert_eq!(
            serialized,
            concat!(
                r#"[0,"#,
                r#""1111111111111111111111111111111111111111111111111111111111111111","#,
                r#"1720000001,9775,[["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example"],["alt","HYF envelope"]],"00"]"#
            )
        );
        Ok(())
    }

    #[test]
    fn canonical_event_escapes_json_strings() -> Result<(), NostrError> {
        let content = "quote: \" slash: \\ newline: \n carriage: \r tab: \t backspace: \u{08} form: \u{0c} null: \u{00} unicode: \u{20ac}";
        let event = event(NostrTagsRef::new(&[]), content, 1);
        let mut out = [0; 260];

        let serialized = write_canonical_event(&event, &mut out)?;

        assert_eq!(
            serialized,
            concat!(
                r#"[0,"#,
                r#""1111111111111111111111111111111111111111111111111111111111111111","#,
                r#"1,9775,[],"quote: \" slash: \\ newline: \n carriage: \r tab: \t backspace: \b form: \f null: \u0000 unicode: "#,
                "\u{20ac}",
                r#""]"#
            )
        );
        Ok(())
    }

    #[test]
    fn canonical_event_reports_short_output() {
        let event = event(NostrTagsRef::new(&[]), "abcd", 1720000000);
        let mut out = [0; 8];

        assert!(matches!(
            write_canonical_event(&event, &mut out),
            Err(NostrError::OutputTooSmall {
                needed: _,
                available: 8
            })
        ));
    }

    fn event<'a>(
        tags: NostrTagsRef<'a>,
        content: &'a str,
        created_at: u64,
    ) -> crate::NostrUnsignedEvent<'a> {
        crate::NostrUnsignedEvent {
            pubkey: PUBLIC_KEY,
            created_at,
            kind: HYF_NOSTR_ENVELOPE_KIND,
            tags,
            content,
        }
    }

    #[test]
    fn public_key_hex_constant_matches_fixture() -> Result<(), NostrError> {
        let mut out = [0; 64];
        assert_eq!(PUBLIC_KEY.write_hex(&mut out)?, PUBLIC_KEY_HEX);
        Ok(())
    }
}
