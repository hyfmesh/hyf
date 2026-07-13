use core::str;

use crate::{NostrError, NostrUnsignedEvent};

pub fn write_canonical_event<'out>(
    event: &NostrUnsignedEvent<'_>,
    out: &'out mut [u8],
) -> Result<&'out str, NostrError> {
    let mut writer = CanonicalWriter::new(out);
    let mut pubkey_hex = [0; 64];
    let pubkey_hex = event.pubkey.write_hex(&mut pubkey_hex)?;

    writer.push_byte(b'[')?;
    writer.push_byte(b'0')?;
    writer.push_byte(b',')?;
    writer.write_json_string(pubkey_hex)?;
    writer.push_byte(b',')?;
    writer.write_u64(event.created_at)?;
    writer.push_byte(b',')?;
    writer.write_u64(u64::from(event.kind))?;
    writer.push_byte(b',')?;
    writer.write_tags(event.tags.as_slice())?;
    writer.push_byte(b',')?;
    writer.write_json_string(event.content)?;
    writer.push_byte(b']')?;
    writer.finish()
}

struct CanonicalWriter<'out> {
    out: &'out mut [u8],
    len: usize,
}

impl<'out> CanonicalWriter<'out> {
    fn new(out: &'out mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), NostrError> {
        if self.len == self.out.len() {
            return Err(NostrError::OutputTooSmall {
                needed: self.len + 1,
                available: self.out.len(),
            });
        }
        self.out[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    fn push_str(&mut self, value: &str) -> Result<(), NostrError> {
        let needed = self
            .len
            .checked_add(value.len())
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
        self.out[self.len..needed].copy_from_slice(value.as_bytes());
        self.len = needed;
        Ok(())
    }

    fn write_json_string(&mut self, value: &str) -> Result<(), NostrError> {
        self.push_byte(b'"')?;
        for character in value.chars() {
            match character {
                '"' => self.push_str(r#"\""#)?,
                '\\' => self.push_str(r#"\\"#)?,
                '\n' => self.push_str(r#"\n"#)?,
                '\r' => self.push_str(r#"\r"#)?,
                '\t' => self.push_str(r#"\t"#)?,
                '\u{08}' => self.push_str(r#"\b"#)?,
                '\u{0c}' => self.push_str(r#"\f"#)?,
                '\u{00}'..='\u{1f}' => self.write_control_escape(character)?,
                _ => {
                    let mut scratch = [0; 4];
                    self.push_str(character.encode_utf8(&mut scratch))?;
                }
            }
        }
        self.push_byte(b'"')
    }

    fn write_control_escape(&mut self, character: char) -> Result<(), NostrError> {
        let value = character as u8;
        let escape = [
            b'\\',
            b'u',
            b'0',
            b'0',
            hex_nibble(value >> 4),
            hex_nibble(value & 0x0f),
        ];
        self.push_str(str::from_utf8(&escape).map_err(|_| NostrError::Utf8)?)
    }

    fn write_tags(&mut self, tags: &[crate::NostrTagRef<'_>]) -> Result<(), NostrError> {
        self.push_byte(b'[')?;
        for (tag_index, tag) in tags.iter().enumerate() {
            if tag_index > 0 {
                self.push_byte(b',')?;
            }
            self.push_byte(b'[')?;
            for (value_index, value) in tag.values().iter().enumerate() {
                if value_index > 0 {
                    self.push_byte(b',')?;
                }
                self.write_json_string(value)?;
            }
            self.push_byte(b']')?;
        }
        self.push_byte(b']')
    }

    fn write_u64(&mut self, mut value: u64) -> Result<(), NostrError> {
        if value == 0 {
            return self.push_byte(b'0');
        }

        let mut scratch = [0; 20];
        let mut cursor = scratch.len();
        while value > 0 {
            cursor -= 1;
            scratch[cursor] = b'0' + (value % 10) as u8;
            value /= 10;
        }

        let value = str::from_utf8(&scratch[cursor..]).map_err(|_| NostrError::Utf8)?;
        self.push_str(value)
    }

    fn finish(self) -> Result<&'out str, NostrError> {
        str::from_utf8(&self.out[..self.len]).map_err(|_| NostrError::Utf8)
    }
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::write_canonical_event;
    use crate::{HYF_NOSTR_ENVELOPE_KIND, NostrError, NostrPublicKey, NostrTagRef, NostrTagsRef};

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
