use alloc::{string::String, vec::Vec};
use core::str;

use crate::{
    NostrError, NostrEvent, NostrEventId, NostrFilter, NostrPublicKey, NostrSignature,
    NostrTagsRef, validate_subscription_id,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrClientMessage<'a> {
    Event(NostrEvent<'a>),
    Req {
        subscription_id: &'a str,
        filters: &'a [NostrFilter<'a>],
    },
    Close {
        subscription_id: &'a str,
    },
    Auth(NostrEvent<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NostrOwnedClientMessage {
    Event(NostrOwnedEvent),
    Req {
        subscription_id: String,
        filters: Vec<NostrOwnedFilter>,
    },
    Close {
        subscription_id: String,
    },
    Auth(NostrOwnedEvent),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrOwnedEvent {
    pub id: NostrEventId,
    pub pubkey: NostrPublicKey,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: NostrSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrOwnedFilter {
    pub kinds: Vec<u16>,
    pub authors: Vec<NostrPublicKey>,
    pub p_tags: Vec<NostrPublicKey>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<usize>,
}

pub fn write_client_message<'out>(
    message: NostrClientMessage<'_>,
    out: &'out mut [u8],
) -> Result<&'out str, NostrError> {
    let mut writer = JsonWriter::new(out);
    writer.push_byte(b'[')?;
    match message {
        NostrClientMessage::Event(event) => {
            writer.write_json_string("EVENT")?;
            writer.push_byte(b',')?;
            writer.write_event(event)?;
        }
        NostrClientMessage::Req {
            subscription_id,
            filters,
        } => {
            validate_subscription_id(subscription_id)?;
            writer.write_json_string("REQ")?;
            writer.push_byte(b',')?;
            writer.write_json_string(subscription_id)?;
            for filter in filters {
                writer.push_byte(b',')?;
                writer.write_filter(*filter)?;
            }
        }
        NostrClientMessage::Close { subscription_id } => {
            validate_subscription_id(subscription_id)?;
            writer.write_json_string("CLOSE")?;
            writer.push_byte(b',')?;
            writer.write_json_string(subscription_id)?;
        }
        NostrClientMessage::Auth(event) => {
            writer.write_json_string("AUTH")?;
            writer.push_byte(b',')?;
            writer.write_event(event)?;
        }
    }
    writer.push_byte(b']')?;
    writer.finish()
}

pub fn decode_client_message(input: &str) -> Result<NostrOwnedClientMessage, NostrError> {
    let value = JsonParser::new(input).parse()?;
    let JsonValue::Array(items) = value else {
        return Err(NostrError::MalformedMessage);
    };
    let Some(JsonValue::String(kind)) = items.first() else {
        return Err(NostrError::MalformedMessage);
    };

    match kind.as_str() {
        "EVENT" => {
            if items.len() != 2 {
                return Err(NostrError::MalformedMessage);
            }
            Ok(NostrOwnedClientMessage::Event(parse_event(&items[1])?))
        }
        "REQ" => {
            if items.len() < 3 {
                return Err(NostrError::MalformedMessage);
            }
            let subscription_id = expect_string(&items[1])?.clone();
            validate_subscription_id(&subscription_id)?;
            let mut filters = Vec::with_capacity(items.len() - 2);
            for filter in &items[2..] {
                filters.push(parse_filter(filter)?);
            }
            Ok(NostrOwnedClientMessage::Req {
                subscription_id,
                filters,
            })
        }
        "CLOSE" => {
            if items.len() != 2 {
                return Err(NostrError::MalformedMessage);
            }
            let subscription_id = expect_string(&items[1])?.clone();
            validate_subscription_id(&subscription_id)?;
            Ok(NostrOwnedClientMessage::Close { subscription_id })
        }
        "AUTH" => {
            if items.len() != 2 {
                return Err(NostrError::MalformedMessage);
            }
            Ok(NostrOwnedClientMessage::Auth(parse_event(&items[1])?))
        }
        _ => Err(NostrError::UnsupportedMessage),
    }
}

struct JsonWriter<'out> {
    out: &'out mut [u8],
    len: usize,
}

impl<'out> JsonWriter<'out> {
    fn new(out: &'out mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), NostrError> {
        self.write_bytes(&[byte])
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), NostrError> {
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

    fn write_str(&mut self, value: &str) -> Result<(), NostrError> {
        self.write_bytes(value.as_bytes())
    }

    fn write_json_string(&mut self, value: &str) -> Result<(), NostrError> {
        self.push_byte(b'"')?;
        for character in value.chars() {
            match character {
                '"' => self.write_str(r#"\""#)?,
                '\\' => self.write_str(r#"\\"#)?,
                '\n' => self.write_str(r#"\n"#)?,
                '\r' => self.write_str(r#"\r"#)?,
                '\t' => self.write_str(r#"\t"#)?,
                '\u{08}' => self.write_str(r#"\b"#)?,
                '\u{0c}' => self.write_str(r#"\f"#)?,
                '\u{00}'..='\u{1f}' => self.write_control_escape(character)?,
                _ => {
                    let mut scratch = [0; 4];
                    self.write_str(character.encode_utf8(&mut scratch))?;
                }
            }
        }
        self.push_byte(b'"')
    }

    fn write_control_escape(&mut self, character: char) -> Result<(), NostrError> {
        let value = character as u8;
        self.write_bytes(&[
            b'\\',
            b'u',
            b'0',
            b'0',
            hex_nibble(value >> 4),
            hex_nibble(value & 0x0f),
        ])
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
        self.write_bytes(&scratch[cursor..])
    }

    fn write_event(&mut self, event: NostrEvent<'_>) -> Result<(), NostrError> {
        let mut id = [0; 64];
        let mut pubkey = [0; 64];
        let mut signature = [0; 128];
        let id = event.id.write_hex(&mut id)?;
        let pubkey = event.pubkey.write_hex(&mut pubkey)?;
        let signature = event.sig.write_hex(&mut signature)?;

        self.push_byte(b'{')?;
        self.write_json_string("id")?;
        self.push_byte(b':')?;
        self.write_json_string(id)?;
        self.push_byte(b',')?;
        self.write_json_string("pubkey")?;
        self.push_byte(b':')?;
        self.write_json_string(pubkey)?;
        self.push_byte(b',')?;
        self.write_json_string("created_at")?;
        self.push_byte(b':')?;
        self.write_u64(event.created_at)?;
        self.push_byte(b',')?;
        self.write_json_string("kind")?;
        self.push_byte(b':')?;
        self.write_u64(u64::from(event.kind))?;
        self.push_byte(b',')?;
        self.write_json_string("tags")?;
        self.push_byte(b':')?;
        self.write_tags(event.tags)?;
        self.push_byte(b',')?;
        self.write_json_string("content")?;
        self.push_byte(b':')?;
        self.write_json_string(event.content)?;
        self.push_byte(b',')?;
        self.write_json_string("sig")?;
        self.push_byte(b':')?;
        self.write_json_string(signature)?;
        self.push_byte(b'}')
    }

    fn write_tags(&mut self, tags: NostrTagsRef<'_>) -> Result<(), NostrError> {
        self.push_byte(b'[')?;
        for (tag_index, tag) in tags.as_slice().iter().enumerate() {
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

    fn write_filter(&mut self, filter: NostrFilter<'_>) -> Result<(), NostrError> {
        let mut wrote = false;
        self.push_byte(b'{')?;
        self.write_number_array_field("kinds", filter.kinds, &mut wrote)?;
        self.write_key_array_field("authors", filter.authors, &mut wrote)?;
        self.write_key_array_field("#p", filter.p_tags, &mut wrote)?;
        self.write_optional_u64_field("since", filter.since, &mut wrote)?;
        self.write_optional_u64_field("until", filter.until, &mut wrote)?;
        if let Some(limit) = filter.limit {
            self.write_field_separator(&mut wrote)?;
            self.write_json_string("limit")?;
            self.push_byte(b':')?;
            self.write_u64(limit as u64)?;
        }
        self.push_byte(b'}')
    }

    fn write_field_separator(&mut self, wrote: &mut bool) -> Result<(), NostrError> {
        if *wrote {
            self.push_byte(b',')?;
        }
        *wrote = true;
        Ok(())
    }

    fn write_number_array_field(
        &mut self,
        name: &str,
        values: &[u16],
        wrote: &mut bool,
    ) -> Result<(), NostrError> {
        if values.is_empty() {
            return Ok(());
        }
        self.write_field_separator(wrote)?;
        self.write_json_string(name)?;
        self.push_byte(b':')?;
        self.push_byte(b'[')?;
        for (index, value) in values.iter().copied().enumerate() {
            if index > 0 {
                self.push_byte(b',')?;
            }
            self.write_u64(u64::from(value))?;
        }
        self.push_byte(b']')
    }

    fn write_key_array_field(
        &mut self,
        name: &str,
        values: &[NostrPublicKey],
        wrote: &mut bool,
    ) -> Result<(), NostrError> {
        if values.is_empty() {
            return Ok(());
        }
        self.write_field_separator(wrote)?;
        self.write_json_string(name)?;
        self.push_byte(b':')?;
        self.push_byte(b'[')?;
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.push_byte(b',')?;
            }
            let mut hex = [0; 64];
            self.write_json_string(value.write_hex(&mut hex)?)?;
        }
        self.push_byte(b']')
    }

    fn write_optional_u64_field(
        &mut self,
        name: &str,
        value: Option<u64>,
        wrote: &mut bool,
    ) -> Result<(), NostrError> {
        let Some(value) = value else {
            return Ok(());
        };
        self.write_field_separator(wrote)?;
        self.write_json_string(name)?;
        self.push_byte(b':')?;
        self.write_u64(value)
    }

    fn finish(self) -> Result<&'out str, NostrError> {
        str::from_utf8(&self.out[..self.len]).map_err(|_| NostrError::Utf8)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

struct JsonParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            position: 0,
        }
    }

    fn parse(mut self) -> Result<JsonValue, NostrError> {
        let value = self.parse_value()?;
        self.skip_ws();
        if self.position != self.input.len() {
            return Err(NostrError::MalformedMessage);
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<JsonValue, NostrError> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'0'..=b'9') => self.parse_number(),
            _ => Err(NostrError::MalformedMessage),
        }
    }

    fn parse_literal(&mut self, literal: &[u8], value: JsonValue) -> Result<JsonValue, NostrError> {
        if self.input.get(self.position..self.position + literal.len()) == Some(literal) {
            self.position += literal.len();
            Ok(value)
        } else {
            Err(NostrError::MalformedMessage)
        }
    }

    fn parse_string(&mut self) -> Result<String, NostrError> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(NostrError::MalformedMessage);
            };
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.position += 1;
                    self.parse_escape(&mut out)?;
                }
                0x00..=0x1f => return Err(NostrError::MalformedMessage),
                0x20..=0x7f => {
                    out.push(byte as char);
                    self.position += 1;
                }
                _ => {
                    let remaining = str::from_utf8(&self.input[self.position..])
                        .map_err(|_| NostrError::Utf8)?;
                    let Some(character) = remaining.chars().next() else {
                        return Err(NostrError::MalformedMessage);
                    };
                    out.push(character);
                    self.position += character.len_utf8();
                }
            }
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), NostrError> {
        let Some(byte) = self.next_byte() else {
            return Err(NostrError::MalformedMessage);
        };
        match byte {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{08}'),
            b'f' => out.push('\u{0c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => out.push(self.parse_unicode_escape()?),
            _ => return Err(NostrError::MalformedMessage),
        }
        Ok(())
    }

    fn parse_unicode_escape(&mut self) -> Result<char, NostrError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let Some(byte) = self.next_byte() else {
                return Err(NostrError::MalformedMessage);
            };
            value = (value << 4) | u32::from(hex_value(byte)?);
        }
        char::from_u32(value).ok_or(NostrError::MalformedMessage)
    }

    fn parse_array(&mut self) -> Result<JsonValue, NostrError> {
        self.expect_byte(b'[')?;
        let mut values = Vec::new();
        self.skip_ws();
        if self.consume_byte(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_ws();
            if self.consume_byte(b']') {
                return Ok(JsonValue::Array(values));
            }
            self.expect_byte(b',')?;
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, NostrError> {
        self.expect_byte(b'{')?;
        let mut fields = Vec::new();
        self.skip_ws();
        if self.consume_byte(b'}') {
            return Ok(JsonValue::Object(fields));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_byte(b':')?;
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_ws();
            if self.consume_byte(b'}') {
                return Ok(JsonValue::Object(fields));
            }
            self.expect_byte(b',')?;
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, NostrError> {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        let value = str::from_utf8(&self.input[start..self.position])
            .map_err(|_| NostrError::Utf8)?
            .parse::<u64>()
            .map_err(|_| NostrError::MalformedMessage)?;
        Ok(JsonValue::Number(value))
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn consume_byte(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect_byte(&mut self, byte: u8) -> Result<(), NostrError> {
        if self.consume_byte(byte) {
            Ok(())
        } else {
            Err(NostrError::MalformedMessage)
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }
}

fn parse_event(value: &JsonValue) -> Result<NostrOwnedEvent, NostrError> {
    let fields = expect_object(value)?;
    let id = NostrEventId::from_hex(expect_string(required_field(fields, "id")?)?)?;
    let pubkey = NostrPublicKey::from_hex(expect_string(required_field(fields, "pubkey")?)?)?;
    let created_at = expect_number(required_field(fields, "created_at")?)?;
    let kind = number_to_u16(expect_number(required_field(fields, "kind")?)?)?;
    let tags = parse_tags(required_field(fields, "tags")?)?;
    let content = expect_string(required_field(fields, "content")?)?.clone();
    let sig = NostrSignature::from_hex(expect_string(required_field(fields, "sig")?)?)?;
    Ok(NostrOwnedEvent {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig,
    })
}

fn parse_filter(value: &JsonValue) -> Result<NostrOwnedFilter, NostrError> {
    let fields = expect_object(value)?;
    Ok(NostrOwnedFilter {
        kinds: optional_number_array(fields, "kinds")?,
        authors: optional_key_array(fields, "authors")?,
        p_tags: optional_key_array(fields, "#p")?,
        since: optional_number(fields, "since")?,
        until: optional_number(fields, "until")?,
        limit: optional_usize(fields, "limit")?,
    })
}

fn parse_tags(value: &JsonValue) -> Result<Vec<Vec<String>>, NostrError> {
    let JsonValue::Array(tags) = value else {
        return Err(NostrError::MalformedMessage);
    };
    let mut parsed = Vec::with_capacity(tags.len());
    for tag in tags {
        let JsonValue::Array(values) = tag else {
            return Err(NostrError::MalformedMessage);
        };
        if values.is_empty() {
            return Err(NostrError::TagEmpty);
        }
        let mut parsed_values = Vec::with_capacity(values.len());
        for value in values {
            parsed_values.push(expect_string(value)?.clone());
        }
        parsed.push(parsed_values);
    }
    Ok(parsed)
}

fn optional_number_array(
    fields: &[(String, JsonValue)],
    name: &str,
) -> Result<Vec<u16>, NostrError> {
    let Some(value) = optional_field(fields, name) else {
        return Ok(Vec::new());
    };
    let JsonValue::Array(values) = value else {
        return Err(NostrError::MalformedMessage);
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        out.push(number_to_u16(expect_number(value)?)?);
    }
    Ok(out)
}

fn optional_key_array(
    fields: &[(String, JsonValue)],
    name: &str,
) -> Result<Vec<NostrPublicKey>, NostrError> {
    let Some(value) = optional_field(fields, name) else {
        return Ok(Vec::new());
    };
    let JsonValue::Array(values) = value else {
        return Err(NostrError::MalformedMessage);
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        out.push(NostrPublicKey::from_hex(expect_string(value)?)?);
    }
    Ok(out)
}

fn optional_number(fields: &[(String, JsonValue)], name: &str) -> Result<Option<u64>, NostrError> {
    optional_field(fields, name).map(expect_number).transpose()
}

fn optional_usize(fields: &[(String, JsonValue)], name: &str) -> Result<Option<usize>, NostrError> {
    optional_field(fields, name)
        .map(|value| {
            let number = expect_number(value)?;
            usize::try_from(number).map_err(|_| NostrError::MalformedMessage)
        })
        .transpose()
}

fn expect_object(value: &JsonValue) -> Result<&[(String, JsonValue)], NostrError> {
    let JsonValue::Object(fields) = value else {
        return Err(NostrError::MalformedMessage);
    };
    Ok(fields)
}

fn expect_string(value: &JsonValue) -> Result<&String, NostrError> {
    let JsonValue::String(value) = value else {
        return Err(NostrError::MalformedMessage);
    };
    Ok(value)
}

fn expect_number(value: &JsonValue) -> Result<u64, NostrError> {
    let JsonValue::Number(value) = value else {
        return Err(NostrError::MalformedMessage);
    };
    Ok(*value)
}

fn required_field<'a>(
    fields: &'a [(String, JsonValue)],
    name: &str,
) -> Result<&'a JsonValue, NostrError> {
    optional_field(fields, name).ok_or(NostrError::MalformedMessage)
}

fn optional_field<'a>(fields: &'a [(String, JsonValue)], name: &str) -> Option<&'a JsonValue> {
    fields
        .iter()
        .find(|(field_name, _)| field_name == name)
        .map(|(_, value)| value)
}

fn number_to_u16(value: u64) -> Result<u16, NostrError> {
    u16::try_from(value).map_err(|_| NostrError::MalformedMessage)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

fn hex_value(value: u8) -> Result<u8, NostrError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(NostrError::MalformedMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NostrClientMessage, NostrOwnedClientMessage, decode_client_message, write_client_message,
    };
    use crate::{
        HYF_NOSTR_ENVELOPE_KIND, NostrError, NostrEvent, NostrEventId, NostrFilter, NostrPublicKey,
        NostrSignature, NostrTagRef, NostrTagsRef,
    };

    const EVENT_ID: NostrEventId = NostrEventId::from_bytes([0x22; 32]);
    const PUBLIC_KEY: NostrPublicKey = NostrPublicKey::from_bytes([0x33; 32]);
    const RECIPIENT: NostrPublicKey = NostrPublicKey::from_bytes([0x44; 32]);
    const SIGNATURE: NostrSignature = NostrSignature::from_bytes([0x55; 64]);

    #[test]
    fn event_client_message_roundtrips() -> Result<(), NostrError> {
        let tag_values = ["p", "relay-target"];
        let tag = NostrTagRef::new(&tag_values)?;
        let tags = [tag];
        let event = fixture_event(NostrTagsRef::new(&tags), "abcd")?;
        let mut out = [0; 768];

        let json = write_client_message(NostrClientMessage::Event(event), &mut out)?;
        let decoded = decode_client_message(json)?;

        let NostrOwnedClientMessage::Event(decoded) = decoded else {
            return Err(NostrError::MalformedMessage);
        };
        assert_eq!(decoded.id, EVENT_ID);
        assert_eq!(decoded.pubkey, PUBLIC_KEY);
        assert_eq!(decoded.kind, HYF_NOSTR_ENVELOPE_KIND);
        assert_eq!(decoded.tags[0], ["p", "relay-target"]);
        assert_eq!(decoded.content, "abcd");
        assert_eq!(decoded.sig, SIGNATURE);
        Ok(())
    }

    #[test]
    fn req_close_and_auth_client_messages_roundtrip() -> Result<(), NostrError> {
        let filter = NostrFilter {
            kinds: &[HYF_NOSTR_ENVELOPE_KIND],
            authors: &[PUBLIC_KEY],
            p_tags: &[RECIPIENT],
            since: Some(10),
            until: Some(20),
            limit: Some(5),
        };
        let mut req_out = [0; 512];
        let req_json = write_client_message(
            NostrClientMessage::Req {
                subscription_id: "sub-1",
                filters: &[filter],
            },
            &mut req_out,
        )?;
        let NostrOwnedClientMessage::Req {
            subscription_id,
            filters,
        } = decode_client_message(req_json)?
        else {
            return Err(NostrError::MalformedMessage);
        };
        assert_eq!(subscription_id, "sub-1");
        assert_eq!(filters[0].kinds, [HYF_NOSTR_ENVELOPE_KIND]);
        assert_eq!(filters[0].authors, [PUBLIC_KEY]);
        assert_eq!(filters[0].p_tags, [RECIPIENT]);
        assert_eq!(filters[0].since, Some(10));
        assert_eq!(filters[0].until, Some(20));
        assert_eq!(filters[0].limit, Some(5));

        let mut close_out = [0; 64];
        let close_json = write_client_message(
            NostrClientMessage::Close {
                subscription_id: "sub-1",
            },
            &mut close_out,
        )?;
        assert_eq!(
            decode_client_message(close_json)?,
            NostrOwnedClientMessage::Close {
                subscription_id: String::from("sub-1"),
            }
        );

        let event = fixture_event(NostrTagsRef::new(&[]), "auth")?;
        let mut auth_out = [0; 640];
        let auth_json = write_client_message(NostrClientMessage::Auth(event), &mut auth_out)?;
        assert!(matches!(
            decode_client_message(auth_json)?,
            NostrOwnedClientMessage::Auth(_)
        ));
        Ok(())
    }

    #[test]
    fn client_message_codec_rejects_malformed_arrays_and_subscriptions() {
        assert_eq!(
            decode_client_message("{}"),
            Err(NostrError::MalformedMessage)
        );
        assert_eq!(
            decode_client_message("[]"),
            Err(NostrError::MalformedMessage)
        );
        assert_eq!(
            decode_client_message(r#"["EVENT"]"#),
            Err(NostrError::MalformedMessage)
        );
        assert_eq!(
            decode_client_message(r#"["NOPE"]"#),
            Err(NostrError::UnsupportedMessage)
        );
        assert_eq!(
            decode_client_message(r#"["CLOSE",""]"#),
            Err(NostrError::InvalidSubscriptionId)
        );
    }

    #[test]
    fn client_message_writer_rejects_short_output_and_invalid_subscription() {
        assert!(matches!(
            write_client_message(
                NostrClientMessage::Close {
                    subscription_id: "sub-1",
                },
                &mut [0; 4],
            ),
            Err(NostrError::OutputTooSmall {
                needed: _,
                available: 4,
            })
        ));
        assert_eq!(
            write_client_message(
                NostrClientMessage::Close {
                    subscription_id: "",
                },
                &mut [0; 64],
            ),
            Err(NostrError::InvalidSubscriptionId)
        );
    }

    fn fixture_event<'a>(
        tags: NostrTagsRef<'a>,
        content: &'a str,
    ) -> Result<NostrEvent<'a>, NostrError> {
        NostrEvent::new(
            EVENT_ID,
            PUBLIC_KEY,
            1720000000,
            HYF_NOSTR_ENVELOPE_KIND,
            tags,
            content,
            SIGNATURE,
        )
    }
}
