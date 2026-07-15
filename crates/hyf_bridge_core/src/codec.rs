use core::str;

use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};

use crate::{
    BridgeEndpointKind, BridgeEndpointRef, BridgeError, BridgeMessageRef, BridgePayloadKind,
    HYF_BRIDGE_AUTHOR_ID_MAX_LEN, HYF_BRIDGE_MESSAGE_MAX_LEN, HYF_BRIDGE_MESSAGE_VERSION_0,
    HYF_BRIDGE_PAYLOAD_MAX_LEN,
};

const ROOM_ID_LEN: usize = 16;
const MESSAGE_ID_LEN: usize = 32;
const U64_LEN: usize = 8;
const U16_LEN: usize = 2;
const FIXED_PREFIX_LEN: usize = 1 + ROOM_ID_LEN + MESSAGE_ID_LEN + 1 + 1 + 1;
const FIXED_SUFFIX_LEN: usize = U64_LEN + 1 + U16_LEN;

const AUTHOR_KIND_HYF_NODE: u8 = 0;
const AUTHOR_KIND_FOREIGN: u8 = 1;
const HYF_AUTHOR_NETWORK_TAG: u8 = 0;

pub fn decode_bridge_message(input: &[u8]) -> Result<BridgeMessageRef<'_>, BridgeError> {
    if input.len() > HYF_BRIDGE_MESSAGE_MAX_LEN {
        return Err(BridgeError::MessageTooLarge {
            actual: input.len(),
            maximum: HYF_BRIDGE_MESSAGE_MAX_LEN,
        });
    }

    let mut cursor = ReadCursor::new(input);
    let version = cursor.read_u8()?;
    if version != HYF_BRIDGE_MESSAGE_VERSION_0 {
        return Err(BridgeError::InvalidVersion { actual: version });
    }

    let room_id = CommunityId(cursor.read_array::<ROOM_ID_LEN>()?);
    if room_id.0 == [0; ROOM_ID_LEN] {
        return Err(BridgeError::ZeroRoomId);
    }
    let message_id = MessageId(cursor.read_array::<MESSAGE_ID_LEN>()?);
    if message_id.0 == [0; MESSAGE_ID_LEN] {
        return Err(BridgeError::ZeroMessageId);
    }

    let author_kind_tag = cursor.read_u8()?;
    let author_network_tag = cursor.read_u8()?;
    let author_id_len = cursor.read_u8()? as usize;
    validate_author_id_len(author_id_len)?;
    let author_id = cursor.read_slice(author_id_len)?;
    let author_kind = decode_author_kind(author_kind_tag, author_network_tag)?;
    let created_at_ms = TimestampMs(cursor.read_u64()?);
    let payload_kind = decode_payload_kind(cursor.read_u8()?)?;
    let payload_len = cursor.read_u16()? as usize;
    if payload_len > HYF_BRIDGE_PAYLOAD_MAX_LEN {
        return Err(BridgeError::PayloadTooLarge {
            actual: payload_len,
            maximum: HYF_BRIDGE_PAYLOAD_MAX_LEN,
        });
    }
    let payload = cursor.read_slice(payload_len)?;
    validate_payload(payload_kind, payload)?;
    cursor.finish()?;

    Ok(BridgeMessageRef {
        version,
        room_id,
        message_id,
        author: BridgeEndpointRef {
            kind: author_kind,
            id: author_id,
        },
        created_at_ms,
        payload_kind,
        payload,
    })
}

pub fn bridge_message_encoded_len(message: BridgeMessageRef<'_>) -> Result<usize, BridgeError> {
    validate_bridge_message_ref(message)?;
    FIXED_PREFIX_LEN
        .checked_add(message.author.id.len())
        .and_then(|len| len.checked_add(FIXED_SUFFIX_LEN))
        .and_then(|len| len.checked_add(message.payload.len()))
        .filter(|len| *len <= HYF_BRIDGE_MESSAGE_MAX_LEN)
        .ok_or(BridgeError::MessageTooLarge {
            actual: message.payload.len(),
            maximum: HYF_BRIDGE_MESSAGE_MAX_LEN,
        })
}

pub fn encode_bridge_message(
    message: BridgeMessageRef<'_>,
    output: &mut [u8],
) -> Result<usize, BridgeError> {
    let required = bridge_message_encoded_len(message)?;
    if output.len() < required {
        return Err(BridgeError::OutputTooSmall {
            actual: output.len(),
            required,
        });
    }

    let mut cursor = WriteCursor::new(output);
    cursor.write_u8(message.version);
    cursor.write_array(&message.room_id.0);
    cursor.write_array(&message.message_id.0);
    match message.author.kind {
        BridgeEndpointKind::HyfNode => {
            cursor.write_u8(AUTHOR_KIND_HYF_NODE);
            cursor.write_u8(HYF_AUTHOR_NETWORK_TAG);
        }
        BridgeEndpointKind::Foreign(network) => {
            cursor.write_u8(AUTHOR_KIND_FOREIGN);
            cursor.write_u8(network.wire_tag());
        }
    }
    cursor.write_u8(message.author.id.len() as u8);
    cursor.write_array(message.author.id);
    cursor.write_u64(message.created_at_ms.0);
    cursor.write_u8(message.payload_kind.wire_tag());
    cursor.write_u16(message.payload.len() as u16);
    cursor.write_array(message.payload);

    Ok(required)
}

fn validate_bridge_message_ref(message: BridgeMessageRef<'_>) -> Result<(), BridgeError> {
    if message.version != HYF_BRIDGE_MESSAGE_VERSION_0 {
        return Err(BridgeError::InvalidVersion {
            actual: message.version,
        });
    }
    if message.room_id.0 == [0; ROOM_ID_LEN] {
        return Err(BridgeError::ZeroRoomId);
    }
    if message.message_id.0 == [0; MESSAGE_ID_LEN] {
        return Err(BridgeError::ZeroMessageId);
    }
    validate_author_id_len(message.author.id.len())?;
    if message.payload.len() > HYF_BRIDGE_PAYLOAD_MAX_LEN {
        return Err(BridgeError::PayloadTooLarge {
            actual: message.payload.len(),
            maximum: HYF_BRIDGE_PAYLOAD_MAX_LEN,
        });
    }
    validate_payload(message.payload_kind, message.payload)
}

fn validate_author_id_len(len: usize) -> Result<(), BridgeError> {
    if len == 0 || len > HYF_BRIDGE_AUTHOR_ID_MAX_LEN {
        return Err(BridgeError::InvalidAuthorIdLen { len });
    }
    Ok(())
}

fn validate_payload(kind: BridgePayloadKind, payload: &[u8]) -> Result<(), BridgeError> {
    if kind == BridgePayloadKind::TextUtf8 && str::from_utf8(payload).is_err() {
        return Err(BridgeError::InvalidTextUtf8);
    }
    Ok(())
}

fn decode_author_kind(
    author_kind_tag: u8,
    author_network_tag: u8,
) -> Result<BridgeEndpointKind, BridgeError> {
    match author_kind_tag {
        AUTHOR_KIND_HYF_NODE => {
            if author_network_tag != HYF_AUTHOR_NETWORK_TAG {
                return Err(BridgeError::UnexpectedHyfAuthorNetworkTag {
                    tag: author_network_tag,
                });
            }
            Ok(BridgeEndpointKind::HyfNode)
        }
        AUTHOR_KIND_FOREIGN => {
            let network = ForeignNetworkKind::from_wire_tag(author_network_tag).map_err(|_| {
                BridgeError::InvalidForeignNetworkTag {
                    tag: author_network_tag,
                }
            })?;
            Ok(BridgeEndpointKind::Foreign(network))
        }
        tag => Err(BridgeError::UnknownAuthorKind { tag }),
    }
}

fn decode_payload_kind(tag: u8) -> Result<BridgePayloadKind, BridgeError> {
    match tag {
        1 => Ok(BridgePayloadKind::TextUtf8),
        255 => Ok(BridgePayloadKind::OpaqueBytes),
        _ => Err(BridgeError::UnknownPayloadKind { tag }),
    }
}

struct ReadCursor<'a> {
    input: &'a [u8],
    index: usize,
}

impl<'a> ReadCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, index: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, BridgeError> {
        Ok(self.read_slice(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, BridgeError> {
        Ok(u16::from_be_bytes(self.read_array::<U16_LEN>()?))
    }

    fn read_u64(&mut self) -> Result<u64, BridgeError> {
        Ok(u64::from_be_bytes(self.read_array::<U64_LEN>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], BridgeError> {
        let bytes = self.read_slice(N)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], BridgeError> {
        let end = self
            .index
            .checked_add(len)
            .ok_or(BridgeError::InputTooShort {
                actual: self.input.len(),
                minimum: self.index,
            })?;
        if end > self.input.len() {
            return Err(BridgeError::InputTooShort {
                actual: self.input.len(),
                minimum: end,
            });
        }
        let slice = &self.input[self.index..end];
        self.index = end;
        Ok(slice)
    }

    fn finish(&self) -> Result<(), BridgeError> {
        if self.index != self.input.len() {
            return Err(BridgeError::TrailingBytes {
                actual: self.input.len(),
                expected: self.index,
            });
        }
        Ok(())
    }
}

struct WriteCursor<'a> {
    output: &'a mut [u8],
    index: usize,
}

impl<'a> WriteCursor<'a> {
    const fn new(output: &'a mut [u8]) -> Self {
        Self { output, index: 0 }
    }

    fn write_u8(&mut self, value: u8) {
        self.output[self.index] = value;
        self.index += 1;
    }

    fn write_u16(&mut self, value: u16) {
        self.write_array(&value.to_be_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write_array(&value.to_be_bytes());
    }

    fn write_array(&mut self, value: &[u8]) {
        let end = self.index + value.len();
        self.output[self.index..end].copy_from_slice(value);
        self.index = end;
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};

    use super::{decode_bridge_message, encode_bridge_message};
    use crate::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeError, BridgeMessageRef, BridgePayloadKind,
        HYF_BRIDGE_MESSAGE_MAX_LEN, HYF_BRIDGE_PAYLOAD_MAX_LEN, bridge_message_encoded_len,
    };

    #[test]
    fn encode_decode_roundtrips_text_and_opaque_messages() -> Result<(), BridgeError> {
        let message = sample_message(BridgePayloadKind::TextUtf8, b"hello");
        let mut encoded = [0; 128];
        let len = encode_bridge_message(message, &mut encoded)?;
        let decoded = decode_bridge_message(&encoded[..len])?;

        assert_eq!(decoded, message);
        assert_eq!(decoded.author.id.as_ptr(), encoded[52..].as_ptr());

        let opaque = sample_message(BridgePayloadKind::OpaqueBytes, &[0xff, 0, 1]);
        let len = encode_bridge_message(opaque, &mut encoded)?;
        assert_eq!(decode_bridge_message(&encoded[..len])?, opaque);
        Ok(())
    }

    #[test]
    fn encoded_len_reports_short_output_and_maximums() {
        let message = sample_message(BridgePayloadKind::TextUtf8, b"hello");
        let mut short = [0; 10];

        assert_eq!(
            encode_bridge_message(message, &mut short),
            Err(BridgeError::OutputTooSmall {
                actual: 10,
                required: bridge_message_encoded_len(message).unwrap_or(0),
            })
        );

        let payload = [b'a'; HYF_BRIDGE_PAYLOAD_MAX_LEN + 1];
        assert_eq!(
            bridge_message_encoded_len(sample_message(BridgePayloadKind::TextUtf8, &payload)),
            Err(BridgeError::PayloadTooLarge {
                actual: HYF_BRIDGE_PAYLOAD_MAX_LEN + 1,
                maximum: HYF_BRIDGE_PAYLOAD_MAX_LEN,
            })
        );
    }

    #[test]
    fn decode_rejects_invalid_fields_and_trailing_bytes() -> Result<(), BridgeError> {
        let mut encoded = [0; 128];
        let len = encode_bridge_message(
            sample_message(BridgePayloadKind::TextUtf8, b"hello"),
            &mut encoded,
        )?;

        encoded[0] = 9;
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::InvalidVersion { actual: 9 })
        );
        encoded[0] = 0;

        encoded[1..17].fill(0);
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::ZeroRoomId)
        );
        encoded[1..17].fill(1);

        encoded[17..49].fill(0);
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::ZeroMessageId)
        );
        encoded[17..49].fill(2);

        encoded[49] = 9;
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::UnknownAuthorKind { tag: 9 })
        );
        encoded[49] = 1;

        encoded[50] = 99;
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::InvalidForeignNetworkTag { tag: 99 })
        );
        encoded[50] = ForeignNetworkKind::BitChat.wire_tag();

        encoded[51] = 0;
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::InvalidAuthorIdLen { len: 0 })
        );
        encoded[51] = 8;

        let mut with_trailing = [0; 129];
        with_trailing[..len].copy_from_slice(&encoded[..len]);
        assert_eq!(
            decode_bridge_message(&with_trailing[..len + 1]),
            Err(BridgeError::TrailingBytes {
                actual: len + 1,
                expected: len,
            })
        );
        Ok(())
    }

    #[test]
    fn decode_rejects_invalid_payload_profile_and_size() -> Result<(), BridgeError> {
        let mut encoded = [0; HYF_BRIDGE_MESSAGE_MAX_LEN + 1];
        let len = encode_bridge_message(
            sample_message(BridgePayloadKind::TextUtf8, b"hello"),
            &mut encoded,
        )?;
        let payload_kind_index = 1 + 16 + 32 + 1 + 1 + 1 + 8 + 8;

        encoded[payload_kind_index] = 2;
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::UnknownPayloadKind { tag: 2 })
        );
        encoded[payload_kind_index] = BridgePayloadKind::TextUtf8.wire_tag();

        let payload_len_index = payload_kind_index + 1;
        encoded[payload_len_index..payload_len_index + 2].copy_from_slice(&1025u16.to_be_bytes());
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::PayloadTooLarge {
                actual: 1025,
                maximum: HYF_BRIDGE_PAYLOAD_MAX_LEN,
            })
        );
        encoded[payload_len_index..payload_len_index + 2].copy_from_slice(&5u16.to_be_bytes());

        let payload_index = payload_len_index + 2;
        encoded[payload_index] = 0xff;
        assert_eq!(
            decode_bridge_message(&encoded[..len]),
            Err(BridgeError::InvalidTextUtf8)
        );

        assert_eq!(
            decode_bridge_message(&[0; HYF_BRIDGE_MESSAGE_MAX_LEN + 1]),
            Err(BridgeError::MessageTooLarge {
                actual: HYF_BRIDGE_MESSAGE_MAX_LEN + 1,
                maximum: HYF_BRIDGE_MESSAGE_MAX_LEN,
            })
        );
        Ok(())
    }

    fn sample_message<'a>(
        payload_kind: BridgePayloadKind,
        payload: &'a [u8],
    ) -> BridgeMessageRef<'a> {
        BridgeMessageRef {
            version: 0,
            room_id: CommunityId([1; 16]),
            message_id: MessageId([2; 32]),
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::BitChat),
                id: &[3; 8],
            },
            created_at_ms: TimestampMs(1234),
            payload_kind,
            payload,
        }
    }
}
