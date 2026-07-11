use core::fmt;

use hyf_core::{
    CommunityId, ForeignEndpointId, ForeignNetworkKind, MessageId, NodeId, TimestampMs,
};

use crate::{HYF_WIRE_VERSION_0, HyfDestination, HyfWireError, PayloadKind};

pub const HYF_ENVELOPE_MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

const MESSAGE_ID_LEN: usize = 32;
const NODE_ID_LEN: usize = 32;
const COMMUNITY_ID_LEN: usize = 16;
const U64_LEN: usize = 8;
const U16_LEN: usize = 2;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HyfEnvelopeRef<'a> {
    pub version: u8,
    pub message_id: MessageId,
    pub source: NodeId,
    pub destination: HyfDestination,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: TimestampMs,
    pub hop_limit: u8,
    pub payload_kind: PayloadKind,
    pub payload: &'a [u8],
}

impl fmt::Debug for HyfEnvelopeRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HyfEnvelopeRef")
            .field("version", &self.version)
            .field("message_id", &self.message_id)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("hop_limit", &self.hop_limit)
            .field("payload_kind", &self.payload_kind)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

pub fn validate_envelope(envelope: HyfEnvelopeRef<'_>) -> Result<(), HyfWireError> {
    if envelope.version != HYF_WIRE_VERSION_0 {
        return Err(HyfWireError::InvalidVersion {
            actual: envelope.version,
        });
    }
    if envelope.expires_at_ms.0 <= envelope.created_at_ms.0 {
        return Err(HyfWireError::InvalidExpiry);
    }
    if envelope.payload.len() > HYF_ENVELOPE_MAX_PAYLOAD_LEN {
        return Err(HyfWireError::EnvelopeTooLarge {
            actual: envelope.payload.len(),
            maximum: HYF_ENVELOPE_MAX_PAYLOAD_LEN,
        });
    }
    Ok(())
}

pub fn envelope_encoded_len(envelope: HyfEnvelopeRef<'_>) -> Result<usize, HyfWireError> {
    validate_envelope(envelope)?;
    fixed_encoded_len(envelope.destination)?
        .checked_add(envelope.payload.len())
        .ok_or(HyfWireError::EnvelopeTooLarge {
            actual: envelope.payload.len(),
            maximum: HYF_ENVELOPE_MAX_PAYLOAD_LEN,
        })
}

pub fn encode_envelope(
    envelope: HyfEnvelopeRef<'_>,
    output: &mut [u8],
) -> Result<usize, HyfWireError> {
    let required = envelope_encoded_len(envelope)?;
    if output.len() < required {
        return Err(HyfWireError::OutputBufferTooShort {
            actual: output.len(),
            required,
        });
    }

    let mut cursor = WriteCursor::new(output);
    cursor.write_u8(envelope.version);
    cursor.write_array(&envelope.message_id.0);
    cursor.write_array(&envelope.source.0);
    encode_destination(envelope.destination, &mut cursor);
    cursor.write_u64(envelope.created_at_ms.0);
    cursor.write_u64(envelope.expires_at_ms.0);
    cursor.write_u8(envelope.hop_limit);
    cursor.write_u8(envelope.payload_kind.wire_tag());
    cursor.write_u16(envelope.payload.len() as u16);
    cursor.write_array(envelope.payload);

    Ok(required)
}

pub fn decode_envelope(input: &[u8]) -> Result<HyfEnvelopeRef<'_>, HyfWireError> {
    let mut cursor = ReadCursor::new(input);
    let version = cursor.read_u8()?;
    if version != HYF_WIRE_VERSION_0 {
        return Err(HyfWireError::InvalidVersion { actual: version });
    }

    let message_id = MessageId(cursor.read_array::<MESSAGE_ID_LEN>()?);
    let source = NodeId(cursor.read_array::<NODE_ID_LEN>()?);
    let destination = decode_destination(&mut cursor)?;
    let created_at_ms = TimestampMs(cursor.read_u64()?);
    let expires_at_ms = TimestampMs(cursor.read_u64()?);
    let hop_limit = cursor.read_u8()?;
    let payload_kind = PayloadKind::from_wire_tag(cursor.read_u8()?)?;
    let payload_len = cursor.read_u16()? as usize;
    let payload = cursor.read_slice(payload_len)?;

    if cursor.position() != input.len() {
        return Err(HyfWireError::TrailingBytes {
            actual: input.len(),
            expected: cursor.position(),
        });
    }

    let envelope = HyfEnvelopeRef {
        version,
        message_id,
        source,
        destination,
        created_at_ms,
        expires_at_ms,
        hop_limit,
        payload_kind,
        payload,
    };
    validate_envelope(envelope)?;
    Ok(envelope)
}

fn fixed_encoded_len(destination: HyfDestination) -> Result<usize, HyfWireError> {
    let destination_len = match destination {
        HyfDestination::Node(_) => 1 + NODE_ID_LEN,
        HyfDestination::Community(_) => 1 + COMMUNITY_ID_LEN,
        HyfDestination::Foreign(endpoint) => 1 + 1 + 1 + endpoint.len(),
    };
    destination_len
        .checked_add(1 + MESSAGE_ID_LEN + NODE_ID_LEN + U64_LEN + U64_LEN + 1 + 1 + U16_LEN)
        .ok_or(HyfWireError::EnvelopeTooLarge {
            actual: destination_len,
            maximum: HYF_ENVELOPE_MAX_PAYLOAD_LEN,
        })
}

fn encode_destination(destination: HyfDestination, cursor: &mut WriteCursor<'_>) {
    cursor.write_u8(destination.wire_tag());
    match destination {
        HyfDestination::Node(node) => cursor.write_array(&node.0),
        HyfDestination::Community(community) => cursor.write_array(&community.0),
        HyfDestination::Foreign(endpoint) => {
            cursor.write_u8(endpoint.network().wire_tag());
            cursor.write_u8(endpoint.len() as u8);
            cursor.write_array(endpoint.as_bytes());
        }
    }
}

fn decode_destination(cursor: &mut ReadCursor<'_>) -> Result<HyfDestination, HyfWireError> {
    match cursor.read_u8()? {
        0 => Ok(HyfDestination::Node(NodeId(
            cursor.read_array::<NODE_ID_LEN>()?,
        ))),
        1 => Ok(HyfDestination::Community(CommunityId(
            cursor.read_array::<COMMUNITY_ID_LEN>()?,
        ))),
        2 => {
            let network = ForeignNetworkKind::from_wire_tag(cursor.read_u8()?)?;
            let endpoint_len = cursor.read_u8()? as usize;
            let endpoint = ForeignEndpointId::new(network, cursor.read_slice(endpoint_len)?)?;
            Ok(HyfDestination::Foreign(endpoint))
        }
        tag => Err(HyfWireError::InvalidDestinationTag { tag }),
    }
}

struct WriteCursor<'a> {
    output: &'a mut [u8],
    index: usize,
}

impl<'a> WriteCursor<'a> {
    fn new(output: &'a mut [u8]) -> Self {
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

struct ReadCursor<'a> {
    input: &'a [u8],
    index: usize,
}

impl<'a> ReadCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, index: 0 }
    }

    const fn position(&self) -> usize {
        self.index
    }

    fn read_u8(&mut self) -> Result<u8, HyfWireError> {
        Ok(self.read_slice(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, HyfWireError> {
        Ok(u16::from_be_bytes(self.read_array::<U16_LEN>()?))
    }

    fn read_u64(&mut self) -> Result<u64, HyfWireError> {
        Ok(u64::from_be_bytes(self.read_array::<U64_LEN>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], HyfWireError> {
        let slice = self.read_slice(N)?;
        let mut output = [0; N];
        output.copy_from_slice(slice);
        Ok(output)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], HyfWireError> {
        let Some(end) = self.index.checked_add(len) else {
            return Err(HyfWireError::EnvelopeTooLarge {
                actual: len,
                maximum: HYF_ENVELOPE_MAX_PAYLOAD_LEN,
            });
        };
        if self.input.len() < end {
            return Err(HyfWireError::InputTooShort {
                actual: self.input.len(),
                minimum: end,
            });
        }
        let slice = &self.input[self.index..end];
        self.index = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::{ForeignEndpointError, ForeignEndpointId, ForeignNetworkKind};

    use super::{
        HYF_ENVELOPE_MAX_PAYLOAD_LEN, HyfEnvelopeRef, decode_envelope, encode_envelope,
        envelope_encoded_len, validate_envelope,
    };
    use crate::{HYF_WIRE_VERSION_0, HyfDestination, HyfWireError, PayloadKind};
    use hyf_core::{CommunityId, MessageId, NodeId, TimestampMs};

    #[test]
    fn encode_decode_roundtrips_node_destination_and_borrows_payload() -> Result<(), HyfWireError> {
        let envelope = sample_envelope(HyfDestination::Node(NodeId([0x44; 32])), b"hello");
        let mut output = [0; 128];
        let len = encode_envelope(envelope, &mut output)?;
        let decoded = decode_envelope(&output[..len])?;

        assert_eq!(decoded.version, HYF_WIRE_VERSION_0);
        assert_eq!(decoded.message_id, MessageId([0x11; 32]));
        assert_eq!(decoded.source, NodeId([0x22; 32]));
        assert_eq!(
            decoded.destination,
            HyfDestination::Node(NodeId([0x44; 32]))
        );
        assert_eq!(decoded.created_at_ms, TimestampMs(100));
        assert_eq!(decoded.expires_at_ms, TimestampMs(200));
        assert_eq!(decoded.hop_limit, 9);
        assert_eq!(decoded.payload_kind, PayloadKind::HyfNativeV0);
        assert_eq!(decoded.payload, b"hello");
        assert_eq!(decoded.payload.as_ptr(), output[len - 5..len].as_ptr());
        Ok(())
    }

    #[test]
    fn encode_decode_roundtrips_community_and_foreign_destinations() -> Result<(), HyfWireError> {
        let community = sample_envelope(HyfDestination::Community(CommunityId([0x55; 16])), b"c");
        let foreign_endpoint =
            ForeignEndpointId::from_fixed_16(ForeignNetworkKind::Fips, [0x66; 16]);
        let foreign = sample_envelope(HyfDestination::Foreign(foreign_endpoint), b"fips");
        let mut output = [0; 128];

        let community_len = encode_envelope(community, &mut output)?;
        assert_eq!(
            decode_envelope(&output[..community_len])?.destination,
            HyfDestination::Community(CommunityId([0x55; 16]))
        );

        let foreign_len = encode_envelope(foreign, &mut output)?;
        assert_eq!(
            decode_envelope(&output[..foreign_len])?.destination,
            HyfDestination::Foreign(foreign_endpoint)
        );
        Ok(())
    }

    #[test]
    fn encoded_len_matches_written_len() -> Result<(), HyfWireError> {
        let envelope = sample_envelope(HyfDestination::Node(NodeId([0x44; 32])), b"hello");
        let mut output = [0; 128];

        assert_eq!(envelope_encoded_len(envelope)?, 123);
        assert_eq!(encode_envelope(envelope, &mut output)?, 123);
        Ok(())
    }

    #[test]
    fn encode_rejects_invalid_expiry_and_short_output() {
        let mut output = [0; 4];
        let invalid_expiry = HyfEnvelopeRef {
            expires_at_ms: TimestampMs(100),
            ..sample_envelope(HyfDestination::Node(NodeId([0x44; 32])), b"hello")
        };
        let valid = sample_envelope(HyfDestination::Node(NodeId([0x44; 32])), b"hello");

        assert_eq!(
            validate_envelope(invalid_expiry),
            Err(HyfWireError::InvalidExpiry)
        );
        assert_eq!(
            encode_envelope(valid, &mut output),
            Err(HyfWireError::OutputBufferTooShort {
                actual: 4,
                required: 123,
            })
        );
    }

    #[test]
    fn encode_rejects_payloads_larger_than_wire_length_field() {
        let payload = [0; HYF_ENVELOPE_MAX_PAYLOAD_LEN + 1];
        let envelope = sample_envelope(HyfDestination::Node(NodeId([0x44; 32])), &payload);

        assert_eq!(
            envelope_encoded_len(envelope),
            Err(HyfWireError::EnvelopeTooLarge {
                actual: HYF_ENVELOPE_MAX_PAYLOAD_LEN + 1,
                maximum: HYF_ENVELOPE_MAX_PAYLOAD_LEN,
            })
        );
    }

    #[test]
    fn decode_rejects_invalid_tags_lengths_and_trailing_bytes() -> Result<(), HyfWireError> {
        let envelope = sample_envelope(HyfDestination::Node(NodeId([0x44; 32])), b"hello");
        let mut output = [0; 128];
        let len = encode_envelope(envelope, &mut output)?;

        output[0] = 7;
        assert_eq!(
            decode_envelope(&output[..len]),
            Err(HyfWireError::InvalidVersion { actual: 7 })
        );
        output[0] = HYF_WIRE_VERSION_0;
        output[65] = 7;
        assert_eq!(
            decode_envelope(&output[..len]),
            Err(HyfWireError::InvalidDestinationTag { tag: 7 })
        );
        output[65] = 0;
        assert_eq!(
            decode_envelope(&output[..len - 1]),
            Err(HyfWireError::InputTooShort {
                actual: len - 1,
                minimum: len,
            })
        );
        output[len] = 0;
        assert_eq!(
            decode_envelope(&output[..len + 1]),
            Err(HyfWireError::TrailingBytes {
                actual: len + 1,
                expected: len,
            })
        );
        Ok(())
    }

    #[test]
    fn decode_rejects_invalid_foreign_endpoint_length() -> Result<(), HyfWireError> {
        let endpoint = ForeignEndpointId::from_fixed_16(ForeignNetworkKind::Fips, [0x66; 16]);
        let envelope = sample_envelope(HyfDestination::Foreign(endpoint), b"fips");
        let mut output = [0; 128];
        let len = encode_envelope(envelope, &mut output)?;
        output[67] = 0;

        assert_eq!(
            decode_envelope(&output[..len]),
            Err(HyfWireError::InvalidForeignEndpoint(
                ForeignEndpointError::Empty
            ))
        );
        Ok(())
    }

    #[test]
    fn debug_redacts_payload_bytes() {
        let envelope = sample_envelope(HyfDestination::Node(NodeId([0x44; 32])), b"secret");
        let debug = format!("{envelope:?}");

        assert!(debug.contains("HyfEnvelopeRef"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("payload_len"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
    }

    fn sample_envelope<'a>(destination: HyfDestination, payload: &'a [u8]) -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([0x11; 32]),
            source: NodeId([0x22; 32]),
            destination,
            created_at_ms: TimestampMs(100),
            expires_at_ms: TimestampMs(200),
            hop_limit: 9,
            payload_kind: PayloadKind::HyfNativeV0,
            payload,
        }
    }

    #[test]
    fn encoding_layout_is_deterministic() -> Result<(), HyfWireError> {
        let endpoint = ForeignEndpointId::from_fixed_16(ForeignNetworkKind::Fips, [0x66; 16]);
        let envelope = sample_envelope(HyfDestination::Foreign(endpoint), b"fips");
        let mut output = vec![0; envelope_encoded_len(envelope)?];

        let len = encode_envelope(envelope, &mut output)?;

        assert_eq!(output[0], HYF_WIRE_VERSION_0);
        assert_eq!(&output[1..33], &[0x11; 32]);
        assert_eq!(&output[33..65], &[0x22; 32]);
        assert_eq!(output[65], 2);
        assert_eq!(output[66], ForeignNetworkKind::Fips.wire_tag());
        assert_eq!(output[67], 16);
        assert_eq!(&output[68..84], &[0x66; 16]);
        assert_eq!(&output[len - 4..len], b"fips");
        Ok(())
    }
}
