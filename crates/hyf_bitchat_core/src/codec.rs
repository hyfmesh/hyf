use crate::{
    BITCHAT_CORE_PACKET_MAX_LEN, BITCHAT_PAYLOAD_MAX_LEN, BITCHAT_PEER_ID_LEN,
    BITCHAT_ROUTE_MAX_HOPS, BITCHAT_SIGNATURE_LEN, BITCHAT_V1_HEADER_LEN, BITCHAT_V2_HEADER_LEN,
    BitchatError, BitchatFlags, BitchatPacketRef, BitchatPayloadRef, BitchatPeerId,
    BitchatRouteRef, BitchatSignature, BitchatVersion,
};

pub fn decode_bitchat_packet(input: &[u8]) -> Result<BitchatPacketRef<'_>, BitchatError> {
    if input.len() > BITCHAT_CORE_PACKET_MAX_LEN {
        return Err(BitchatError::PacketTooLarge {
            actual: input.len(),
            maximum: BITCHAT_CORE_PACKET_MAX_LEN,
        });
    }

    let version = decode_version(input)?;
    let minimum_header_len = fixed_header_len(version);
    if input.len() < minimum_header_len {
        return Err(BitchatError::PacketTooShort {
            actual: input.len(),
            minimum: minimum_header_len,
        });
    }

    let mut cursor = DecodeCursor::new(input);
    let _version = cursor.read_u8("version")?;
    let packet_type = cursor.read_u8("packet type")?;
    let ttl = cursor.read_u8("ttl")?;
    let timestamp = cursor.read_u64("timestamp")?;
    let flags = BitchatFlags::from_wire_byte(cursor.read_u8("flags")?)?;

    if version == BitchatVersion::V1 && flags.has_route {
        return Err(BitchatError::V1RouteFlag);
    }

    let payload_len = match version {
        BitchatVersion::V1 => usize::from(cursor.read_u16("payload length")?),
        BitchatVersion::V2 => cursor.read_u32("payload length")? as usize,
    };

    if payload_len > BITCHAT_PAYLOAD_MAX_LEN {
        return Err(BitchatError::PayloadTooLarge {
            actual: payload_len,
            maximum: BITCHAT_PAYLOAD_MAX_LEN,
        });
    }

    let sender_id = BitchatPeerId::from_bytes(cursor.read_array("sender ID")?);
    let recipient_id = if flags.has_recipient {
        Some(BitchatPeerId::from_bytes(
            cursor.read_array("recipient ID")?,
        ))
    } else {
        None
    };
    let route = decode_route(version, flags, &mut cursor)?;
    let payload_bytes = cursor.read_slice("payload", payload_len)?;
    let payload = decode_payload(version, flags, payload_bytes)?;
    let signature = if flags.has_signature {
        Some(BitchatSignature::from_bytes(
            cursor.read_array("signature")?,
        ))
    } else {
        None
    };

    cursor.finish()?;

    Ok(BitchatPacketRef {
        version,
        packet_type,
        ttl,
        timestamp,
        flags,
        sender_id,
        recipient_id,
        route,
        payload,
        signature,
    })
}

pub fn bitchat_packet_encoded_len_v2(
    packet: BitchatPacketRef<'_>,
) -> Result<usize, BitchatError> {
    let payload_len = encode_plain_payload_len(packet)?;
    let route_len = encoded_route_len(packet.route)?;

    let mut len = BITCHAT_V2_HEADER_LEN
        .checked_add(BITCHAT_PEER_ID_LEN)
        .ok_or(BitchatError::LengthOverflow)?;
    if packet.recipient_id.is_some() {
        len = len
            .checked_add(BITCHAT_PEER_ID_LEN)
            .ok_or(BitchatError::LengthOverflow)?;
    }
    len = len
        .checked_add(route_len)
        .ok_or(BitchatError::LengthOverflow)?
        .checked_add(payload_len)
        .ok_or(BitchatError::LengthOverflow)?;
    if packet.signature.is_some() {
        len = len
            .checked_add(BITCHAT_SIGNATURE_LEN)
            .ok_or(BitchatError::LengthOverflow)?;
    }

    if len > BITCHAT_CORE_PACKET_MAX_LEN {
        return Err(BitchatError::PacketTooLarge {
            actual: len,
            maximum: BITCHAT_CORE_PACKET_MAX_LEN,
        });
    }

    Ok(len)
}

pub fn encode_bitchat_packet_v2(
    packet: BitchatPacketRef<'_>,
    output: &mut [u8],
) -> Result<usize, BitchatError> {
    let needed = bitchat_packet_encoded_len_v2(packet)?;
    if output.len() < needed {
        return Err(BitchatError::OutputTooSmall {
            needed,
            available: output.len(),
        });
    }

    let BitchatPayloadRef::Plain(payload) = packet.payload else {
        return Err(BitchatError::UnsupportedCompressedEncode);
    };

    let flags = canonical_encode_flags(packet);
    let mut cursor = EncodeCursor::new(output);
    cursor.write_u8(2)?;
    cursor.write_u8(packet.packet_type)?;
    cursor.write_u8(packet.ttl)?;
    cursor.write_slice(&packet.timestamp.to_be_bytes())?;
    cursor.write_u8(flags.to_wire_byte())?;
    cursor.write_slice(&(payload.len() as u32).to_be_bytes())?;
    cursor.write_slice(packet.sender_id.as_bytes())?;
    if let Some(recipient_id) = packet.recipient_id {
        cursor.write_slice(recipient_id.as_bytes())?;
    }
    if let Some(route) = packet.route {
        cursor.write_u8(route.hop_count)?;
        cursor.write_slice(route.raw_hops)?;
    }
    cursor.write_slice(payload)?;
    if let Some(signature) = packet.signature {
        cursor.write_slice(signature.as_bytes())?;
    }

    Ok(cursor.position())
}

fn encode_plain_payload_len(packet: BitchatPacketRef<'_>) -> Result<usize, BitchatError> {
    if packet.version != BitchatVersion::V2 {
        return Err(BitchatError::UnsupportedEncodeVersion {
            version: packet.version.wire_value(),
        });
    }

    let BitchatPayloadRef::Plain(payload) = packet.payload else {
        return Err(BitchatError::UnsupportedCompressedEncode);
    };

    if payload.len() > BITCHAT_PAYLOAD_MAX_LEN {
        return Err(BitchatError::PayloadTooLarge {
            actual: payload.len(),
            maximum: BITCHAT_PAYLOAD_MAX_LEN,
        });
    }

    Ok(payload.len())
}

fn encoded_route_len(route: Option<BitchatRouteRef<'_>>) -> Result<usize, BitchatError> {
    let Some(route) = route else {
        return Ok(0);
    };

    let hop_count = usize::from(route.hop_count);
    if hop_count > BITCHAT_ROUTE_MAX_HOPS {
        return Err(BitchatError::RouteTooManyHops {
            actual: hop_count,
            maximum: BITCHAT_ROUTE_MAX_HOPS,
        });
    }

    let expected = hop_count
        .checked_mul(BITCHAT_PEER_ID_LEN)
        .ok_or(BitchatError::LengthOverflow)?;
    if route.raw_hops.len() != expected {
        return Err(BitchatError::InvalidRouteByteLength {
            hop_count: route.hop_count,
            actual: route.raw_hops.len(),
            expected,
        });
    }

    expected.checked_add(1).ok_or(BitchatError::LengthOverflow)
}

const fn canonical_encode_flags(packet: BitchatPacketRef<'_>) -> BitchatFlags {
    BitchatFlags {
        has_recipient: packet.recipient_id.is_some(),
        has_signature: packet.signature.is_some(),
        is_compressed: false,
        has_route: packet.route.is_some(),
        is_rsr: packet.flags.is_rsr,
    }
}

fn decode_version(input: &[u8]) -> Result<BitchatVersion, BitchatError> {
    let Some(version) = input.first().copied() else {
        return Err(BitchatError::PacketTooShort {
            actual: 0,
            minimum: 1,
        });
    };

    BitchatVersion::from_wire_value(version)
}

const fn fixed_header_len(version: BitchatVersion) -> usize {
    match version {
        BitchatVersion::V1 => BITCHAT_V1_HEADER_LEN,
        BitchatVersion::V2 => BITCHAT_V2_HEADER_LEN,
    }
}

fn decode_route<'a>(
    version: BitchatVersion,
    flags: BitchatFlags,
    cursor: &mut DecodeCursor<'a>,
) -> Result<Option<BitchatRouteRef<'a>>, BitchatError> {
    if !flags.has_route {
        return Ok(None);
    }

    if version == BitchatVersion::V1 {
        return Err(BitchatError::V1RouteFlag);
    }

    let hop_count = cursor.read_u8("route hop count")?;
    let hop_count_usize = usize::from(hop_count);
    if hop_count_usize > BITCHAT_ROUTE_MAX_HOPS {
        return Err(BitchatError::RouteTooManyHops {
            actual: hop_count_usize,
            maximum: BITCHAT_ROUTE_MAX_HOPS,
        });
    }

    let route_len = hop_count_usize
        .checked_mul(BITCHAT_PEER_ID_LEN)
        .ok_or(BitchatError::LengthOverflow)?;
    let raw_hops = cursor.read_slice("route hops", route_len)?;

    Ok(Some(BitchatRouteRef {
        hop_count,
        raw_hops,
    }))
}

fn decode_payload<'a>(
    version: BitchatVersion,
    flags: BitchatFlags,
    payload_bytes: &'a [u8],
) -> Result<BitchatPayloadRef<'a>, BitchatError> {
    if !flags.is_compressed {
        return Ok(BitchatPayloadRef::Plain(payload_bytes));
    }

    let preamble_len = compressed_preamble_len(version);
    if payload_bytes.len() < preamble_len {
        return Err(BitchatError::CompressedOriginalLenMissing {
            actual: payload_bytes.len(),
            minimum: preamble_len,
        });
    }

    let original_len = match version {
        BitchatVersion::V1 => {
            usize::from(u16::from_be_bytes([payload_bytes[0], payload_bytes[1]]))
        }
        BitchatVersion::V2 => u32::from_be_bytes([
            payload_bytes[0],
            payload_bytes[1],
            payload_bytes[2],
            payload_bytes[3],
        ]) as usize,
    };

    if original_len == 0 {
        return Err(BitchatError::CompressedOriginalLenZero);
    }
    if original_len > BITCHAT_PAYLOAD_MAX_LEN {
        return Err(BitchatError::CompressedOriginalLenTooLarge {
            actual: original_len,
            maximum: BITCHAT_PAYLOAD_MAX_LEN,
        });
    }

    let compressed_bytes = &payload_bytes[preamble_len..];
    if compressed_bytes.is_empty() {
        return Err(BitchatError::CompressedBodyEmpty);
    }

    Ok(BitchatPayloadRef::Compressed {
        original_len,
        compressed_bytes,
    })
}

const fn compressed_preamble_len(version: BitchatVersion) -> usize {
    match version {
        BitchatVersion::V1 => 2,
        BitchatVersion::V2 => 4,
    }
}

pub(crate) struct DecodeCursor<'a> {
    input: &'a [u8],
    position: usize,
}

struct EncodeCursor<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> EncodeCursor<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn write_u8(&mut self, value: u8) -> Result<(), BitchatError> {
        self.write_slice(&[value])
    }

    fn write_slice(&mut self, bytes: &[u8]) -> Result<(), BitchatError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(BitchatError::LengthOverflow)?;
        if end > self.output.len() {
            return Err(BitchatError::OutputTooSmall {
                needed: end,
                available: self.output.len(),
            });
        }

        self.output[self.position..end].copy_from_slice(bytes);
        self.position = end;

        Ok(())
    }
}

impl<'a> DecodeCursor<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    #[cfg(test)]
    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    pub(crate) fn read_u8(&mut self, field: &'static str) -> Result<u8, BitchatError> {
        let bytes = self.read_slice(field, 1)?;

        Ok(bytes[0])
    }

    pub(crate) fn read_u16(&mut self, field: &'static str) -> Result<u16, BitchatError> {
        let bytes = self.read_slice(field, 2)?;

        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&mut self, field: &'static str) -> Result<u32, BitchatError> {
        let bytes = self.read_slice(field, 4)?;

        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_u64(&mut self, field: &'static str) -> Result<u64, BitchatError> {
        let bytes = self.read_slice(field, 8)?;

        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(crate) fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], BitchatError> {
        let bytes = self.read_slice(field, N)?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);

        Ok(output)
    }

    pub(crate) fn read_slice(
        &mut self,
        field: &'static str,
        len: usize,
    ) -> Result<&'a [u8], BitchatError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(BitchatError::LengthOverflow)?;

        if end > self.input.len() {
            return Err(BitchatError::MissingField {
                field,
                needed: len,
                remaining: self.remaining(),
            });
        }

        let slice = &self.input[self.position..end];
        self.position = end;

        Ok(slice)
    }

    pub(crate) fn finish(self) -> Result<(), BitchatError> {
        let remaining = self.input.len().saturating_sub(self.position);
        if remaining == 0 {
            Ok(())
        } else {
            Err(BitchatError::TrailingBytes { remaining })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DecodeCursor, bitchat_packet_encoded_len_v2, decode_bitchat_packet,
        encode_bitchat_packet_v2,
    };
    use crate::{
        BITCHAT_CORE_PACKET_MAX_LEN, BITCHAT_PAYLOAD_MAX_LEN, BITCHAT_ROUTE_MAX_HOPS,
        BITCHAT_PEER_ID_LEN, BITCHAT_SIGNATURE_LEN, BITCHAT_V1_HEADER_LEN, BITCHAT_V2_HEADER_LEN,
        BitchatError, BitchatFlags, BitchatPacketRef, BitchatPayloadRef, BitchatPeerId,
        BitchatRouteRef, BitchatSignature, BitchatVersion,
    };

    #[test]
    fn cursor_reads_big_endian_values_and_slices() -> Result<(), BitchatError> {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut cursor = DecodeCursor::new(&bytes);

        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.read_u8("version")?, 0x01);
        assert_eq!(cursor.read_u16("u16")?, 0x0203);
        assert_eq!(cursor.read_u32("u32")?, 0x0405_0607);
        assert_eq!(cursor.read_u64("u64")?, 0x0809_0a0b_0c0d_0e0f);
        assert_eq!(cursor.finish(), Ok(()));

        Ok(())
    }

    #[test]
    fn cursor_reads_arrays_and_borrowed_slices() -> Result<(), BitchatError> {
        let bytes = [1, 2, 3, 4, 5, 6];
        let mut cursor = DecodeCursor::new(&bytes);

        assert_eq!(cursor.read_array::<2>("array")?, [1, 2]);
        assert_eq!(cursor.read_slice("slice", 3)?, &[3, 4, 5]);
        assert_eq!(cursor.remaining(), 1);

        Ok(())
    }

    #[test]
    fn cursor_rejects_missing_fields_and_trailing_bytes() -> Result<(), BitchatError> {
        let bytes = [1, 2, 3];
        let mut cursor = DecodeCursor::new(&bytes);

        assert_eq!(cursor.read_u8("first")?, 1);
        assert_eq!(
            cursor.read_slice("payload", 4),
            Err(BitchatError::MissingField {
                field: "payload",
                needed: 4,
                remaining: 2,
            })
        );
        assert_eq!(
            cursor.finish(),
            Err(BitchatError::TrailingBytes { remaining: 2 })
        );

        Ok(())
    }

    #[test]
    fn decode_v1_broadcast_plain_packet() -> Result<(), BitchatError> {
        let packet = v1_packet(0, b"hello");
        let decoded = decode_bitchat_packet(&packet)?;

        assert_eq!(decoded.version, BitchatVersion::V1);
        assert_eq!(decoded.packet_type, 0x31);
        assert_eq!(decoded.ttl, 5);
        assert_eq!(decoded.timestamp, 0x0102_0304_0506_0708);
        assert_eq!(decoded.sender_id, sender_id());
        assert_eq!(decoded.recipient_id, None);
        assert_eq!(decoded.route, None);
        assert_eq!(decoded.payload, BitchatPayloadRef::Plain(b"hello"));
        assert_eq!(decoded.signature, None);

        Ok(())
    }

    #[test]
    fn decode_v1_directed_and_signed_packet() -> Result<(), BitchatError> {
        let mut packet = v1_header_only(0x03, b"hello".len());
        packet.extend_from_slice(recipient_id().as_bytes());
        packet.extend_from_slice(b"hello");
        packet.extend_from_slice(signature().as_bytes());
        let decoded = decode_bitchat_packet(&packet)?;

        assert!(decoded.flags.has_recipient);
        assert!(decoded.flags.has_signature);
        assert_eq!(decoded.recipient_id, Some(recipient_id()));
        assert_eq!(decoded.signature, Some(signature()));
        assert_eq!(decoded.payload, BitchatPayloadRef::Plain(b"hello"));

        Ok(())
    }

    #[test]
    fn decode_rejects_v1_route_flag() {
        assert_eq!(
            decode_bitchat_packet(&v1_packet(0x08, b"hello")),
            Err(BitchatError::V1RouteFlag)
        );
    }

    #[test]
    fn decode_v2_broadcast_plain_packet_with_zero_values() -> Result<(), BitchatError> {
        let packet = v2_packet(0, 0x99, 0, 0, zero_peer_id(), b"");
        let decoded = decode_bitchat_packet(&packet)?;

        assert_eq!(decoded.version, BitchatVersion::V2);
        assert_eq!(decoded.packet_type, 0x99);
        assert_eq!(decoded.ttl, 0);
        assert_eq!(decoded.timestamp, 0);
        assert_eq!(decoded.sender_id, zero_peer_id());
        assert_eq!(decoded.payload, BitchatPayloadRef::Plain(b""));

        Ok(())
    }

    #[test]
    fn decode_v2_directed_route_and_empty_route_packets() -> Result<(), BitchatError> {
        let route_hops = [0x44; 16];
        let mut packet = v2_header_only(0x09, 0x42, 8, 7, sender_id(), b"payload".len());
        packet.extend_from_slice(recipient_id().as_bytes());
        packet.push(2);
        packet.extend_from_slice(&route_hops);
        packet.extend_from_slice(b"payload");
        let decoded = decode_bitchat_packet(&packet)?;

        assert_eq!(decoded.recipient_id, Some(recipient_id()));
        assert_eq!(
            decoded.route,
            Some(BitchatRouteRef {
                hop_count: 2,
                raw_hops: &route_hops,
            })
        );
        assert_eq!(decoded.payload, BitchatPayloadRef::Plain(b"payload"));

        let empty_route = v2_header_only(0x08, 0x42, 8, 7, sender_id(), b"payload".len());
        let mut empty_route_with_count = empty_route;
        empty_route_with_count.push(0);
        empty_route_with_count.extend_from_slice(b"payload");
        let decoded_empty_route = decode_bitchat_packet(&empty_route_with_count)?;
        assert_eq!(
            decoded_empty_route.route,
            Some(BitchatRouteRef {
                hop_count: 0,
                raw_hops: &[],
            })
        );

        Ok(())
    }

    #[test]
    fn decode_compressed_payloads_structurally() -> Result<(), BitchatError> {
        let v1_payload = [0x00, 0x09, 0xaa, 0xbb];
        let v1_packet = v1_packet(0x04, &v1_payload);
        let v1 = decode_bitchat_packet(&v1_packet)?;
        assert_eq!(
            v1.payload,
            BitchatPayloadRef::Compressed {
                original_len: 9,
                compressed_bytes: &[0xaa, 0xbb],
            }
        );

        let v2_payload = [0x00, 0x00, 0x00, 0x0a, 0xcc];
        let v2_packet = v2_packet(0x04, 1, 1, 1, sender_id(), &v2_payload);
        let v2 = decode_bitchat_packet(&v2_packet)?;
        assert_eq!(
            v2.payload,
            BitchatPayloadRef::Compressed {
                original_len: 10,
                compressed_bytes: &[0xcc],
            }
        );

        Ok(())
    }

    #[test]
    fn decode_rejects_malformed_compressed_payloads() {
        assert_eq!(
            decode_bitchat_packet(&v1_packet(0x04, &[0x00])),
            Err(BitchatError::CompressedOriginalLenMissing {
                actual: 1,
                minimum: 2,
            })
        );
        assert_eq!(
            decode_bitchat_packet(&v1_packet(0x04, &[0x00, 0x00, 0xaa])),
            Err(BitchatError::CompressedOriginalLenZero)
        );
        assert_eq!(
            decode_bitchat_packet(&v1_packet(0x04, &[0x00, 0x01])),
            Err(BitchatError::CompressedBodyEmpty)
        );

        let mut too_large = Vec::new();
        too_large.extend_from_slice(&(BITCHAT_PAYLOAD_MAX_LEN as u32 + 1).to_be_bytes());
        too_large.push(0xaa);
        assert_eq!(
            decode_bitchat_packet(&v2_packet(0x04, 1, 1, 1, sender_id(), &too_large)),
            Err(BitchatError::CompressedOriginalLenTooLarge {
                actual: BITCHAT_PAYLOAD_MAX_LEN + 1,
                maximum: BITCHAT_PAYLOAD_MAX_LEN,
            })
        );
    }

    #[test]
    fn decode_rejects_trailing_padding() {
        let mut packet = v2_packet(0, 1, 1, 1, sender_id(), b"payload");
        packet.push(0);

        assert_eq!(
            decode_bitchat_packet(&packet),
            Err(BitchatError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn decode_rejects_malformed_structures() {
        assert_eq!(
            decode_bitchat_packet(&[]),
            Err(BitchatError::PacketTooShort {
                actual: 0,
                minimum: 1,
            })
        );
        assert_eq!(
            decode_bitchat_packet(&[3]),
            Err(BitchatError::UnknownVersion { version: 3 })
        );
        assert_eq!(
            decode_bitchat_packet(&[1; BITCHAT_V1_HEADER_LEN - 1]),
            Err(BitchatError::PacketTooShort {
                actual: BITCHAT_V1_HEADER_LEN - 1,
                minimum: BITCHAT_V1_HEADER_LEN,
            })
        );
        assert_eq!(
            decode_bitchat_packet(&v2_packet(0xe0, 1, 1, 1, sender_id(), b"payload")),
            Err(BitchatError::ReservedFlags { flags: 0xe0 })
        );

        let mut route_too_many = v2_header_only(0x08, 1, 1, 1, sender_id(), b"payload".len());
        route_too_many.push((BITCHAT_ROUTE_MAX_HOPS + 1) as u8);
        assert_eq!(
            decode_bitchat_packet(&route_too_many),
            Err(BitchatError::RouteTooManyHops {
                actual: BITCHAT_ROUTE_MAX_HOPS + 1,
                maximum: BITCHAT_ROUTE_MAX_HOPS,
            })
        );

        let payload_too_large =
            v2_header_only(0, 1, 1, 1, sender_id(), BITCHAT_PAYLOAD_MAX_LEN + 1);
        assert_eq!(
            decode_bitchat_packet(&payload_too_large),
            Err(BitchatError::PayloadTooLarge {
                actual: BITCHAT_PAYLOAD_MAX_LEN + 1,
                maximum: BITCHAT_PAYLOAD_MAX_LEN,
            })
        );

        let packet_too_large = vec![1; BITCHAT_CORE_PACKET_MAX_LEN + 1];
        assert_eq!(
            decode_bitchat_packet(&packet_too_large),
            Err(BitchatError::PacketTooLarge {
                actual: BITCHAT_CORE_PACKET_MAX_LEN + 1,
                maximum: BITCHAT_CORE_PACKET_MAX_LEN,
            })
        );
    }

    #[test]
    fn decode_rejects_missing_variable_fields() {
        let mut missing_sender = v2_header_only(0, 1, 1, 1, sender_id(), 1);
        missing_sender.truncate(16);
        assert_eq!(
            decode_bitchat_packet(&missing_sender),
            Err(BitchatError::MissingField {
                field: "sender ID",
                needed: 8,
                remaining: 0,
            })
        );

        let mut missing_recipient = v2_packet(0x01, 1, 1, 1, sender_id(), b"payload");
        missing_recipient.truncate(24);
        assert_eq!(
            decode_bitchat_packet(&missing_recipient),
            Err(BitchatError::MissingField {
                field: "recipient ID",
                needed: 8,
                remaining: 0,
            })
        );

        let mut missing_route_hop = v2_header_only(0x08, 1, 1, 1, sender_id(), b"payload".len());
        missing_route_hop.push(1);
        assert_eq!(
            decode_bitchat_packet(&missing_route_hop),
            Err(BitchatError::MissingField {
                field: "route hops",
                needed: 8,
                remaining: 0,
            })
        );

        let missing_payload = v2_header_only(0, 1, 1, 1, sender_id(), 4);
        assert_eq!(
            decode_bitchat_packet(&missing_payload),
            Err(BitchatError::MissingField {
                field: "payload",
                needed: 4,
                remaining: 0,
            })
        );

        let mut missing_signature = v2_packet(0x02, 1, 1, 1, sender_id(), b"payload");
        assert_eq!(
            decode_bitchat_packet(&missing_signature),
            Err(BitchatError::MissingField {
                field: "signature",
                needed: BITCHAT_SIGNATURE_LEN,
                remaining: 0,
            })
        );
        missing_signature.extend_from_slice(&[0xaa; 63]);
        assert_eq!(
            decode_bitchat_packet(&missing_signature),
            Err(BitchatError::MissingField {
                field: "signature",
                needed: BITCHAT_SIGNATURE_LEN,
                remaining: 63,
            })
        );
    }

    #[test]
    fn encoded_len_v2_counts_payload_without_route_bytes() -> Result<(), BitchatError> {
        let route_hops = [0x44; 16];
        let packet = packet_ref(
            BitchatPayloadRef::Plain(b"hello"),
            Some(BitchatRouteRef {
                hop_count: 2,
                raw_hops: &route_hops,
            }),
            None,
            None,
        );

        assert_eq!(
            bitchat_packet_encoded_len_v2(packet)?,
            BITCHAT_V2_HEADER_LEN + BITCHAT_PEER_ID_LEN + 1 + route_hops.len() + b"hello".len()
        );

        Ok(())
    }

    #[test]
    fn encode_v2_writes_canonical_plain_packet() -> Result<(), BitchatError> {
        let route_hops = [0x55; 8];
        let packet = BitchatPacketRef {
            version: BitchatVersion::V2,
            packet_type: 0xfe,
            ttl: 9,
            timestamp: 0x0102_0304_0506_0708,
            flags: BitchatFlags {
                has_recipient: false,
                has_signature: false,
                is_compressed: true,
                has_route: false,
                is_rsr: true,
            },
            sender_id: sender_id(),
            recipient_id: Some(recipient_id()),
            route: Some(BitchatRouteRef {
                hop_count: 1,
                raw_hops: &route_hops,
            }),
            payload: BitchatPayloadRef::Plain(b"hello"),
            signature: Some(signature()),
        };
        let needed = bitchat_packet_encoded_len_v2(packet)?;
        let mut output = vec![0; needed];

        let written = encode_bitchat_packet_v2(packet, &mut output)?;
        assert_eq!(written, needed);
        assert_eq!(&output[..3], &[2, 0xfe, 9]);
        assert_eq!(&output[3..11], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(output[11], 0x1b);
        assert_eq!(&output[12..16], &(b"hello".len() as u32).to_be_bytes());

        let decoded = decode_bitchat_packet(&output)?;
        assert_eq!(decoded.packet_type, 0xfe);
        assert_eq!(decoded.flags.to_wire_byte(), 0x1b);
        assert_eq!(decoded.payload, BitchatPayloadRef::Plain(b"hello"));
        assert_eq!(decoded.recipient_id, Some(recipient_id()));
        assert_eq!(
            decoded.route,
            Some(BitchatRouteRef {
                hop_count: 1,
                raw_hops: &route_hops,
            })
        );
        assert_eq!(decoded.signature, Some(signature()));

        Ok(())
    }

    #[test]
    fn packet_type_roundtrips_as_raw_u8() -> Result<(), BitchatError> {
        let packet = packet_ref(BitchatPayloadRef::Plain(b"packet-type"), None, None, None);
        let packet = BitchatPacketRef {
            packet_type: 0xff,
            ..packet
        };
        let mut output = vec![0; bitchat_packet_encoded_len_v2(packet)?];

        encode_bitchat_packet_v2(packet, &mut output)?;
        assert_eq!(decode_bitchat_packet(&output)?.packet_type, 0xff);

        Ok(())
    }

    #[test]
    fn encode_v2_rejects_unsupported_inputs() {
        let v1 = BitchatPacketRef {
            version: BitchatVersion::V1,
            ..packet_ref(BitchatPayloadRef::Plain(b"hello"), None, None, None)
        };
        assert_eq!(
            bitchat_packet_encoded_len_v2(v1),
            Err(BitchatError::UnsupportedEncodeVersion { version: 1 })
        );

        let compressed = packet_ref(
            BitchatPayloadRef::Compressed {
                original_len: 5,
                compressed_bytes: b"bytes",
            },
            None,
            None,
            None,
        );
        assert_eq!(
            bitchat_packet_encoded_len_v2(compressed),
            Err(BitchatError::UnsupportedCompressedEncode)
        );

        let oversized_payload = vec![0xaa; BITCHAT_PAYLOAD_MAX_LEN + 1];
        let oversized = packet_ref(BitchatPayloadRef::Plain(&oversized_payload), None, None, None);
        assert_eq!(
            bitchat_packet_encoded_len_v2(oversized),
            Err(BitchatError::PayloadTooLarge {
                actual: BITCHAT_PAYLOAD_MAX_LEN + 1,
                maximum: BITCHAT_PAYLOAD_MAX_LEN,
            })
        );
    }

    #[test]
    fn encode_v2_rejects_route_and_output_errors() -> Result<(), BitchatError> {
        let route_hops = [0xaa; 8];
        let too_many = packet_ref(
            BitchatPayloadRef::Plain(b"hello"),
            Some(BitchatRouteRef {
                hop_count: (BITCHAT_ROUTE_MAX_HOPS + 1) as u8,
                raw_hops: &route_hops,
            }),
            None,
            None,
        );
        assert_eq!(
            bitchat_packet_encoded_len_v2(too_many),
            Err(BitchatError::RouteTooManyHops {
                actual: BITCHAT_ROUTE_MAX_HOPS + 1,
                maximum: BITCHAT_ROUTE_MAX_HOPS,
            })
        );

        let invalid_route = packet_ref(
            BitchatPayloadRef::Plain(b"hello"),
            Some(BitchatRouteRef {
                hop_count: 2,
                raw_hops: &route_hops,
            }),
            None,
            None,
        );
        assert_eq!(
            bitchat_packet_encoded_len_v2(invalid_route),
            Err(BitchatError::InvalidRouteByteLength {
                hop_count: 2,
                actual: 8,
                expected: 16,
            })
        );

        let packet = packet_ref(BitchatPayloadRef::Plain(b"hello"), None, None, None);
        let needed = bitchat_packet_encoded_len_v2(packet)?;
        let mut short_output = vec![0; needed - 1];
        assert_eq!(
            encode_bitchat_packet_v2(packet, &mut short_output),
            Err(BitchatError::OutputTooSmall {
                needed,
                available: needed - 1,
            })
        );

        Ok(())
    }

    fn v1_packet(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = v1_header_only(flags, payload.len());
        packet.extend_from_slice(payload);
        packet
    }

    fn v1_header_only(flags: u8, payload_len: usize) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(1);
        packet.push(0x31);
        packet.push(5);
        packet.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
        packet.push(flags);
        packet.extend_from_slice(&(payload_len as u16).to_be_bytes());
        packet.extend_from_slice(sender_id().as_bytes());
        packet
    }

    fn v2_packet(
        flags: u8,
        packet_type: u8,
        ttl: u8,
        timestamp: u64,
        sender_id: BitchatPeerId,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = v2_header_only(flags, packet_type, ttl, timestamp, sender_id, payload.len());
        packet.extend_from_slice(payload);
        packet
    }

    fn v2_header_only(
        flags: u8,
        packet_type: u8,
        ttl: u8,
        timestamp: u64,
        sender_id: BitchatPeerId,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(2);
        packet.push(packet_type);
        packet.push(ttl);
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.push(flags);
        packet.extend_from_slice(&(payload_len as u32).to_be_bytes());
        packet.extend_from_slice(sender_id.as_bytes());
        packet
    }

    fn sender_id() -> BitchatPeerId {
        BitchatPeerId::from_bytes([0x11; 8])
    }

    fn recipient_id() -> BitchatPeerId {
        BitchatPeerId::from_bytes([0x22; 8])
    }

    fn zero_peer_id() -> BitchatPeerId {
        BitchatPeerId::from_bytes([0; 8])
    }

    fn signature() -> BitchatSignature {
        BitchatSignature::from_bytes([0x33; 64])
    }

    fn packet_ref<'a>(
        payload: BitchatPayloadRef<'a>,
        route: Option<BitchatRouteRef<'a>>,
        recipient_id: Option<BitchatPeerId>,
        signature: Option<BitchatSignature>,
    ) -> BitchatPacketRef<'a> {
        BitchatPacketRef {
            version: BitchatVersion::V2,
            packet_type: 0x31,
            ttl: 5,
            timestamp: 6,
            flags: BitchatFlags::empty(),
            sender_id: sender_id(),
            recipient_id,
            route,
            payload,
            signature,
        }
    }
}
