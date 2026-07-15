use core::{fmt, str};

use hyf_bitchat_core::{
    BitchatFlags, BitchatPacketRef, BitchatPayloadRef, BitchatVersion, decode_bitchat_packet,
    encode_bitchat_packet_v2,
};
use hyf_bridge_core::{
    BridgeEndpointKind, BridgeEndpointRef, BridgeIngressMeta, BridgeMessageRef, BridgePayloadKind,
    BridgeProtocol, BridgeVerificationState, bridge_message_encoded_len,
};
use hyf_core::{ForeignNetworkKind, TimestampMs};

use crate::{BitchatBridgeEgressParams, BitchatBridgeError, BitchatBridgeIngressParams};

pub const BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE: u8 = 0x02;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BitchatBridgeIngress<'a> {
    packet: BitchatPacketRef<'a>,
    params: BitchatBridgeIngressParams,
    sender_id: [u8; 8],
    payload: &'a [u8],
}

impl fmt::Debug for BitchatBridgeIngress<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitchatBridgeIngress")
            .field("packet", &self.packet)
            .field("params", &self.params)
            .field("sender_id", &"<redacted>")
            .field("sender_id_len", &self.sender_id.len())
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl<'a> BitchatBridgeIngress<'a> {
    pub const fn packet(&self) -> BitchatPacketRef<'a> {
        self.packet
    }

    pub const fn ingress_meta(&self) -> BridgeIngressMeta {
        BridgeIngressMeta {
            origin_protocol: BridgeProtocol::BitChat,
            verification_state: BridgeVerificationState::Unverified,
        }
    }

    pub fn bridge_message(&self) -> BridgeMessageRef<'_> {
        BridgeMessageRef {
            version: hyf_bridge_core::HYF_BRIDGE_MESSAGE_VERSION_0,
            room_id: self.params.room_id,
            message_id: self.params.message_id,
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::BitChat),
                id: &self.sender_id,
            },
            created_at_ms: TimestampMs(self.packet.timestamp),
            payload_kind: BridgePayloadKind::TextUtf8,
            payload: self.payload,
        }
    }
}

pub fn decode_bitchat_bridge_ingress<'a>(
    raw: &'a [u8],
    params: BitchatBridgeIngressParams,
) -> Result<BitchatBridgeIngress<'a>, BitchatBridgeError> {
    let packet = decode_bitchat_packet(raw)?;
    validate_ingress_packet(packet)?;
    let BitchatPayloadRef::Plain(payload) = packet.payload else {
        return Err(BitchatBridgeError::CompressedPacket);
    };
    if payload.is_empty() {
        return Err(BitchatBridgeError::EmptyPayload);
    }
    if str::from_utf8(payload).is_err() {
        return Err(BitchatBridgeError::InvalidPayloadUtf8);
    }

    Ok(BitchatBridgeIngress {
        packet,
        params,
        sender_id: packet.sender_id.into_bytes(),
        payload,
    })
}

pub fn encode_bridge_message_to_bitchat_packet(
    message: BridgeMessageRef<'_>,
    params: BitchatBridgeEgressParams,
    output: &mut [u8],
) -> Result<usize, BitchatBridgeError> {
    validate_egress_message(message)?;
    let packet = BitchatPacketRef {
        version: BitchatVersion::V2,
        packet_type: BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE,
        ttl: params.ttl,
        timestamp: message.created_at_ms.0,
        flags: BitchatFlags::empty(),
        sender_id: params.sender_id,
        recipient_id: None,
        route: None,
        payload: BitchatPayloadRef::Plain(message.payload),
        signature: None,
    };

    Ok(encode_bitchat_packet_v2(packet, output)?)
}

fn validate_ingress_packet(packet: BitchatPacketRef<'_>) -> Result<(), BitchatBridgeError> {
    if packet.version != BitchatVersion::V2 {
        return Err(BitchatBridgeError::UnsupportedVersion {
            version: packet.version,
        });
    }
    if packet.packet_type != BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE {
        return Err(BitchatBridgeError::UnsupportedPacketType {
            packet_type: packet.packet_type,
        });
    }
    if packet.flags.has_signature || packet.signature.is_some() {
        return Err(BitchatBridgeError::SignedPacket);
    }
    if packet.flags.is_compressed || matches!(packet.payload, BitchatPayloadRef::Compressed { .. })
    {
        return Err(BitchatBridgeError::CompressedPacket);
    }
    if packet.flags.has_recipient || packet.recipient_id.is_some() {
        return Err(BitchatBridgeError::DirectedPacket);
    }
    if packet.flags.has_route || packet.route.is_some() {
        return Err(BitchatBridgeError::RoutedPacket);
    }
    if packet.flags.is_rsr {
        return Err(BitchatBridgeError::RsrPacket);
    }
    if packet.timestamp == 0 {
        return Err(BitchatBridgeError::TimestampZero);
    }
    Ok(())
}

fn validate_egress_message(message: BridgeMessageRef<'_>) -> Result<(), BitchatBridgeError> {
    if message.payload_kind != BridgePayloadKind::TextUtf8 {
        return Err(BitchatBridgeError::UnsupportedBridgePayloadKind {
            kind: message.payload_kind,
        });
    }
    if message.payload.is_empty() {
        return Err(BitchatBridgeError::EmptyPayload);
    }
    if str::from_utf8(message.payload).is_err() {
        return Err(BitchatBridgeError::InvalidPayloadUtf8);
    }
    if message.created_at_ms.0 == 0 {
        return Err(BitchatBridgeError::TimestampZero);
    }
    bridge_message_encoded_len(message)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyf_bitchat_core::{
        BITCHAT_PEER_ID_LEN, BITCHAT_SIGNATURE_LEN, BitchatFlags, BitchatPacketRef,
        BitchatPayloadRef, BitchatPeerId, BitchatSignature, BitchatVersion, decode_bitchat_packet,
        encode_bitchat_packet_v2,
    };
    use hyf_bridge_core::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeMessageRef, BridgePayloadKind, BridgeProtocol,
        BridgeVerificationState, HYF_BRIDGE_MESSAGE_VERSION_0,
    };
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};

    use super::{
        BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE, decode_bitchat_bridge_ingress,
        encode_bridge_message_to_bitchat_packet,
    };
    use crate::{BitchatBridgeEgressParams, BitchatBridgeError, BitchatBridgeIngressParams};

    const ROOM: CommunityId = CommunityId([0x31; 16]);
    const MESSAGE: MessageId = MessageId([0x32; 32]);
    const SENDER: BitchatPeerId = BitchatPeerId::from_bytes([0x33; 8]);

    #[test]
    fn strict_public_packet_converts_to_bridge_message() -> Result<(), BitchatBridgeError> {
        let raw = encode_public_packet(b"hello", 1000)?;
        let ingress = decode_bitchat_bridge_ingress(&raw, params())?;
        let message = ingress.bridge_message();
        let meta = ingress.ingress_meta();

        assert_eq!(
            ingress.packet().packet_type,
            BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE
        );
        assert_eq!(meta.origin_protocol, BridgeProtocol::BitChat);
        assert_eq!(meta.verification_state, BridgeVerificationState::Unverified);
        assert_eq!(message.version, HYF_BRIDGE_MESSAGE_VERSION_0);
        assert_eq!(message.room_id, ROOM);
        assert_eq!(message.message_id, MESSAGE);
        assert_eq!(
            message.author,
            BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::BitChat),
                id: SENDER.as_bytes(),
            }
        );
        assert_eq!(message.created_at_ms, TimestampMs(1000));
        assert_eq!(message.payload_kind, BridgePayloadKind::TextUtf8);
        assert_eq!(message.payload, b"hello");
        Ok(())
    }

    #[test]
    fn bridge_message_encodes_to_canonical_public_v2_packet() -> Result<(), BitchatBridgeError> {
        let mut output = [0; 128];
        let len = encode_bridge_message_to_bitchat_packet(
            bridge_message(b"hello", 2000, BridgePayloadKind::TextUtf8),
            BitchatBridgeEgressParams::with_ttl(SENDER, 3),
            &mut output,
        )?;
        let packet = decode_bitchat_packet(&output[..len])?;

        assert_eq!(packet.version, BitchatVersion::V2);
        assert_eq!(
            packet.packet_type,
            BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE
        );
        assert_eq!(packet.ttl, 3);
        assert_eq!(packet.timestamp, 2000);
        assert_eq!(packet.flags, BitchatFlags::empty());
        assert_eq!(packet.sender_id, SENDER);
        assert_eq!(packet.recipient_id, None);
        assert_eq!(packet.route, None);
        assert_eq!(packet.payload, BitchatPayloadRef::Plain(b"hello"));
        assert_eq!(packet.signature, None);
        Ok(())
    }

    #[test]
    fn ingress_rejects_every_non_public_profile_case() -> Result<(), BitchatBridgeError> {
        assert_ingress_error(
            &encode_packet(packet_ref(
                0x09,
                BitchatFlags::empty(),
                b"hello",
                1000,
                None,
            ))?,
            BitchatBridgeError::UnsupportedPacketType { packet_type: 0x09 },
        );
        assert_ingress_error(
            &raw_v1_public_packet(b"hello"),
            BitchatBridgeError::UnsupportedVersion {
                version: BitchatVersion::V1,
            },
        );
        assert_ingress_error(
            &raw_v2_packet(0x04, b"\0\0\0\x05hello", None),
            BitchatBridgeError::CompressedPacket,
        );
        assert_ingress_error(
            &encode_packet(packet_ref(
                BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE,
                BitchatFlags::empty(),
                b"hello",
                1000,
                Some(SENDER),
            ))?,
            BitchatBridgeError::DirectedPacket,
        );
        assert_ingress_error(
            &raw_v2_packet(0x08, b"hello", Some(&route_bytes())),
            BitchatBridgeError::RoutedPacket,
        );
        assert_ingress_error(
            &encode_packet(BitchatPacketRef {
                flags: BitchatFlags {
                    is_rsr: true,
                    ..BitchatFlags::empty()
                },
                ..packet_ref(
                    BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE,
                    BitchatFlags::empty(),
                    b"hello",
                    1000,
                    None,
                )
            })?,
            BitchatBridgeError::RsrPacket,
        );
        assert_ingress_error(
            &encode_packet(BitchatPacketRef {
                signature: Some(BitchatSignature::from_bytes([0x44; BITCHAT_SIGNATURE_LEN])),
                ..packet_ref(
                    BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE,
                    BitchatFlags::empty(),
                    b"hello",
                    1000,
                    None,
                )
            })?,
            BitchatBridgeError::SignedPacket,
        );
        assert_ingress_error(
            &encode_public_packet(b"", 1000)?,
            BitchatBridgeError::EmptyPayload,
        );
        assert_ingress_error(
            &encode_public_packet(&[0xff], 1000)?,
            BitchatBridgeError::InvalidPayloadUtf8,
        );
        assert_ingress_error(
            &encode_public_packet(b"hello", 0)?,
            BitchatBridgeError::TimestampZero,
        );
        Ok(())
    }

    #[test]
    fn egress_rejects_non_text_empty_invalid_utf8_and_zero_timestamp() {
        let mut output = [0; 128];

        assert_eq!(
            encode_bridge_message_to_bitchat_packet(
                bridge_message(b"opaque", 1000, BridgePayloadKind::OpaqueBytes),
                BitchatBridgeEgressParams::new(SENDER),
                &mut output,
            ),
            Err(BitchatBridgeError::UnsupportedBridgePayloadKind {
                kind: BridgePayloadKind::OpaqueBytes,
            })
        );
        assert_eq!(
            encode_bridge_message_to_bitchat_packet(
                bridge_message(b"", 1000, BridgePayloadKind::TextUtf8),
                BitchatBridgeEgressParams::new(SENDER),
                &mut output,
            ),
            Err(BitchatBridgeError::EmptyPayload)
        );
        assert_eq!(
            encode_bridge_message_to_bitchat_packet(
                bridge_message(&[0xff], 1000, BridgePayloadKind::TextUtf8),
                BitchatBridgeEgressParams::new(SENDER),
                &mut output,
            ),
            Err(BitchatBridgeError::InvalidPayloadUtf8)
        );
        assert_eq!(
            encode_bridge_message_to_bitchat_packet(
                bridge_message(b"hello", 0, BridgePayloadKind::TextUtf8),
                BitchatBridgeEgressParams::new(SENDER),
                &mut output,
            ),
            Err(BitchatBridgeError::TimestampZero)
        );
    }

    #[test]
    fn egress_surfaces_output_too_small_from_bitchat_core() {
        let mut output = [0; 2];

        assert!(matches!(
            encode_bridge_message_to_bitchat_packet(
                bridge_message(b"hello", 1000, BridgePayloadKind::TextUtf8),
                BitchatBridgeEgressParams::new(SENDER),
                &mut output,
            ),
            Err(BitchatBridgeError::Bitchat(_))
        ));
    }

    fn assert_ingress_error(raw: &[u8], expected: BitchatBridgeError) {
        assert_eq!(decode_bitchat_bridge_ingress(raw, params()), Err(expected));
    }

    fn encode_public_packet(payload: &[u8], timestamp: u64) -> Result<Vec<u8>, BitchatBridgeError> {
        encode_packet(packet_ref(
            BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE,
            BitchatFlags::empty(),
            payload,
            timestamp,
            None,
        ))
    }

    fn encode_packet(packet: BitchatPacketRef<'_>) -> Result<Vec<u8>, BitchatBridgeError> {
        let len = hyf_bitchat_core::bitchat_packet_encoded_len_v2(packet)?;
        let mut output = vec![0; len];
        encode_bitchat_packet_v2(packet, &mut output)?;
        Ok(output)
    }

    fn raw_v1_public_packet(payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(1);
        raw.push(BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE);
        raw.push(7);
        raw.extend_from_slice(&1000u64.to_be_bytes());
        raw.push(0);
        raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(SENDER.as_bytes());
        raw.extend_from_slice(payload);
        raw
    }

    fn raw_v2_packet(flags: u8, payload: &[u8], route: Option<&[u8]>) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(2);
        raw.push(BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE);
        raw.push(7);
        raw.extend_from_slice(&1000u64.to_be_bytes());
        raw.push(flags);
        raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(SENDER.as_bytes());
        if let Some(route_bytes) = route {
            raw.push((route_bytes.len() / BITCHAT_PEER_ID_LEN) as u8);
            raw.extend_from_slice(route_bytes);
        }
        raw.extend_from_slice(payload);
        raw
    }

    fn packet_ref<'a>(
        packet_type: u8,
        flags: BitchatFlags,
        payload: &'a [u8],
        timestamp: u64,
        recipient_id: Option<BitchatPeerId>,
    ) -> BitchatPacketRef<'a> {
        BitchatPacketRef {
            version: BitchatVersion::V2,
            packet_type,
            ttl: 7,
            timestamp,
            flags,
            sender_id: SENDER,
            recipient_id,
            route: None,
            payload: BitchatPayloadRef::Plain(payload),
            signature: None,
        }
    }

    fn bridge_message(
        payload: &[u8],
        created_at_ms: u64,
        payload_kind: BridgePayloadKind,
    ) -> BridgeMessageRef<'_> {
        BridgeMessageRef {
            version: HYF_BRIDGE_MESSAGE_VERSION_0,
            room_id: ROOM,
            message_id: MESSAGE,
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::BitChat),
                id: SENDER.as_bytes(),
            },
            created_at_ms: TimestampMs(created_at_ms),
            payload_kind,
            payload,
        }
    }

    fn params() -> BitchatBridgeIngressParams {
        BitchatBridgeIngressParams::new(ROOM, MESSAGE)
    }

    fn route_bytes() -> [u8; BITCHAT_PEER_ID_LEN] {
        [0x55; BITCHAT_PEER_ID_LEN]
    }
}
