use hyf_bitchat_core::{BITCHAT_CARRIER_PACKET_MAX_LEN, BitchatPacketRef, decode_bitchat_packet};
use hyf_wire::{HYF_WIRE_VERSION_0, HyfEnvelopeRef, PayloadKind, validate_envelope};

use crate::{BitchatWrapParams, HyfLinkBitchatError};

pub fn validate_bitchat_packet(raw: &[u8]) -> Result<BitchatPacketRef<'_>, HyfLinkBitchatError> {
    enforce_carrier_packet_len(raw)?;
    Ok(decode_bitchat_packet(raw)?)
}

fn enforce_carrier_packet_len(raw: &[u8]) -> Result<(), HyfLinkBitchatError> {
    if raw.len() > BITCHAT_CARRIER_PACKET_MAX_LEN {
        return Err(HyfLinkBitchatError::PacketTooLargeForCarrier {
            actual: raw.len(),
            maximum: BITCHAT_CARRIER_PACKET_MAX_LEN,
        });
    }

    Ok(())
}

pub fn wrap_bitchat_packet<'a>(
    raw: &'a [u8],
    params: BitchatWrapParams,
) -> Result<HyfEnvelopeRef<'a>, HyfLinkBitchatError> {
    validate_bitchat_packet(raw)?;
    let envelope = HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id: params.message_id,
        source: params.source_node,
        destination: params.destination,
        created_at_ms: params.created_at_ms,
        expires_at_ms: params.expires_at_ms,
        hop_limit: params.hop_limit,
        payload_kind: PayloadKind::ForeignBitChatPacket,
        payload: raw,
    };
    validate_envelope(envelope)?;
    Ok(envelope)
}

pub fn unwrap_bitchat_packet<'a>(
    envelope: HyfEnvelopeRef<'a>,
) -> Result<&'a [u8], HyfLinkBitchatError> {
    validate_envelope(envelope)?;
    if envelope.payload_kind != PayloadKind::ForeignBitChatPacket {
        return Err(HyfLinkBitchatError::WrongPayloadKind {
            actual: envelope.payload_kind,
        });
    }
    validate_bitchat_packet(envelope.payload)?;
    Ok(envelope.payload)
}

#[cfg(test)]
mod tests {
    use hyf_bitchat_core::{BITCHAT_CARRIER_PACKET_MAX_LEN, BitchatError};
    use hyf_core::{ForeignEndpointId, ForeignNetworkKind, MessageId, NodeId, TimestampMs};
    use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind};

    use super::{unwrap_bitchat_packet, validate_bitchat_packet, wrap_bitchat_packet};
    use crate::{BitchatWrapParams, HyfLinkBitchatError};

    const EXPLICIT_MESSAGE_ID: MessageId = MessageId([0x9a; 32]);
    const EXPLICIT_DESTINATION_BYTES: [u8; 16] = [0xbc; 16];

    #[test]
    fn validate_accepts_valid_bitchat_packet() -> Result<(), HyfLinkBitchatError> {
        let raw = raw_bitchat_packet();
        let packet = validate_bitchat_packet(&raw)?;

        assert_eq!(packet.packet_type, 0x31);
        assert_eq!(
            packet.payload,
            hyf_bitchat_core::BitchatPayloadRef::Plain(b"hello")
        );

        Ok(())
    }

    #[test]
    fn validate_rejects_malformed_bitchat_packet() {
        assert_eq!(
            validate_bitchat_packet(&[2]),
            Err(HyfLinkBitchatError::Bitchat(BitchatError::PacketTooShort {
                actual: 1,
                minimum: 16,
            }))
        );
    }

    #[test]
    fn wrap_sets_explicit_bitchat_kind_destination_and_borrows_raw()
    -> Result<(), HyfLinkBitchatError> {
        let raw = raw_bitchat_packet();
        let envelope = wrap_bitchat_packet(&raw, params())?;

        assert_eq!(envelope.version, HYF_WIRE_VERSION_0);
        assert_eq!(envelope.message_id, EXPLICIT_MESSAGE_ID);
        assert_eq!(envelope.source, NodeId([1; 32]));
        assert_eq!(envelope.destination, params().destination);
        assert_eq!(envelope.payload_kind, PayloadKind::ForeignBitChatPacket);
        assert_eq!(envelope.payload, raw);
        assert_eq!(envelope.payload.as_ptr(), raw.as_ptr());

        Ok(())
    }

    #[test]
    fn wrap_rejects_invalid_hyf_params_and_carrier_oversize() {
        let raw = raw_bitchat_packet();
        let params = BitchatWrapParams {
            expires_at_ms: TimestampMs(10),
            ..params()
        };
        assert_eq!(
            wrap_bitchat_packet(&raw, params),
            Err(HyfLinkBitchatError::HyfWire(
                hyf_wire::HyfWireError::InvalidExpiry
            ))
        );

        let oversize = vec![0; BITCHAT_CARRIER_PACKET_MAX_LEN + 1];
        assert_eq!(
            wrap_bitchat_packet(&oversize, self::params()),
            Err(HyfLinkBitchatError::PacketTooLargeForCarrier {
                actual: BITCHAT_CARRIER_PACKET_MAX_LEN + 1,
                maximum: BITCHAT_CARRIER_PACKET_MAX_LEN,
            })
        );
    }

    #[test]
    fn unwrap_returns_exact_raw_bitchat_packet_and_rejects_wrong_kinds()
    -> Result<(), HyfLinkBitchatError> {
        let raw = raw_bitchat_packet();
        let envelope = wrap_bitchat_packet(&raw, params())?;

        assert_eq!(unwrap_bitchat_packet(envelope)?, raw);

        let native = HyfEnvelopeRef {
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"native",
            ..envelope
        };
        assert_eq!(
            unwrap_bitchat_packet(native),
            Err(HyfLinkBitchatError::WrongPayloadKind {
                actual: PayloadKind::HyfNativeV0,
            })
        );

        let lxmf = HyfEnvelopeRef {
            payload_kind: PayloadKind::ForeignLxmfMessage,
            payload: b"lxmf",
            ..envelope
        };
        assert_eq!(
            unwrap_bitchat_packet(lxmf),
            Err(HyfLinkBitchatError::WrongPayloadKind {
                actual: PayloadKind::ForeignLxmfMessage,
            })
        );

        Ok(())
    }

    #[test]
    fn unwrap_rejects_invalid_embedded_bitchat_packet() {
        let envelope = HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([3; 32]),
            source: NodeId([1; 32]),
            destination: params().destination,
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 1,
            payload_kind: PayloadKind::ForeignBitChatPacket,
            payload: &[2],
        };

        assert_eq!(
            unwrap_bitchat_packet(envelope),
            Err(HyfLinkBitchatError::Bitchat(BitchatError::PacketTooShort {
                actual: 1,
                minimum: 16,
            }))
        );
    }

    fn params() -> BitchatWrapParams {
        BitchatWrapParams {
            message_id: EXPLICIT_MESSAGE_ID,
            source_node: NodeId([1; 32]),
            destination: HyfDestination::Foreign(ForeignEndpointId::from_fixed_16(
                ForeignNetworkKind::BitChat,
                EXPLICIT_DESTINATION_BYTES,
            )),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
        }
    }

    fn raw_bitchat_packet() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(2);
        packet.push(0x31);
        packet.push(5);
        packet.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
        packet.push(0);
        packet.extend_from_slice(&(b"hello".len() as u32).to_be_bytes());
        packet.extend_from_slice(&[0x11; 8]);
        packet.extend_from_slice(b"hello");
        packet
    }
}
