use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_wire::{
    HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, validate_envelope,
};

use crate::{HyfLinkRnsError, RnsPacketRef, validate_rns_packet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnsWrapParams {
    pub source_node: NodeId,
    pub destination: HyfDestination,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: TimestampMs,
    pub hop_limit: u8,
    pub message_id: MessageId,
}

pub fn wrap_rns_packet<'a>(
    packet: RnsPacketRef<'a>,
    params: RnsWrapParams,
) -> Result<HyfEnvelopeRef<'a>, HyfLinkRnsError> {
    validate_rns_packet(packet.raw)?;
    let envelope = HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id: params.message_id,
        source: params.source_node,
        destination: params.destination,
        created_at_ms: params.created_at_ms,
        expires_at_ms: params.expires_at_ms,
        hop_limit: params.hop_limit,
        payload_kind: PayloadKind::ForeignRnsPacket,
        payload: packet.raw,
    };
    validate_envelope(envelope)?;
    Ok(envelope)
}

pub fn unwrap_rns_packet<'a>(envelope: HyfEnvelopeRef<'a>) -> Result<&'a [u8], HyfLinkRnsError> {
    validate_envelope(envelope)?;
    if envelope.payload_kind != PayloadKind::ForeignRnsPacket {
        return Err(HyfLinkRnsError::NotForeignRnsPacket);
    }
    Ok(validate_rns_packet(envelope.payload)?.raw)
}

#[cfg(test)]
mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind};

    use super::{RnsWrapParams, unwrap_rns_packet, wrap_rns_packet};
    use crate::{HyfLinkRnsError, validate_rns_packet};

    const HEADER_1_PACKET: &[u8] = &[
        0x00, 0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x00, b'h', b'e', b'a', b'd', b'e', b'r', b'-', b'o', b'n', b'e',
    ];

    #[test]
    fn wrap_sets_foreign_rns_payload_kind_and_borrows_raw_packet() -> Result<(), HyfLinkRnsError> {
        let packet = validate_rns_packet(HEADER_1_PACKET)?;
        let envelope = wrap_rns_packet(packet, params())?;

        assert_eq!(envelope.version, HYF_WIRE_VERSION_0);
        assert_eq!(envelope.message_id, MessageId([3; 32]));
        assert_eq!(envelope.payload_kind, PayloadKind::ForeignRnsPacket);
        assert_eq!(envelope.payload, HEADER_1_PACKET);
        assert_eq!(envelope.payload.as_ptr(), HEADER_1_PACKET.as_ptr());
        Ok(())
    }

    #[test]
    fn unwrap_returns_exact_raw_packet_and_rejects_native_payload() -> Result<(), HyfLinkRnsError> {
        let packet = validate_rns_packet(HEADER_1_PACKET)?;
        let envelope = wrap_rns_packet(packet, params())?;

        assert_eq!(unwrap_rns_packet(envelope)?, HEADER_1_PACKET);

        let native = HyfEnvelopeRef {
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"native",
            ..envelope
        };
        assert_eq!(
            unwrap_rns_packet(native),
            Err(HyfLinkRnsError::NotForeignRnsPacket)
        );
        Ok(())
    }

    #[test]
    fn wrap_rejects_invalid_params() -> Result<(), HyfLinkRnsError> {
        let packet = validate_rns_packet(HEADER_1_PACKET)?;
        let bad_params = RnsWrapParams {
            expires_at_ms: TimestampMs(10),
            ..params()
        };

        assert!(matches!(
            wrap_rns_packet(packet, bad_params),
            Err(HyfLinkRnsError::HyfWire(
                hyf_wire::HyfWireError::InvalidExpiry
            ))
        ));
        Ok(())
    }

    #[test]
    fn unwrap_rejects_invalid_embedded_rns_packet() {
        let envelope = HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([3; 32]),
            source: NodeId([1; 32]),
            destination: HyfDestination::Node(NodeId([2; 32])),
            created_at_ms: TimestampMs(1),
            expires_at_ms: TimestampMs(2),
            hop_limit: 1,
            payload_kind: PayloadKind::ForeignRnsPacket,
            payload: b"bad",
        };

        assert!(unwrap_rns_packet(envelope).is_err());
    }

    fn params() -> RnsWrapParams {
        RnsWrapParams {
            source_node: NodeId([1; 32]),
            destination: HyfDestination::Node(NodeId([2; 32])),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
            message_id: MessageId([3; 32]),
        }
    }
}
