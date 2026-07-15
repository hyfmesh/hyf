use hyf_core::{NodeId, TimestampMs};
use hyf_wire::{
    HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, validate_envelope,
};

use crate::{BridgeError, decode_bridge_message};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeWrapParams {
    pub source_node: NodeId,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: TimestampMs,
    pub hop_limit: u8,
}

pub fn validate_bridge_message(raw: &[u8]) -> Result<crate::BridgeMessageRef<'_>, BridgeError> {
    decode_bridge_message(raw)
}

pub fn wrap_bridge_message<'a>(
    raw: &'a [u8],
    params: BridgeWrapParams,
) -> Result<HyfEnvelopeRef<'a>, BridgeError> {
    let message = validate_bridge_message(raw)?;
    let envelope = HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id: message.message_id,
        source: params.source_node,
        destination: HyfDestination::Community(message.room_id),
        created_at_ms: params.created_at_ms,
        expires_at_ms: params.expires_at_ms,
        hop_limit: params.hop_limit,
        payload_kind: PayloadKind::HyfBridgeMessageV0,
        payload: raw,
    };
    validate_envelope(envelope)?;
    Ok(envelope)
}

pub fn unwrap_bridge_message<'a>(envelope: HyfEnvelopeRef<'a>) -> Result<&'a [u8], BridgeError> {
    validate_envelope(envelope)?;
    if envelope.payload_kind != PayloadKind::HyfBridgeMessageV0 {
        return Err(BridgeError::WrongPayloadKind {
            actual: envelope.payload_kind,
        });
    }
    let message = validate_bridge_message(envelope.payload)?;
    if envelope.message_id != message.message_id {
        return Err(BridgeError::EnvelopeMessageIdMismatch);
    }
    if envelope.destination != HyfDestination::Community(message.room_id) {
        return Err(BridgeError::EnvelopeRoomMismatch);
    }
    Ok(envelope.payload)
}

#[cfg(test)]
mod tests {
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, NodeId, TimestampMs};
    use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind};

    use super::{
        BridgeWrapParams, unwrap_bridge_message, validate_bridge_message, wrap_bridge_message,
    };
    use crate::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeError, BridgeMessageRef, BridgePayloadKind,
        encode_bridge_message,
    };

    const ROOM: CommunityId = CommunityId([1; 16]);
    const MESSAGE: MessageId = MessageId([2; 32]);
    const SOURCE: NodeId = NodeId([3; 32]);

    #[test]
    fn wrap_sets_bridge_envelope_fields_and_borrows_raw() -> Result<(), BridgeError> {
        let mut raw = [0; 128];
        let len = encode_bridge_message(sample_message(b"hello"), &mut raw)?;
        let envelope = wrap_bridge_message(&raw[..len], params())?;

        assert_eq!(envelope.version, HYF_WIRE_VERSION_0);
        assert_eq!(envelope.message_id, MESSAGE);
        assert_eq!(envelope.source, SOURCE);
        assert_eq!(envelope.destination, HyfDestination::Community(ROOM));
        assert_eq!(envelope.payload_kind, PayloadKind::HyfBridgeMessageV0);
        assert_eq!(envelope.payload, &raw[..len]);
        assert_eq!(envelope.payload.as_ptr(), raw.as_ptr());
        Ok(())
    }

    #[test]
    fn unwrap_returns_raw_bridge_message_and_rejects_mismatches() -> Result<(), BridgeError> {
        let mut raw = [0; 128];
        let len = encode_bridge_message(sample_message(b"hello"), &mut raw)?;
        let envelope = wrap_bridge_message(&raw[..len], params())?;

        assert_eq!(unwrap_bridge_message(envelope)?, &raw[..len]);

        let wrong_kind = HyfEnvelopeRef {
            payload_kind: PayloadKind::HyfNativeV0,
            ..envelope
        };
        assert_eq!(
            unwrap_bridge_message(wrong_kind),
            Err(BridgeError::WrongPayloadKind {
                actual: PayloadKind::HyfNativeV0,
            })
        );

        let wrong_id = HyfEnvelopeRef {
            message_id: MessageId([9; 32]),
            ..envelope
        };
        assert_eq!(
            unwrap_bridge_message(wrong_id),
            Err(BridgeError::EnvelopeMessageIdMismatch)
        );

        let wrong_room = HyfEnvelopeRef {
            destination: HyfDestination::Community(CommunityId([9; 16])),
            ..envelope
        };
        assert_eq!(
            unwrap_bridge_message(wrong_room),
            Err(BridgeError::EnvelopeRoomMismatch)
        );
        Ok(())
    }

    #[test]
    fn validate_rejects_invalid_bridge_payload() {
        assert!(matches!(
            validate_bridge_message(b"bad"),
            Err(BridgeError::InvalidVersion { actual: b'b' })
        ));
    }

    fn params() -> BridgeWrapParams {
        BridgeWrapParams {
            source_node: SOURCE,
            created_at_ms: TimestampMs(1000),
            expires_at_ms: TimestampMs(2000),
            hop_limit: 7,
        }
    }

    fn sample_message(payload: &[u8]) -> BridgeMessageRef<'_> {
        BridgeMessageRef {
            version: 0,
            room_id: ROOM,
            message_id: MESSAGE,
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::BitChat),
                id: &[4; 8],
            },
            created_at_ms: TimestampMs(1000),
            payload_kind: BridgePayloadKind::TextUtf8,
            payload,
        }
    }
}
