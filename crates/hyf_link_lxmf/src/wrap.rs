use hyf_core::{ForeignEndpointId, ForeignNetworkKind, MessageId};
use hyf_lxmf_core::{LxmfMessageId, LxmfMessageRef, decode_lxmf_message, lxmf_message_id};
use hyf_wire::{
    HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, validate_envelope,
};

use crate::{HyfLinkLxmfError, LxmfWrapParams};

pub fn validate_lxmf_message(raw: &[u8]) -> Result<LxmfMessageRef<'_>, HyfLinkLxmfError> {
    Ok(decode_lxmf_message(raw)?)
}

pub fn wrap_lxmf_message<'a>(
    raw: &'a [u8],
    params: LxmfWrapParams,
) -> Result<HyfEnvelopeRef<'a>, HyfLinkLxmfError> {
    let message = validate_lxmf_message(raw)?;
    let message_id = hyf_message_id(lxmf_message_id(message)?);
    let destination_hash = *message.destination_hash().as_bytes();
    let envelope = HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id,
        source: params.source_node,
        destination: HyfDestination::Foreign(ForeignEndpointId::from_fixed_16(
            ForeignNetworkKind::Lxmf,
            destination_hash,
        )),
        created_at_ms: params.created_at_ms,
        expires_at_ms: params.expires_at_ms,
        hop_limit: params.hop_limit,
        payload_kind: PayloadKind::ForeignLxmfMessage,
        payload: raw,
    };
    validate_envelope(envelope)?;
    Ok(envelope)
}

fn hyf_message_id(message_id: LxmfMessageId) -> MessageId {
    MessageId(message_id.into_bytes())
}

pub fn unwrap_lxmf_message<'a>(envelope: HyfEnvelopeRef<'a>) -> Result<&'a [u8], HyfLinkLxmfError> {
    validate_envelope(envelope)?;
    if envelope.payload_kind != PayloadKind::ForeignLxmfMessage {
        return Err(HyfLinkLxmfError::WrongPayloadKind {
            actual: envelope.payload_kind,
        });
    }
    validate_lxmf_message(envelope.payload)?;
    Ok(envelope.payload)
}

#[cfg(test)]
mod tests {
    use hyf_core::{ForeignNetworkKind, MessageId, NodeId, TimestampMs};
    use hyf_lxmf_core::LXMF_FIXED_HEADER_LEN;
    use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind};

    use super::{unwrap_lxmf_message, validate_lxmf_message, wrap_lxmf_message};
    use crate::{HyfLinkLxmfError, LxmfWrapParams};

    const DESTINATION_HASH: [u8; 16] = [0x01; 16];
    const SOURCE_HASH: [u8; 16] = [0x02; 16];
    const SIGNATURE: [u8; 64] = [0x03; 64];
    const PAYLOAD4: &[u8] = &[
        0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4,
        0x05, b'h', b'e', b'l', b'l', b'o', 0x80,
    ];
    const EXPECTED_MESSAGE_ID: MessageId = MessageId([
        0x18, 0x93, 0xa6, 0xcf, 0x0c, 0xca, 0x60, 0x56, 0x8b, 0x39, 0xf7, 0xa7, 0x00, 0xa1, 0x7a,
        0x67, 0xc0, 0x1c, 0x05, 0xb1, 0xc1, 0xea, 0xbc, 0x6b, 0xa5, 0xf5, 0xd9, 0xf6, 0xfa, 0x17,
        0xe3, 0xe3,
    ]);

    #[test]
    fn validate_accepts_valid_lxmf_message() -> Result<(), HyfLinkLxmfError> {
        let mut raw = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        write_lxmf_message(PAYLOAD4, &mut raw);

        let message = validate_lxmf_message(&raw)?;

        assert_eq!(message.destination_hash().as_bytes(), &DESTINATION_HASH);
        assert_eq!(message.source_hash().as_bytes(), &SOURCE_HASH);
        assert_eq!(message.packed_payload(), PAYLOAD4);
        Ok(())
    }

    #[test]
    fn validate_rejects_malformed_lxmf_message() {
        assert!(matches!(
            validate_lxmf_message(b"bad"),
            Err(HyfLinkLxmfError::Lxmf(
                hyf_lxmf_core::LxmfError::MessageTooShort {
                    actual: 3,
                    minimum: LXMF_FIXED_HEADER_LEN,
                }
            ))
        ));
    }

    #[test]
    fn wrap_sets_foreign_lxmf_kind_destination_and_borrows_raw()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut raw = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        write_lxmf_message(PAYLOAD4, &mut raw);

        let envelope = wrap_lxmf_message(&raw, params())?;

        assert_eq!(envelope.version, HYF_WIRE_VERSION_0);
        assert_eq!(envelope.message_id, EXPECTED_MESSAGE_ID);
        assert_eq!(envelope.source, NodeId([1; 32]));
        assert_eq!(envelope.payload_kind, PayloadKind::ForeignLxmfMessage);
        assert_eq!(envelope.payload, raw);
        assert_eq!(envelope.payload.as_ptr(), raw.as_ptr());
        let HyfDestination::Foreign(endpoint) = envelope.destination else {
            return Err(std::io::Error::other("expected foreign LXMF destination").into());
        };
        assert_eq!(endpoint.network(), ForeignNetworkKind::Lxmf);
        assert_eq!(endpoint.as_bytes(), &DESTINATION_HASH);
        Ok(())
    }

    #[test]
    fn wrap_rejects_invalid_hyf_envelope_params() {
        let mut raw = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        write_lxmf_message(PAYLOAD4, &mut raw);
        let params = LxmfWrapParams {
            expires_at_ms: TimestampMs(10),
            ..params()
        };

        assert!(matches!(
            wrap_lxmf_message(&raw, params),
            Err(HyfLinkLxmfError::HyfWire(
                hyf_wire::HyfWireError::InvalidExpiry
            ))
        ));
    }

    #[test]
    fn unwrap_returns_exact_raw_lxmf_message_and_rejects_wrong_payload_kinds()
    -> Result<(), HyfLinkLxmfError> {
        let mut raw = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        write_lxmf_message(PAYLOAD4, &mut raw);
        let envelope = wrap_lxmf_message(&raw, params())?;

        assert_eq!(unwrap_lxmf_message(envelope)?, raw);

        let native = HyfEnvelopeRef {
            payload_kind: PayloadKind::HyfNativeV0,
            payload: b"native",
            ..envelope
        };
        assert_eq!(
            unwrap_lxmf_message(native),
            Err(HyfLinkLxmfError::WrongPayloadKind {
                actual: PayloadKind::HyfNativeV0,
            })
        );

        let rns = HyfEnvelopeRef {
            payload_kind: PayloadKind::ForeignRnsPacket,
            payload: b"rns",
            ..envelope
        };
        assert_eq!(
            unwrap_lxmf_message(rns),
            Err(HyfLinkLxmfError::WrongPayloadKind {
                actual: PayloadKind::ForeignRnsPacket,
            })
        );
        Ok(())
    }

    #[test]
    fn unwrap_rejects_invalid_embedded_lxmf_message() {
        let envelope = HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([3; 32]),
            source: NodeId([1; 32]),
            destination: HyfDestination::Node(NodeId([2; 32])),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 1,
            payload_kind: PayloadKind::ForeignLxmfMessage,
            payload: b"bad",
        };

        assert!(matches!(
            unwrap_lxmf_message(envelope),
            Err(HyfLinkLxmfError::Lxmf(
                hyf_lxmf_core::LxmfError::MessageTooShort {
                    actual: 3,
                    minimum: LXMF_FIXED_HEADER_LEN,
                }
            ))
        ));
    }

    fn params() -> LxmfWrapParams {
        LxmfWrapParams {
            source_node: NodeId([1; 32]),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
        }
    }

    fn write_lxmf_message(payload: &[u8], output: &mut [u8]) {
        output[..16].copy_from_slice(&DESTINATION_HASH);
        output[16..32].copy_from_slice(&SOURCE_HASH);
        output[32..96].copy_from_slice(&SIGNATURE);
        output[96..96 + payload.len()].copy_from_slice(payload);
    }
}
