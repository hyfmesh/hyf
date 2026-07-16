use core::{fmt, str};

use hyf_bridge_core::{
    BridgeEndpointKind, BridgeEndpointRef, BridgeIngressMeta, BridgeMessageRef, BridgePayloadKind,
    BridgeProtocol, BridgeVerificationState, bridge_message_encoded_len,
};
use hyf_core::{ForeignNetworkKind, TimestampMs};
use hyf_lxmf_core::{
    LxmfMessageRef, LxmfPayloadRef, LxmfRawMapRef, decode_lxmf_message, encode_lxmf_message,
};

use crate::{LxmfBridgeEgressParams, LxmfBridgeError, LxmfBridgeIngressParams};

const EMPTY_FIELDS_MAP: &[u8] = &[0x80];

#[derive(Clone, Copy, PartialEq)]
pub struct LxmfBridgeIngress<'a> {
    message: LxmfMessageRef<'a>,
    params: LxmfBridgeIngressParams,
    source_hash: [u8; 16],
    created_at_ms: TimestampMs,
    content: &'a [u8],
}

impl fmt::Debug for LxmfBridgeIngress<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LxmfBridgeIngress")
            .field("message", &self.message)
            .field("params", &self.params)
            .field("source_hash", &"<redacted>")
            .field("source_hash_len", &self.source_hash.len())
            .field("created_at_ms", &self.created_at_ms)
            .field("content", &"<redacted>")
            .field("content_len", &self.content.len())
            .finish()
    }
}

impl<'a> LxmfBridgeIngress<'a> {
    pub const fn message(&self) -> LxmfMessageRef<'a> {
        self.message
    }

    pub const fn ingress_meta(&self) -> BridgeIngressMeta {
        BridgeIngressMeta {
            origin_protocol: BridgeProtocol::Lxmf,
            verification_state: BridgeVerificationState::Unverified,
        }
    }

    pub fn bridge_message(&self) -> BridgeMessageRef<'_> {
        BridgeMessageRef {
            version: hyf_bridge_core::HYF_BRIDGE_MESSAGE_VERSION_0,
            room_id: self.params.room_id,
            message_id: self.params.message_id,
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::Lxmf),
                id: &self.source_hash,
            },
            created_at_ms: self.created_at_ms,
            payload_kind: BridgePayloadKind::TextUtf8,
            payload: self.content,
        }
    }
}

pub fn lxmf_message_to_bridge_message<'a>(
    raw: &'a [u8],
    params: LxmfBridgeIngressParams,
) -> Result<LxmfBridgeIngress<'a>, LxmfBridgeError> {
    let message = decode_lxmf_message(raw)?;
    let payload = message.payload();
    validate_content_only_payload(payload)?;
    let created_at_ms = timestamp_secs_to_ms(payload.timestamp_secs)?;

    Ok(LxmfBridgeIngress {
        message,
        params,
        source_hash: *message.source_hash().as_bytes(),
        created_at_ms,
        content: payload.content,
    })
}

pub fn bridge_message_to_lxmf_message_fixture(
    message: BridgeMessageRef<'_>,
    params: LxmfBridgeEgressParams,
    output: &mut [u8],
) -> Result<usize, LxmfBridgeError> {
    validate_egress_message(message)?;
    let payload = LxmfPayloadRef {
        timestamp_secs: message.created_at_ms.0 as f64 / 1000.0,
        title: b"",
        content: message.payload,
        fields: LxmfRawMapRef {
            bytes: EMPTY_FIELDS_MAP,
        },
        stamp: None,
    };

    Ok(encode_lxmf_message(
        params.destination_hash,
        params.source_hash,
        params.signature,
        payload,
        output,
    )?)
}

fn validate_content_only_payload(payload: LxmfPayloadRef<'_>) -> Result<(), LxmfBridgeError> {
    if !payload.title.is_empty() {
        return Err(LxmfBridgeError::NonEmptyTitle);
    }
    if payload.fields.bytes != EMPTY_FIELDS_MAP {
        return Err(LxmfBridgeError::NonEmptyFields);
    }
    if payload.stamp.is_some() {
        return Err(LxmfBridgeError::StampPresent);
    }
    if payload.content.is_empty() {
        return Err(LxmfBridgeError::EmptyContent);
    }
    if str::from_utf8(payload.content).is_err() {
        return Err(LxmfBridgeError::InvalidContentUtf8);
    }
    Ok(())
}

fn validate_egress_message(message: BridgeMessageRef<'_>) -> Result<(), LxmfBridgeError> {
    if message.payload_kind != BridgePayloadKind::TextUtf8 {
        return Err(LxmfBridgeError::UnsupportedBridgePayloadKind {
            kind: message.payload_kind,
        });
    }
    if message.payload.is_empty() {
        return Err(LxmfBridgeError::EmptyContent);
    }
    if str::from_utf8(message.payload).is_err() {
        return Err(LxmfBridgeError::InvalidContentUtf8);
    }
    bridge_message_encoded_len(message)?;
    Ok(())
}

fn timestamp_secs_to_ms(timestamp_secs: f64) -> Result<TimestampMs, LxmfBridgeError> {
    if timestamp_secs < 0.0 {
        return Err(LxmfBridgeError::NegativeTimestamp);
    }
    let millis = timestamp_secs * 1000.0;
    if !millis.is_finite() || millis > u64::MAX as f64 {
        return Err(LxmfBridgeError::TimestampOverflow);
    }
    Ok(TimestampMs(millis as u64))
}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeMessageRef, BridgePayloadKind, BridgeProtocol,
        BridgeVerificationState, HYF_BRIDGE_MESSAGE_VERSION_0,
    };
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};
    use hyf_lxmf_core::{
        LXMF_FIXED_HEADER_LEN, LxmfDestinationHash, LxmfPayloadRef, LxmfRawMapRef, LxmfSignature,
        LxmfSourceHash, LxmfStampRef, decode_lxmf_message, encode_lxmf_message,
    };

    use super::{bridge_message_to_lxmf_message_fixture, lxmf_message_to_bridge_message};
    use crate::{LxmfBridgeEgressParams, LxmfBridgeError, LxmfBridgeIngressParams};

    const ROOM: CommunityId = CommunityId([0x41; 16]);
    const MESSAGE: MessageId = MessageId([0x42; 32]);
    const DESTINATION_HASH: LxmfDestinationHash = LxmfDestinationHash::from_bytes([0x43; 16]);
    const SOURCE_HASH: LxmfSourceHash = LxmfSourceHash::from_bytes([0x44; 16]);
    const SIGNATURE: LxmfSignature = LxmfSignature::from_bytes([0x45; 64]);

    #[test]
    fn content_only_lxmf_converts_to_bridge_message() -> Result<(), LxmfBridgeError> {
        let raw = encode_lxmf_fixture(payload_ref(1.5, b"", b"hello", &[0x80], None))?;
        let ingress = lxmf_message_to_bridge_message(&raw, params())?;
        let message = ingress.bridge_message();
        let meta = ingress.ingress_meta();

        assert_eq!(ingress.message().source_hash(), &SOURCE_HASH);
        assert_eq!(meta.origin_protocol, BridgeProtocol::Lxmf);
        assert_eq!(meta.verification_state, BridgeVerificationState::Unverified);
        assert_eq!(message.version, HYF_BRIDGE_MESSAGE_VERSION_0);
        assert_eq!(message.room_id, ROOM);
        assert_eq!(message.message_id, MESSAGE);
        assert_eq!(
            message.author,
            BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::Lxmf),
                id: SOURCE_HASH.as_bytes(),
            }
        );
        assert_eq!(message.created_at_ms, TimestampMs(1500));
        assert_eq!(message.payload_kind, BridgePayloadKind::TextUtf8);
        assert_eq!(message.payload, b"hello");
        Ok(())
    }

    #[test]
    fn bridge_message_encodes_to_content_only_lxmf_fixture() -> Result<(), LxmfBridgeError> {
        let mut output = [0; 256];
        let len = bridge_message_to_lxmf_message_fixture(
            bridge_message(b"hello", 2500, BridgePayloadKind::TextUtf8),
            egress_params(),
            &mut output,
        )?;
        let message = decode_lxmf_message(&output[..len])?;
        let payload = message.payload();

        assert_eq!(message.destination_hash(), &DESTINATION_HASH);
        assert_eq!(message.source_hash(), &SOURCE_HASH);
        assert_eq!(message.signature(), &SIGNATURE);
        assert_eq!(payload.timestamp_secs, 2.5);
        assert_eq!(payload.title, b"");
        assert_eq!(payload.content, b"hello");
        assert_eq!(payload.fields.bytes, &[0x80]);
        assert_eq!(payload.stamp, None);
        Ok(())
    }

    #[test]
    fn ingress_rejects_non_content_only_profiles() -> Result<(), LxmfBridgeError> {
        assert_ingress_error(
            &encode_lxmf_fixture(payload_ref(1.0, b"title", b"hello", &[0x80], None))?,
            LxmfBridgeError::NonEmptyTitle,
        );
        assert_ingress_error(
            &encode_lxmf_fixture(payload_ref(
                1.0,
                b"",
                b"hello",
                &[0x81, 0xa1, b'a', 0x01],
                None,
            ))?,
            LxmfBridgeError::NonEmptyFields,
        );
        assert_ingress_error(
            &raw_lxmf_with_stamp(b"hello"),
            LxmfBridgeError::StampPresent,
        );
        assert_ingress_error(
            &encode_lxmf_fixture(payload_ref(1.0, b"", b"", &[0x80], None))?,
            LxmfBridgeError::EmptyContent,
        );
        assert_ingress_error(
            &encode_lxmf_fixture(payload_ref(1.0, b"", &[0xff], &[0x80], None))?,
            LxmfBridgeError::InvalidContentUtf8,
        );
        assert_ingress_error(
            &encode_lxmf_fixture(payload_ref(-1.0, b"", b"hello", &[0x80], None))?,
            LxmfBridgeError::NegativeTimestamp,
        );
        Ok(())
    }

    #[test]
    fn egress_rejects_non_text_empty_invalid_utf8_and_short_output() {
        let mut output = [0; 256];

        assert_eq!(
            bridge_message_to_lxmf_message_fixture(
                bridge_message(b"opaque", 1000, BridgePayloadKind::OpaqueBytes),
                egress_params(),
                &mut output,
            ),
            Err(LxmfBridgeError::UnsupportedBridgePayloadKind {
                kind: BridgePayloadKind::OpaqueBytes,
            })
        );
        assert_eq!(
            bridge_message_to_lxmf_message_fixture(
                bridge_message(b"", 1000, BridgePayloadKind::TextUtf8),
                egress_params(),
                &mut output,
            ),
            Err(LxmfBridgeError::EmptyContent)
        );
        assert_eq!(
            bridge_message_to_lxmf_message_fixture(
                bridge_message(&[0xff], 1000, BridgePayloadKind::TextUtf8),
                egress_params(),
                &mut output,
            ),
            Err(LxmfBridgeError::InvalidContentUtf8)
        );

        let mut short = [0; 2];
        assert!(matches!(
            bridge_message_to_lxmf_message_fixture(
                bridge_message(b"hello", 1000, BridgePayloadKind::TextUtf8),
                egress_params(),
                &mut short,
            ),
            Err(LxmfBridgeError::Lxmf(_))
        ));
    }

    #[test]
    fn timestamp_conversion_rejects_overflow() {
        let overflow_secs = f64::MAX;
        assert_eq!(
            super::timestamp_secs_to_ms(overflow_secs),
            Err(LxmfBridgeError::TimestampOverflow)
        );
    }

    fn assert_ingress_error(raw: &[u8], expected: LxmfBridgeError) {
        assert_eq!(lxmf_message_to_bridge_message(raw, params()), Err(expected));
    }

    fn encode_lxmf_fixture(payload: LxmfPayloadRef<'_>) -> Result<Vec<u8>, LxmfBridgeError> {
        let mut output = vec![0; 256];
        let len = encode_lxmf_message(
            DESTINATION_HASH,
            SOURCE_HASH,
            SIGNATURE,
            payload,
            &mut output,
        )?;
        output.truncate(len);
        Ok(output)
    }

    fn raw_lxmf_with_stamp(content: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0x95);
        payload.push(0xcb);
        payload.extend_from_slice(&1.0f64.to_bits().to_be_bytes());
        write_bin(b"", &mut payload);
        write_bin(content, &mut payload);
        payload.push(0x80);
        write_bin(b"stamp", &mut payload);

        let mut output = vec![0; LXMF_FIXED_HEADER_LEN + payload.len()];
        output[..16].copy_from_slice(DESTINATION_HASH.as_bytes());
        output[16..32].copy_from_slice(SOURCE_HASH.as_bytes());
        output[32..96].copy_from_slice(SIGNATURE.as_bytes());
        output[96..].copy_from_slice(&payload);
        output
    }

    fn write_bin(bytes: &[u8], output: &mut Vec<u8>) {
        output.push(0xc4);
        output.push(bytes.len() as u8);
        output.extend_from_slice(bytes);
    }

    fn payload_ref<'a>(
        timestamp_secs: f64,
        title: &'a [u8],
        content: &'a [u8],
        fields: &'a [u8],
        stamp: Option<LxmfStampRef<'a>>,
    ) -> LxmfPayloadRef<'a> {
        LxmfPayloadRef {
            timestamp_secs,
            title,
            content,
            fields: LxmfRawMapRef { bytes: fields },
            stamp,
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
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::Lxmf),
                id: SOURCE_HASH.as_bytes(),
            },
            created_at_ms: TimestampMs(created_at_ms),
            payload_kind,
            payload,
        }
    }

    fn params() -> LxmfBridgeIngressParams {
        LxmfBridgeIngressParams::new(ROOM, MESSAGE)
    }

    fn egress_params() -> LxmfBridgeEgressParams {
        LxmfBridgeEgressParams::new(DESTINATION_HASH, SOURCE_HASH, SIGNATURE)
    }
}
