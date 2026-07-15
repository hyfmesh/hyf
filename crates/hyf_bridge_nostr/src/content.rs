use hyf_bridge_core::validate_bridge_message;
use hyf_link_nostr::{decode_lower_hex, encode_lower_hex};

use crate::NostrBridgeError;

pub fn encode_bridge_nostr_content<'out>(
    raw_bridge_message: &[u8],
    output: &'out mut [u8],
) -> Result<&'out str, NostrBridgeError> {
    validate_bridge_message(raw_bridge_message)?;
    Ok(encode_lower_hex(raw_bridge_message, output)?)
}

pub fn decode_bridge_nostr_content<'out>(
    content: &str,
    output: &'out mut [u8],
) -> Result<&'out [u8], NostrBridgeError> {
    let len = decode_lower_hex(content, output)?;
    validate_bridge_message(&output[..len])?;
    Ok(&output[..len])
}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeMessageRef, BridgePayloadKind,
        HYF_BRIDGE_MESSAGE_VERSION_0, encode_bridge_message,
    };
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};

    use super::{decode_bridge_nostr_content, encode_bridge_nostr_content};
    use crate::NostrBridgeError;

    #[test]
    fn content_codec_roundtrips_lowercase_hex_bridge_messages() -> Result<(), NostrBridgeError> {
        let mut raw = [0; 128];
        let raw_len = encode_bridge_message(sample_message(), &mut raw)?;
        let mut content = [0; 256];
        let content = encode_bridge_nostr_content(&raw[..raw_len], &mut content)?;
        let mut decoded = [0; 128];
        let decoded = decode_bridge_nostr_content(content, &mut decoded)?;

        assert!(!content.as_bytes().iter().any(u8::is_ascii_uppercase));
        assert_eq!(decoded, &raw[..raw_len]);
        Ok(())
    }

    #[test]
    fn content_codec_rejects_bad_hex_and_invalid_bridge_payload() {
        assert!(matches!(
            decode_bridge_nostr_content("zz", &mut [0; 1]),
            Err(NostrBridgeError::Nostr(_))
        ));
        assert!(matches!(
            decode_bridge_nostr_content("00", &mut [0; 1]),
            Err(NostrBridgeError::Bridge(_))
        ));
    }

    fn sample_message() -> BridgeMessageRef<'static> {
        BridgeMessageRef {
            version: HYF_BRIDGE_MESSAGE_VERSION_0,
            room_id: CommunityId([1; 16]),
            message_id: MessageId([2; 32]),
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::Nostr),
                id: &[3; 32],
            },
            created_at_ms: TimestampMs(1000),
            payload_kind: BridgePayloadKind::TextUtf8,
            payload: b"hello",
        }
    }
}
