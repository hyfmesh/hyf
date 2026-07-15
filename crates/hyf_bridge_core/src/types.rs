use core::fmt;

use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeEndpointKind {
    HyfNode,
    Foreign(ForeignNetworkKind),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BridgeEndpointRef<'a> {
    pub kind: BridgeEndpointKind,
    pub id: &'a [u8],
}

impl fmt::Debug for BridgeEndpointRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeEndpointRef")
            .field("kind", &self.kind)
            .field("id", &"<redacted>")
            .field("id_len", &self.id.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BridgePayloadKind {
    TextUtf8 = 1,
    OpaqueBytes = 255,
}

impl BridgePayloadKind {
    pub const fn wire_tag(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BridgeMessageRef<'a> {
    pub version: u8,
    pub room_id: CommunityId,
    pub message_id: MessageId,
    pub author: BridgeEndpointRef<'a>,
    pub created_at_ms: TimestampMs,
    pub payload_kind: BridgePayloadKind,
    pub payload: &'a [u8],
}

impl fmt::Debug for BridgeMessageRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeMessageRef")
            .field("version", &self.version)
            .field("room_id", &self.room_id)
            .field("message_id", &self.message_id)
            .field("author", &self.author)
            .field("created_at_ms", &self.created_at_ms)
            .field("payload_kind", &self.payload_kind)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeProtocol {
    Hyf,
    BitChat,
    Lxmf,
    Nostr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeVerificationState {
    Unverified,
    TransportSigned,
    PolicyVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeIngressMeta {
    pub origin_protocol: BridgeProtocol,
    pub verification_state: BridgeVerificationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeMessageKey {
    pub room_id: CommunityId,
    pub message_id: MessageId,
}

#[cfg(test)]
mod tests {
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, TimestampMs};

    use super::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeMessageKey, BridgeMessageRef,
        BridgePayloadKind,
    };

    #[test]
    fn bridge_types_preserve_fields_and_redact_debug_bytes() {
        let message = BridgeMessageRef {
            version: 0,
            room_id: CommunityId([1; 16]),
            message_id: MessageId([2; 32]),
            author: BridgeEndpointRef {
                kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::Nostr),
                id: b"secret-author",
            },
            created_at_ms: TimestampMs(1000),
            payload_kind: BridgePayloadKind::TextUtf8,
            payload: b"secret-payload",
        };
        let debug = format!("{message:?}");

        assert_eq!(
            BridgeMessageKey {
                room_id: message.room_id,
                message_id: message.message_id,
            },
            BridgeMessageKey {
                room_id: CommunityId([1; 16]),
                message_id: MessageId([2; 32]),
            }
        );
        assert!(debug.contains("BridgeMessageRef"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-author"));
        assert!(!debug.contains("secret-payload"));
    }
}
