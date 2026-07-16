use core::fmt;

use hyf_bridge_core::BridgeMessageKey;
use hyf_wire::HyfEnvelopeRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeDropReason {
    Duplicate,
    LoopPrevented,
    UnsupportedProfile,
    OutputTooSmall,
    MalformedInput,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum BridgeRuntimeCommand<'a> {
    EmitHyfEnvelope(HyfEnvelopeRef<'a>),
    EmitBitChatPacket(&'a [u8]),
    EmitLxmfMessage(&'a [u8]),
    EmitNostrEvent(&'a [u8]),
    Drop {
        key: BridgeMessageKey,
        reason: BridgeDropReason,
    },
}

impl fmt::Debug for BridgeRuntimeCommand<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmitHyfEnvelope(envelope) => formatter
                .debug_tuple("EmitHyfEnvelope")
                .field(envelope)
                .finish(),
            Self::EmitBitChatPacket(packet) => formatter
                .debug_struct("EmitBitChatPacket")
                .field("packet", &"<redacted>")
                .field("packet_len", &packet.len())
                .finish(),
            Self::EmitLxmfMessage(message) => formatter
                .debug_struct("EmitLxmfMessage")
                .field("message", &"<redacted>")
                .field("message_len", &message.len())
                .finish(),
            Self::EmitNostrEvent(event) => formatter
                .debug_struct("EmitNostrEvent")
                .field("event", &"<redacted>")
                .field("event_len", &event.len())
                .finish(),
            Self::Drop { key, reason } => formatter
                .debug_struct("Drop")
                .field("key", key)
                .field("reason", reason)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::BridgeMessageKey;
    use hyf_core::{CommunityId, MessageId};

    use super::{BridgeDropReason, BridgeRuntimeCommand};

    #[test]
    fn command_debug_redacts_packet_bytes() {
        let command = BridgeRuntimeCommand::EmitBitChatPacket(b"secret-payload");
        let debug = format!("{command:?}");

        assert!(debug.contains("EmitBitChatPacket"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("packet_len"));
        assert!(!debug.contains("secret-payload"));

        let command = BridgeRuntimeCommand::EmitNostrEvent(br#"{"content":"secret-payload"}"#);
        let debug = format!("{command:?}");

        assert!(debug.contains("EmitNostrEvent"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("event_len"));
        assert!(!debug.contains("secret-payload"));
    }

    #[test]
    fn drop_command_preserves_key_and_reason() {
        let key = BridgeMessageKey {
            room_id: CommunityId([1; 16]),
            message_id: MessageId([2; 32]),
        };
        let command = BridgeRuntimeCommand::Drop {
            key,
            reason: BridgeDropReason::LoopPrevented,
        };

        assert_eq!(
            command,
            BridgeRuntimeCommand::Drop {
                key,
                reason: BridgeDropReason::LoopPrevented,
            }
        );
    }
}
