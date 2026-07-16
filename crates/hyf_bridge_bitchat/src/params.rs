use hyf_bitchat_core::{BITCHAT_CORE_PACKET_MAX_LEN, BitchatPeerId};
use hyf_core::{CommunityId, MessageId};

pub const BITCHAT_BRIDGE_PACKET_MAX_LEN: usize = BITCHAT_CORE_PACKET_MAX_LEN;
pub const BITCHAT_BRIDGE_DEFAULT_TTL: u8 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitchatBridgeIngressParams {
    pub room_id: CommunityId,
    pub message_id: MessageId,
}

impl BitchatBridgeIngressParams {
    pub const fn new(room_id: CommunityId, message_id: MessageId) -> Self {
        Self {
            room_id,
            message_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitchatBridgeEgressParams {
    pub sender_id: BitchatPeerId,
    pub ttl: u8,
}

impl BitchatBridgeEgressParams {
    pub const fn new(sender_id: BitchatPeerId) -> Self {
        Self {
            sender_id,
            ttl: BITCHAT_BRIDGE_DEFAULT_TTL,
        }
    }

    pub const fn with_ttl(sender_id: BitchatPeerId, ttl: u8) -> Self {
        Self { sender_id, ttl }
    }
}

#[cfg(test)]
mod tests {
    use hyf_bitchat_core::BitchatPeerId;
    use hyf_core::{CommunityId, MessageId};

    use super::{
        BITCHAT_BRIDGE_DEFAULT_TTL, BITCHAT_BRIDGE_PACKET_MAX_LEN, BitchatBridgeEgressParams,
        BitchatBridgeIngressParams,
    };

    #[test]
    fn params_preserve_fields() {
        let ingress = BitchatBridgeIngressParams::new(CommunityId([1; 16]), MessageId([2; 32]));
        let egress = BitchatBridgeEgressParams::new(BitchatPeerId::from_bytes([3; 8]));

        assert_eq!(ingress.room_id, CommunityId([1; 16]));
        assert_eq!(ingress.message_id, MessageId([2; 32]));
        assert_eq!(egress.sender_id, BitchatPeerId::from_bytes([3; 8]));
        assert_eq!(egress.ttl, BITCHAT_BRIDGE_DEFAULT_TTL);
        assert_eq!(BITCHAT_BRIDGE_PACKET_MAX_LEN, 2048);
        assert_eq!(
            BitchatBridgeEgressParams::with_ttl(BitchatPeerId::from_bytes([4; 8]), 3).ttl,
            3
        );
    }
}
