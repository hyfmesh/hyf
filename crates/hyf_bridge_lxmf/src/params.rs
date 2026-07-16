use hyf_core::{CommunityId, MessageId};
use hyf_lxmf_core::{LXMF_MESSAGE_MAX_LEN, LxmfDestinationHash, LxmfSignature, LxmfSourceHash};

pub const LXMF_BRIDGE_MESSAGE_MAX_LEN: usize = LXMF_MESSAGE_MAX_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LxmfBridgeIngressParams {
    pub room_id: CommunityId,
    pub message_id: MessageId,
}

impl LxmfBridgeIngressParams {
    pub const fn new(room_id: CommunityId, message_id: MessageId) -> Self {
        Self {
            room_id,
            message_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LxmfBridgeEgressParams {
    pub destination_hash: LxmfDestinationHash,
    pub source_hash: LxmfSourceHash,
    pub signature: LxmfSignature,
}

impl LxmfBridgeEgressParams {
    pub const fn new(
        destination_hash: LxmfDestinationHash,
        source_hash: LxmfSourceHash,
        signature: LxmfSignature,
    ) -> Self {
        Self {
            destination_hash,
            source_hash,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::{CommunityId, MessageId};
    use hyf_lxmf_core::{LxmfDestinationHash, LxmfSignature, LxmfSourceHash};

    use super::{LXMF_BRIDGE_MESSAGE_MAX_LEN, LxmfBridgeEgressParams, LxmfBridgeIngressParams};

    #[test]
    fn params_preserve_fields() {
        let ingress = LxmfBridgeIngressParams::new(CommunityId([1; 16]), MessageId([2; 32]));
        let egress = LxmfBridgeEgressParams::new(
            LxmfDestinationHash::from_bytes([3; 16]),
            LxmfSourceHash::from_bytes([4; 16]),
            LxmfSignature::from_bytes([5; 64]),
        );

        assert_eq!(ingress.room_id, CommunityId([1; 16]));
        assert_eq!(ingress.message_id, MessageId([2; 32]));
        assert_eq!(egress.destination_hash.as_bytes(), &[3; 16]);
        assert_eq!(egress.source_hash.as_bytes(), &[4; 16]);
        assert_eq!(egress.signature.as_bytes(), &[5; 64]);
        assert_eq!(LXMF_BRIDGE_MESSAGE_MAX_LEN, 4096);
    }
}
