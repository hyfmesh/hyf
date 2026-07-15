pub const BITCHAT_V1_HEADER_LEN: usize = 14;
pub const BITCHAT_V2_HEADER_LEN: usize = 16;
pub const BITCHAT_PEER_ID_LEN: usize = 8;
pub const BITCHAT_SIGNATURE_LEN: usize = 64;
pub const BITCHAT_ROUTE_MAX_HOPS: usize = 16;
pub const BITCHAT_CORE_PACKET_MAX_LEN: usize = 2048;
pub const BITCHAT_CARRIER_PACKET_MAX_LEN: usize = 1536;
pub const BITCHAT_PAYLOAD_MAX_LEN: usize = 1536;

#[cfg(test)]
mod tests {
    use super::{
        BITCHAT_CARRIER_PACKET_MAX_LEN, BITCHAT_CORE_PACKET_MAX_LEN, BITCHAT_PAYLOAD_MAX_LEN,
        BITCHAT_PEER_ID_LEN, BITCHAT_ROUTE_MAX_HOPS, BITCHAT_SIGNATURE_LEN, BITCHAT_V1_HEADER_LEN,
        BITCHAT_V2_HEADER_LEN,
    };

    #[test]
    fn constants_match_bitchat_contract() {
        assert_eq!(BITCHAT_V1_HEADER_LEN, 14);
        assert_eq!(BITCHAT_V2_HEADER_LEN, 16);
        assert_eq!(BITCHAT_PEER_ID_LEN, 8);
        assert_eq!(BITCHAT_SIGNATURE_LEN, 64);
        assert_eq!(BITCHAT_ROUTE_MAX_HOPS, 16);
        assert_eq!(BITCHAT_CORE_PACKET_MAX_LEN, 2048);
        assert_eq!(BITCHAT_CARRIER_PACKET_MAX_LEN, 1536);
        assert_eq!(BITCHAT_PAYLOAD_MAX_LEN, 1536);
    }
}
