pub const HYF_BRIDGE_MESSAGE_VERSION_0: u8 = 0;
pub const HYF_BRIDGE_AUTHOR_ID_MAX_LEN: usize = 32;
pub const HYF_BRIDGE_HYF_NODE_AUTHOR_ID_LEN: usize = 32;
pub const HYF_BRIDGE_BITCHAT_AUTHOR_ID_LEN: usize = 8;
pub const HYF_BRIDGE_LXMF_AUTHOR_ID_LEN: usize = 16;
pub const HYF_BRIDGE_NOSTR_AUTHOR_ID_LEN: usize = 32;
pub const HYF_BRIDGE_PAYLOAD_MAX_LEN: usize = 1024;
pub const HYF_BRIDGE_MESSAGE_MAX_LEN: usize = 1536;

#[cfg(test)]
mod tests {
    use super::{
        HYF_BRIDGE_AUTHOR_ID_MAX_LEN, HYF_BRIDGE_BITCHAT_AUTHOR_ID_LEN,
        HYF_BRIDGE_HYF_NODE_AUTHOR_ID_LEN, HYF_BRIDGE_LXMF_AUTHOR_ID_LEN,
        HYF_BRIDGE_MESSAGE_MAX_LEN, HYF_BRIDGE_MESSAGE_VERSION_0, HYF_BRIDGE_NOSTR_AUTHOR_ID_LEN,
        HYF_BRIDGE_PAYLOAD_MAX_LEN,
    };

    #[test]
    fn constants_match_bridge_contract() {
        assert_eq!(HYF_BRIDGE_MESSAGE_VERSION_0, 0);
        assert_eq!(HYF_BRIDGE_AUTHOR_ID_MAX_LEN, 32);
        assert_eq!(HYF_BRIDGE_HYF_NODE_AUTHOR_ID_LEN, 32);
        assert_eq!(HYF_BRIDGE_BITCHAT_AUTHOR_ID_LEN, 8);
        assert_eq!(HYF_BRIDGE_LXMF_AUTHOR_ID_LEN, 16);
        assert_eq!(HYF_BRIDGE_NOSTR_AUTHOR_ID_LEN, 32);
        assert_eq!(HYF_BRIDGE_PAYLOAD_MAX_LEN, 1024);
        assert_eq!(HYF_BRIDGE_MESSAGE_MAX_LEN, 1536);
    }
}
