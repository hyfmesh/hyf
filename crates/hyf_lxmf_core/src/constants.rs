pub const LXMF_DESTINATION_HASH_LEN: usize = 16;
pub const LXMF_SOURCE_HASH_LEN: usize = 16;
pub const LXMF_SIGNATURE_LEN: usize = 64;
pub const LXMF_MESSAGE_ID_LEN: usize = 32;
pub const LXMF_FIXED_HEADER_LEN: usize =
    LXMF_DESTINATION_HASH_LEN + LXMF_SOURCE_HASH_LEN + LXMF_SIGNATURE_LEN;
pub const LXMF_MESSAGE_MAX_LEN: usize = 4096;
pub const LXMF_PAYLOAD_MAX_LEN: usize = LXMF_MESSAGE_MAX_LEN - LXMF_FIXED_HEADER_LEN;
pub const LXMF_MSGPACK_MAX_DEPTH: usize = 16;
pub const LXMF_TITLE_MAX_LEN: usize = 2048;
pub const LXMF_CONTENT_MAX_LEN: usize = 2048;
pub const LXMF_FIELDS_MAX_LEN: usize = 1024;
pub const LXMF_STAMP_MAX_LEN: usize = 128;

#[cfg(test)]
mod tests {
    use super::{
        LXMF_CONTENT_MAX_LEN, LXMF_DESTINATION_HASH_LEN, LXMF_FIELDS_MAX_LEN,
        LXMF_FIXED_HEADER_LEN, LXMF_MESSAGE_ID_LEN, LXMF_MESSAGE_MAX_LEN, LXMF_MSGPACK_MAX_DEPTH,
        LXMF_PAYLOAD_MAX_LEN, LXMF_SIGNATURE_LEN, LXMF_SOURCE_HASH_LEN, LXMF_STAMP_MAX_LEN,
        LXMF_TITLE_MAX_LEN,
    };

    #[test]
    fn lxmf_fixed_lengths_are_stable() {
        assert_eq!(LXMF_DESTINATION_HASH_LEN, 16);
        assert_eq!(LXMF_SOURCE_HASH_LEN, 16);
        assert_eq!(LXMF_SIGNATURE_LEN, 64);
        assert_eq!(LXMF_MESSAGE_ID_LEN, 32);
        assert_eq!(LXMF_FIXED_HEADER_LEN, 96);
    }

    #[test]
    fn lxmf_size_limits_use_approved_poc_values() {
        assert_eq!(LXMF_MESSAGE_MAX_LEN, 4096);
        assert_eq!(LXMF_PAYLOAD_MAX_LEN, 4096 - LXMF_FIXED_HEADER_LEN);
        assert_eq!(LXMF_MSGPACK_MAX_DEPTH, 16);
        assert_eq!(LXMF_TITLE_MAX_LEN, 2048);
        assert_eq!(LXMF_CONTENT_MAX_LEN, 2048);
        assert_eq!(LXMF_FIELDS_MAX_LEN, 1024);
        assert_eq!(LXMF_STAMP_MAX_LEN, 128);
    }
}
