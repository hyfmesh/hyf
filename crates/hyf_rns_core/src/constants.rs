pub const RNS_MTU: usize = 500;
pub const RNS_TRUNCATED_HASH_LEN: usize = 16;
pub const RNS_NAME_HASH_LEN: usize = 10;
pub const RNS_HEADER_1_LEN: usize = 19;
pub const RNS_HEADER_2_LEN: usize = 35;
pub const RNS_MDU: usize = 464;

#[cfg(test)]
mod tests {
    use super::{
        RNS_HEADER_1_LEN, RNS_HEADER_2_LEN, RNS_MDU, RNS_MTU, RNS_NAME_HASH_LEN,
        RNS_TRUNCATED_HASH_LEN,
    };

    #[test]
    fn constants_match_profile0() {
        assert_eq!(RNS_MTU, 500);
        assert_eq!(RNS_TRUNCATED_HASH_LEN, 16);
        assert_eq!(RNS_NAME_HASH_LEN, 10);
        assert_eq!(RNS_HEADER_1_LEN, 19);
        assert_eq!(RNS_HEADER_2_LEN, 35);
        assert_eq!(RNS_MDU, 464);
    }
}
