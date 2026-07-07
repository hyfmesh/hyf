pub type RnsFullHash = [u8; 32];
pub type RnsTruncatedHash = [u8; 16];
pub type RnsNameHash = [u8; 10];
pub type RnsDestinationHash = [u8; 16];
pub type RnsIdentityHash = [u8; 16];

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{RnsDestinationHash, RnsFullHash, RnsIdentityHash, RnsNameHash, RnsTruncatedHash};

    #[test]
    fn rns_hash_type_sizes_are_stable() {
        assert_eq!(size_of::<RnsFullHash>(), 32);
        assert_eq!(size_of::<RnsTruncatedHash>(), 16);
        assert_eq!(size_of::<RnsNameHash>(), 10);
        assert_eq!(size_of::<RnsDestinationHash>(), 16);
        assert_eq!(size_of::<RnsIdentityHash>(), 16);
    }
}
