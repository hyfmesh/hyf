macro_rules! rns_hash_type {
    ($name:ident, $len:literal) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; $len] {
                self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self::new(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(hash: $name) -> Self {
                hash.into_bytes()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
    };
}

rns_hash_type!(RnsFullHash, 32);
rns_hash_type!(RnsTruncatedHash, 16);
rns_hash_type!(RnsNameHash, 10);
rns_hash_type!(RnsDestinationHash, 16);
rns_hash_type!(RnsIdentityHash, 16);

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

    #[test]
    fn rns_hash_types_preserve_fixed_bytes() {
        let full = RnsFullHash::new([1; RnsFullHash::LEN]);
        let truncated = RnsTruncatedHash::new([2; RnsTruncatedHash::LEN]);
        let name = RnsNameHash::new([3; RnsNameHash::LEN]);
        let destination = RnsDestinationHash::new([4; RnsDestinationHash::LEN]);
        let identity = RnsIdentityHash::new([5; RnsIdentityHash::LEN]);

        assert_eq!(full.as_bytes(), &[1; 32]);
        assert_eq!(truncated.into_bytes(), [2; 16]);
        assert_eq!(name.as_ref(), &[3; 10]);
        assert_eq!(destination.as_bytes(), &[4; 16]);
        assert_eq!(identity.into_bytes(), [5; 16]);
    }
}
