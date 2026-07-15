use core::fmt;

use crate::{BITCHAT_PEER_ID_LEN, BITCHAT_SIGNATURE_LEN};

macro_rules! bitchat_fixed_type {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn into_bytes(self) -> [u8; $len] {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("bytes", &"<redacted>")
                    .field("len", &$len)
                    .finish()
            }
        }
    };
}

bitchat_fixed_type!(BitchatPeerId, BITCHAT_PEER_ID_LEN);
bitchat_fixed_type!(BitchatSignature, BITCHAT_SIGNATURE_LEN);

#[cfg(test)]
mod tests {
    use super::{BitchatPeerId, BitchatSignature};

    #[test]
    fn fixed_types_preserve_bytes() {
        let peer_id = BitchatPeerId::from_bytes([1; 8]);
        let signature = BitchatSignature::from_bytes([2; 64]);

        assert_eq!(peer_id.as_bytes(), &[1; 8]);
        assert_eq!(peer_id.into_bytes(), [1; 8]);
        assert_eq!(signature.as_bytes(), &[2; 64]);
        assert_eq!(signature.into_bytes(), [2; 64]);
    }

    #[test]
    fn fixed_type_debug_redacts_bytes() {
        let peer_id = BitchatPeerId::from_bytes([7; 8]);
        let signature = BitchatSignature::from_bytes([9; 64]);
        let peer_debug = format!("{peer_id:?}");
        let signature_debug = format!("{signature:?}");

        assert!(peer_debug.contains("BitchatPeerId"));
        assert!(peer_debug.contains("<redacted>"));
        assert!(!peer_debug.contains("7, 7"));
        assert!(signature_debug.contains("BitchatSignature"));
        assert!(signature_debug.contains("<redacted>"));
        assert!(!signature_debug.contains("9, 9"));
    }
}
