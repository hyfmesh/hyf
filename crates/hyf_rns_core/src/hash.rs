use sha2::{Digest, Sha256};

use crate::{RnsFullHash, RnsTruncatedHash};

pub fn full_hash(data: &[u8]) -> RnsFullHash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    RnsFullHash::new(hasher.finalize().into())
}

pub fn truncated_hash(data: &[u8]) -> RnsTruncatedHash {
    let full = full_hash(data).into_bytes();
    let mut truncated = [0; RnsTruncatedHash::LEN];
    truncated.copy_from_slice(&full[..RnsTruncatedHash::LEN]);
    RnsTruncatedHash::new(truncated)
}

#[cfg(test)]
mod tests {
    use super::{full_hash, truncated_hash};

    const EMPTY_SHA256: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    const ABC_SHA256: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    #[test]
    fn full_hash_matches_known_vectors() {
        assert_eq!(full_hash(b""), EMPTY_SHA256.into());
        assert_eq!(full_hash(b"abc"), ABC_SHA256.into());
    }

    #[test]
    fn truncated_hash_is_first_sixteen_bytes() {
        let mut empty_truncated = [0; 16];
        empty_truncated.copy_from_slice(&EMPTY_SHA256[..16]);

        let mut abc_truncated = [0; 16];
        abc_truncated.copy_from_slice(&ABC_SHA256[..16]);

        assert_eq!(truncated_hash(b""), empty_truncated.into());
        assert_eq!(truncated_hash(b"abc"), abc_truncated.into());
    }
}
