use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use hyf_rns_core::{RnsIdentityHash, truncated_hash};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::RnsCryptoError;

pub const RNS_PUBLIC_IDENTITY_LEN: usize = 64;
pub const RNS_SECRET_IDENTITY_LEN: usize = 64;
pub const RNS_IDENTITY_KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnsPublicIdentity {
    pub x25519_public: [u8; RNS_IDENTITY_KEY_LEN],
    pub ed25519_public: [u8; RNS_IDENTITY_KEY_LEN],
}

pub struct RnsSecretIdentity {
    x25519_secret: Zeroizing<[u8; RNS_IDENTITY_KEY_LEN]>,
    ed25519_secret: Zeroizing<[u8; RNS_IDENTITY_KEY_LEN]>,
}

impl fmt::Debug for RnsSecretIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnsSecretIdentity")
            .field("x25519_secret", &"<redacted>")
            .field("ed25519_secret", &"<redacted>")
            .finish()
    }
}

impl RnsSecretIdentity {
    pub fn public_identity(&self) -> Result<RnsPublicIdentity, RnsCryptoError> {
        let x25519_secret = self.x25519_static_secret();
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let ed25519_signing_key = SigningKey::from_bytes(&self.ed25519_secret);
        let ed25519_public = ed25519_signing_key.verifying_key();

        Ok(RnsPublicIdentity {
            x25519_public: x25519_public.to_bytes(),
            ed25519_public: ed25519_public.to_bytes(),
        })
    }

    pub(crate) fn ed25519_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed25519_secret)
    }

    fn x25519_static_secret(&self) -> StaticSecret {
        let x25519_secret = Zeroizing::new(*self.x25519_secret);
        StaticSecret::from(*x25519_secret)
    }
}

pub fn public_identity_from_bytes(
    bytes: &[u8; RNS_PUBLIC_IDENTITY_LEN],
) -> Result<RnsPublicIdentity, RnsCryptoError> {
    let mut x25519_public = [0; RNS_IDENTITY_KEY_LEN];
    x25519_public.copy_from_slice(&bytes[..RNS_IDENTITY_KEY_LEN]);

    let mut ed25519_public = [0; RNS_IDENTITY_KEY_LEN];
    ed25519_public.copy_from_slice(&bytes[RNS_IDENTITY_KEY_LEN..]);

    VerifyingKey::from_bytes(&ed25519_public).map_err(|_| RnsCryptoError::InvalidPublicIdentity)?;

    Ok(RnsPublicIdentity {
        x25519_public,
        ed25519_public,
    })
}

pub fn secret_identity_from_bytes(
    bytes: &[u8; RNS_SECRET_IDENTITY_LEN],
) -> Result<RnsSecretIdentity, RnsCryptoError> {
    let mut x25519_secret = [0; RNS_IDENTITY_KEY_LEN];
    x25519_secret.copy_from_slice(&bytes[..RNS_IDENTITY_KEY_LEN]);

    let mut ed25519_secret = [0; RNS_IDENTITY_KEY_LEN];
    ed25519_secret.copy_from_slice(&bytes[RNS_IDENTITY_KEY_LEN..]);

    let identity = RnsSecretIdentity {
        x25519_secret: Zeroizing::new(x25519_secret),
        ed25519_secret: Zeroizing::new(ed25519_secret),
    };
    identity.public_identity()?;
    Ok(identity)
}

pub fn public_identity_to_bytes(identity: &RnsPublicIdentity) -> [u8; RNS_PUBLIC_IDENTITY_LEN] {
    let mut bytes = [0; RNS_PUBLIC_IDENTITY_LEN];
    bytes[..RNS_IDENTITY_KEY_LEN].copy_from_slice(&identity.x25519_public);
    bytes[RNS_IDENTITY_KEY_LEN..].copy_from_slice(&identity.ed25519_public);
    bytes
}

pub fn identity_hash(identity: &RnsPublicIdentity) -> RnsIdentityHash {
    let public_identity = public_identity_to_bytes(identity);
    RnsIdentityHash::new(truncated_hash(&public_identity).into_bytes())
}

pub(crate) fn ed25519_verifying_key(
    identity: &RnsPublicIdentity,
) -> Result<VerifyingKey, RnsCryptoError> {
    VerifyingKey::from_bytes(&identity.ed25519_public)
        .map_err(|_| RnsCryptoError::InvalidPublicIdentity)
}

#[cfg(test)]
mod tests {
    use super::{
        RNS_PUBLIC_IDENTITY_LEN, RNS_SECRET_IDENTITY_LEN, identity_hash,
        public_identity_from_bytes, public_identity_to_bytes, secret_identity_from_bytes,
    };

    const TEST_SECRET_IDENTITY_BYTES: [u8; RNS_SECRET_IDENTITY_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    const TEST_PUBLIC_IDENTITY_BYTES: [u8; RNS_PUBLIC_IDENTITY_LEN] = [
        0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2, 0x14, 0xea, 0x76, 0x7a,
        0x6e, 0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b, 0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38,
        0x28, 0x5f, 0x29, 0xac, 0xba, 0xe1, 0x41, 0xbc, 0xca, 0xf0, 0xb2, 0x2e, 0x1a, 0x94, 0xd3,
        0x4d, 0x0b, 0xc7, 0x36, 0x1e, 0x52, 0x6d, 0x0b, 0xfe, 0x12, 0xc8, 0x97, 0x94, 0xbc, 0x93,
        0x22, 0x96, 0x6d, 0xd7,
    ];

    const TEST_IDENTITY_HASH_BYTES: [u8; 16] = [
        0xac, 0xa3, 0x1a, 0xf0, 0x44, 0x1d, 0x81, 0xdb, 0xec, 0x71, 0xe8, 0x2d, 0xa0, 0xb4, 0xb5,
        0xf5,
    ];

    #[test]
    fn secret_identity_derives_public_identity() {
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES);

        assert_eq!(
            secret.and_then(|identity| identity.public_identity()),
            public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)
        );
    }

    #[test]
    fn public_identity_round_trips_bytes() {
        let identity = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES);

        assert_eq!(
            identity.map(|identity| public_identity_to_bytes(&identity)),
            Ok(TEST_PUBLIC_IDENTITY_BYTES)
        );
    }

    #[test]
    fn identity_hash_matches_deterministic_vector() {
        let identity = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES);

        assert_eq!(
            identity.map(|identity| identity_hash(&identity).into_bytes()),
            Ok(TEST_IDENTITY_HASH_BYTES)
        );
    }
}
