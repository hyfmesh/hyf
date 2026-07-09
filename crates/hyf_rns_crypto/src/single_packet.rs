use rand_core::TryCryptoRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[cfg(any(test, feature = "test_vectors"))]
use crate::token_encrypt_with_iv;
use crate::{
    RNS_IDENTITY_KEY_LEN, RnsCryptoError, RnsPublicIdentity, RnsSecretIdentity, identity_hash,
    pkcs7_padded_len, rns_hkdf_sha256, token_decrypt, token_encrypt,
};

pub const RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN: usize = RNS_IDENTITY_KEY_LEN;
pub const RNS_SINGLE_PACKET_DERIVED_KEY_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnsRatchetSecretRef<'a> {
    secret: &'a [u8; RNS_IDENTITY_KEY_LEN],
}

impl<'a> RnsRatchetSecretRef<'a> {
    pub const fn new(secret: &'a [u8; RNS_IDENTITY_KEY_LEN]) -> Self {
        Self { secret }
    }

    pub const fn as_bytes(&self) -> &'a [u8; RNS_IDENTITY_KEY_LEN] {
        self.secret
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RnsDecryptOutcome<'a> {
    pub plaintext: &'a [u8],
    pub ratchet_index: Option<usize>,
}

impl<'a> RnsDecryptOutcome<'a> {
    pub const fn plaintext(&self) -> &'a [u8] {
        self.plaintext
    }

    pub const fn ratchet_index(&self) -> Option<usize> {
        self.ratchet_index
    }
}

pub fn encrypt_for_identity<R>(
    recipient: &RnsPublicIdentity,
    plaintext: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<usize, RnsCryptoError>
where
    R: TryCryptoRng + ?Sized,
{
    let mut ephemeral_secret = Zeroizing::new([0; RNS_IDENTITY_KEY_LEN]);
    rng.try_fill_bytes(&mut ephemeral_secret[..])
        .map_err(|_| RnsCryptoError::RandomSourceFailed)?;

    encrypt_with_secret(
        recipient,
        plaintext,
        *ephemeral_secret,
        out,
        |key, plaintext, out| token_encrypt(key, plaintext, rng, out),
    )
}

#[cfg(any(test, feature = "test_vectors"))]
pub fn encrypt_for_identity_with_ephemeral_and_iv(
    recipient: &RnsPublicIdentity,
    plaintext: &[u8],
    ephemeral_secret: [u8; RNS_IDENTITY_KEY_LEN],
    iv: [u8; crate::RNS_TOKEN_IV_LEN],
    out: &mut [u8],
) -> Result<usize, RnsCryptoError> {
    encrypt_with_secret(
        recipient,
        plaintext,
        ephemeral_secret,
        out,
        |key, plaintext, out| token_encrypt_with_iv(key, plaintext, iv, out),
    )
}

#[cfg(any(test, feature = "test_vectors"))]
pub fn derive_identity_token_key_for_test_vectors(
    recipient: &RnsPublicIdentity,
    ephemeral_secret: [u8; RNS_IDENTITY_KEY_LEN],
) -> Result<[u8; RNS_SINGLE_PACKET_DERIVED_KEY_LEN], RnsCryptoError> {
    let ephemeral_secret = StaticSecret::from(ephemeral_secret);
    let recipient_public = X25519PublicKey::from(recipient.x25519_public);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    let key = derive_token_key(&shared, recipient)?;
    Ok(*key)
}

pub fn decrypt_for_identity<'a>(
    recipient: &RnsSecretIdentity,
    ciphertext_token: &[u8],
    ratchets: &[RnsRatchetSecretRef<'_>],
    enforce_ratchets: bool,
    out: &'a mut [u8],
) -> Result<RnsDecryptOutcome<'a>, RnsCryptoError> {
    if ciphertext_token.len() <= RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN {
        return Err(RnsCryptoError::InvalidToken);
    }

    let recipient_public = recipient.public_identity()?;
    let ephemeral_public = parse_ephemeral_public(ciphertext_token)?;
    let token = &ciphertext_token[RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN..];

    for (index, ratchet) in ratchets.iter().enumerate() {
        let ratchet_secret = StaticSecret::from(*ratchet.as_bytes());
        match decrypt_with_secret_len(
            &ratchet_secret,
            &recipient_public,
            &ephemeral_public,
            token,
            out,
        ) {
            Ok(plaintext_len) => {
                return Ok(RnsDecryptOutcome {
                    plaintext: &out[..plaintext_len],
                    ratchet_index: Some(index),
                });
            }
            Err(RnsCryptoError::AuthenticationFailed) => {}
            Err(error) => return Err(error),
        }
    }

    if enforce_ratchets {
        return Err(RnsCryptoError::AuthenticationFailed);
    }

    let identity_secret = recipient.x25519_static_secret();
    let plaintext_len = decrypt_with_secret_len(
        &identity_secret,
        &recipient_public,
        &ephemeral_public,
        token,
        out,
    )?;

    Ok(RnsDecryptOutcome {
        plaintext: &out[..plaintext_len],
        ratchet_index: None,
    })
}

fn encrypt_with_secret(
    recipient: &RnsPublicIdentity,
    plaintext: &[u8],
    ephemeral_secret: [u8; RNS_IDENTITY_KEY_LEN],
    out: &mut [u8],
    token_encryptor: impl FnOnce(&[u8], &[u8], &mut [u8]) -> Result<usize, RnsCryptoError>,
) -> Result<usize, RnsCryptoError> {
    let required = single_packet_len_for_plaintext(plaintext.len())?;
    if out.len() < required {
        return Err(RnsCryptoError::OutputBufferTooShort {
            actual: out.len(),
            required,
        });
    }

    let ephemeral_secret = StaticSecret::from(ephemeral_secret);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_public = X25519PublicKey::from(recipient.x25519_public);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    let key = derive_token_key(&shared, recipient)?;

    out[..RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN].copy_from_slice(ephemeral_public.as_bytes());
    let token_len = token_encryptor(
        &key[..],
        plaintext,
        &mut out[RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN..required],
    )?;
    Ok(RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN + token_len)
}

fn decrypt_with_secret_len(
    secret: &StaticSecret,
    recipient: &RnsPublicIdentity,
    ephemeral_public: &X25519PublicKey,
    token: &[u8],
    out: &mut [u8],
) -> Result<usize, RnsCryptoError> {
    let shared = secret.diffie_hellman(ephemeral_public);
    let key = derive_token_key(&shared, recipient)?;
    token_decrypt(&key[..], token, out)
}

fn parse_ephemeral_public(ciphertext_token: &[u8]) -> Result<X25519PublicKey, RnsCryptoError> {
    let mut public = [0; RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN];
    public.copy_from_slice(&ciphertext_token[..RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN]);
    Ok(X25519PublicKey::from(public))
}

fn derive_token_key(
    shared: &x25519_dalek::SharedSecret,
    recipient: &RnsPublicIdentity,
) -> Result<Zeroizing<[u8; RNS_SINGLE_PACKET_DERIVED_KEY_LEN]>, RnsCryptoError> {
    if !shared.was_contributory() {
        return Err(RnsCryptoError::InvalidPublicIdentity);
    }

    let salt = identity_hash(recipient);
    let mut key = Zeroizing::new([0; RNS_SINGLE_PACKET_DERIVED_KEY_LEN]);
    rns_hkdf_sha256(&mut key[..], shared.as_bytes(), Some(salt.as_bytes()), None)?;
    Ok(key)
}

fn single_packet_len_for_plaintext(plaintext_len: usize) -> Result<usize, RnsCryptoError> {
    let token_ciphertext_len = pkcs7_padded_len(plaintext_len)?;
    let token_len = crate::RNS_TOKEN_OVERHEAD
        .checked_add(token_ciphertext_len)
        .ok_or(RnsCryptoError::LengthOverflow)?;

    RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN
        .checked_add(token_len)
        .ok_or(RnsCryptoError::LengthOverflow)
}

#[cfg(test)]
mod tests {
    use super::{
        RNS_SINGLE_PACKET_DERIVED_KEY_LEN, RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN,
        RnsRatchetSecretRef, decrypt_for_identity, derive_token_key, encrypt_for_identity,
        encrypt_for_identity_with_ephemeral_and_iv,
    };
    use crate::{
        RNS_SECRET_IDENTITY_LEN, RNS_TOKEN_HMAC_LEN, RNS_TOKEN_IV_LEN, RnsCryptoError,
        public_identity_from_bytes, secret_identity_from_bytes,
        token::token_retag_for_test_vectors,
    };
    use rand_core::{Infallible, TryCryptoRng, TryRng};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    const TEST_SECRET_IDENTITY_BYTES: [u8; RNS_SECRET_IDENTITY_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];
    const TEST_PUBLIC_IDENTITY_BYTES: [u8; 64] = [
        0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2, 0x14, 0xea, 0x76, 0x7a,
        0x6e, 0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b, 0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38,
        0x28, 0x5f, 0x29, 0xac, 0xba, 0xe1, 0x41, 0xbc, 0xca, 0xf0, 0xb2, 0x2e, 0x1a, 0x94, 0xd3,
        0x4d, 0x0b, 0xc7, 0x36, 0x1e, 0x52, 0x6d, 0x0b, 0xfe, 0x12, 0xc8, 0x97, 0x94, 0xbc, 0x93,
        0x22, 0x96, 0x6d, 0xd7,
    ];
    const EPHEMERAL_SECRET: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];
    const IV: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const PLAINTEXT: &[u8] = b"hello identity";

    #[test]
    fn deterministic_identity_encryption_roundtrips() -> Result<(), RnsCryptoError> {
        let public = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let mut ciphertext = [0; 128];
        let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
            &public,
            PLAINTEXT,
            EPHEMERAL_SECRET,
            IV,
            &mut ciphertext,
        )?;
        let mut plaintext = [0; 64];
        let outcome = decrypt_for_identity(
            &secret,
            &ciphertext[..ciphertext_len],
            &[],
            false,
            &mut plaintext,
        )?;

        assert_eq!(outcome.plaintext(), PLAINTEXT);
        assert_eq!(outcome.ratchet_index(), None);
        assert_eq!(
            ciphertext_len,
            RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN + crate::RNS_TOKEN_OVERHEAD + 16
        );
        assert_eq!(RNS_SINGLE_PACKET_DERIVED_KEY_LEN, 64);
        Ok(())
    }

    #[test]
    fn public_identity_encryption_uses_caller_rng() -> Result<(), RnsCryptoError> {
        let public = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
        let mut deterministic = [0; 128];
        let deterministic_len = encrypt_for_identity_with_ephemeral_and_iv(
            &public,
            PLAINTEXT,
            EPHEMERAL_SECRET,
            IV,
            &mut deterministic,
        )?;
        let mut rng = FixedRng::new();
        let mut random_path = [0; 128];
        let random_path_len = encrypt_for_identity(&public, PLAINTEXT, &mut rng, &mut random_path)?;

        assert_eq!(random_path_len, deterministic_len);
        assert_eq!(
            &random_path[..random_path_len],
            &deterministic[..deterministic_len]
        );
        Ok(())
    }

    #[test]
    fn decrypt_falls_back_to_identity_when_ratchets_are_not_enforced() -> Result<(), RnsCryptoError>
    {
        let public = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let wrong_ratchet = [0x99; 32];
        let ratchets = [RnsRatchetSecretRef::new(&wrong_ratchet)];
        let mut ciphertext = [0; 128];
        let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
            &public,
            PLAINTEXT,
            EPHEMERAL_SECRET,
            IV,
            &mut ciphertext,
        )?;
        let mut plaintext = [0; 64];
        let outcome = decrypt_for_identity(
            &secret,
            &ciphertext[..ciphertext_len],
            &ratchets,
            false,
            &mut plaintext,
        )?;

        assert_eq!(outcome.plaintext(), PLAINTEXT);
        assert_eq!(outcome.ratchet_index(), None);
        Ok(())
    }

    #[test]
    fn decrypt_rejects_enforced_empty_ratchets() -> Result<(), RnsCryptoError> {
        let public = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let mut ciphertext = [0; 128];
        let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
            &public,
            PLAINTEXT,
            EPHEMERAL_SECRET,
            IV,
            &mut ciphertext,
        )?;
        let mut plaintext = [0; 64];

        assert_eq!(
            decrypt_for_identity(
                &secret,
                &ciphertext[..ciphertext_len],
                &[],
                true,
                &mut plaintext,
            ),
            Err(RnsCryptoError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn decrypt_rejects_short_ciphertext() -> Result<(), RnsCryptoError> {
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let mut plaintext = [0; 64];

        assert_eq!(
            decrypt_for_identity(
                &secret,
                &[0; RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN],
                &[],
                false,
                &mut plaintext,
            ),
            Err(RnsCryptoError::InvalidToken)
        );
        Ok(())
    }

    #[test]
    fn decrypt_rejects_noncontributory_ephemeral_key() -> Result<(), RnsCryptoError> {
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let mut ciphertext = [0; RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN + 64];
        let mut plaintext = [0; 64];

        assert_eq!(
            decrypt_for_identity(&secret, &ciphertext, &[], false, &mut plaintext),
            Err(RnsCryptoError::InvalidPublicIdentity)
        );
        ciphertext[RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN] = 1;
        assert_eq!(
            decrypt_for_identity(&secret, &ciphertext, &[], false, &mut plaintext),
            Err(RnsCryptoError::InvalidPublicIdentity)
        );
        Ok(())
    }

    #[test]
    fn decrypt_rejects_short_output_without_writing_plaintext() -> Result<(), RnsCryptoError> {
        let public = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let mut ciphertext = [0; 128];
        let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
            &public,
            PLAINTEXT,
            EPHEMERAL_SECRET,
            IV,
            &mut ciphertext,
        )?;
        let mut plaintext = [0x55; 4];

        assert_eq!(
            decrypt_for_identity(
                &secret,
                &ciphertext[..ciphertext_len],
                &[],
                false,
                &mut plaintext,
            ),
            Err(RnsCryptoError::OutputBufferTooShort {
                actual: 4,
                required: 16
            })
        );
        assert_eq!(plaintext, [0x55; 4]);
        Ok(())
    }

    #[test]
    fn decrypt_rejects_bad_token_hmac() -> Result<(), RnsCryptoError> {
        let public = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let mut ciphertext = [0; 128];
        let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
            &public,
            PLAINTEXT,
            EPHEMERAL_SECRET,
            IV,
            &mut ciphertext,
        )?;
        ciphertext[ciphertext_len - RNS_TOKEN_HMAC_LEN] ^= 0x01;
        let mut plaintext = [0x55; 64];

        assert_eq!(
            decrypt_for_identity(
                &secret,
                &ciphertext[..ciphertext_len],
                &[],
                false,
                &mut plaintext,
            ),
            Err(RnsCryptoError::AuthenticationFailed)
        );
        assert_eq!(plaintext, [0x55; 64]);
        Ok(())
    }

    #[test]
    fn decrypt_rejects_bad_token_padding_without_leaving_plaintext() -> Result<(), RnsCryptoError> {
        let public = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY_BYTES)?;
        let mut ciphertext = [0; 128];
        let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
            &public,
            PLAINTEXT,
            EPHEMERAL_SECRET,
            IV,
            &mut ciphertext,
        )?;

        let ephemeral_secret = StaticSecret::from(EPHEMERAL_SECRET);
        let recipient_public = X25519PublicKey::from(public.x25519_public);
        let shared = ephemeral_secret.diffie_hellman(&recipient_public);
        let token_key = derive_token_key(&shared, &public)?;
        let token_start = RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN;
        let iv_last = token_start + RNS_TOKEN_IV_LEN - 1;
        ciphertext[iv_last] ^= 0x01;
        token_retag_for_test_vectors(&token_key[..], &mut ciphertext[token_start..ciphertext_len])?;
        let mut plaintext = [0x55; 64];

        assert_eq!(
            decrypt_for_identity(
                &secret,
                &ciphertext[..ciphertext_len],
                &[],
                false,
                &mut plaintext,
            ),
            Err(RnsCryptoError::InvalidPadding)
        );
        assert_eq!(&plaintext[..16], &[0; 16]);
        assert_eq!(&plaintext[16..], &[0x55; 48]);
        Ok(())
    }

    struct FixedRng {
        cursor: usize,
    }

    impl FixedRng {
        const fn new() -> Self {
            Self { cursor: 0 }
        }
    }

    impl TryRng for FixedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let mut bytes = [0; 48];
            bytes[..EPHEMERAL_SECRET.len()].copy_from_slice(&EPHEMERAL_SECRET);
            bytes[EPHEMERAL_SECRET.len()..].copy_from_slice(&IV);
            dst.copy_from_slice(&bytes[self.cursor..self.cursor + dst.len()]);
            self.cursor += dst.len();
            Ok(())
        }
    }

    impl TryCryptoRng for FixedRng {}
}
