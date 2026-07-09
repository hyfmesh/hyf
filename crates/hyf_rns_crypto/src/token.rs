use aes::{Aes128, Aes256};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{Hmac, KeyInit, Mac};
use rand_core::TryCryptoRng;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    RnsCryptoError,
    pkcs7::{pkcs7_pad, pkcs7_padded_len, pkcs7_unpad},
};

pub const RNS_TOKEN_IV_LEN: usize = 16;
pub const RNS_TOKEN_HMAC_LEN: usize = 32;
pub const RNS_TOKEN_OVERHEAD: usize = RNS_TOKEN_IV_LEN + RNS_TOKEN_HMAC_LEN;

const TOKEN_KEY_32_LEN: usize = 32;
const TOKEN_KEY_64_LEN: usize = 64;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn token_encrypt<R>(
    key: &[u8],
    plaintext: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<usize, RnsCryptoError>
where
    R: TryCryptoRng + ?Sized,
{
    let mut iv = [0; RNS_TOKEN_IV_LEN];
    rng.try_fill_bytes(&mut iv)
        .map_err(|_| RnsCryptoError::RandomSourceFailed)?;

    token_encrypt_with_iv(key, plaintext, iv, out)
}

#[cfg(any(test, feature = "test_vectors"))]
pub fn token_encrypt_with_iv(
    key: &[u8],
    plaintext: &[u8],
    iv: [u8; RNS_TOKEN_IV_LEN],
    out: &mut [u8],
) -> Result<usize, RnsCryptoError> {
    token_encrypt_with_iv_inner(key, plaintext, iv, out)
}

#[cfg(not(any(test, feature = "test_vectors")))]
fn token_encrypt_with_iv(
    key: &[u8],
    plaintext: &[u8],
    iv: [u8; RNS_TOKEN_IV_LEN],
    out: &mut [u8],
) -> Result<usize, RnsCryptoError> {
    token_encrypt_with_iv_inner(key, plaintext, iv, out)
}

fn token_encrypt_with_iv_inner(
    key: &[u8],
    plaintext: &[u8],
    iv: [u8; RNS_TOKEN_IV_LEN],
    out: &mut [u8],
) -> Result<usize, RnsCryptoError> {
    let keys = TokenKeys::split(key)?;
    let ciphertext_len = pkcs7_padded_len(plaintext.len())?;
    let required = token_len_for_ciphertext(ciphertext_len)?;
    if out.len() < required {
        return Err(RnsCryptoError::OutputBufferTooShort {
            actual: out.len(),
            required,
        });
    }

    out[..RNS_TOKEN_IV_LEN].copy_from_slice(&iv);
    let ciphertext_start = RNS_TOKEN_IV_LEN;
    let ciphertext_end = ciphertext_start + ciphertext_len;
    let padded_len = pkcs7_pad(plaintext, &mut out[ciphertext_start..ciphertext_end])?;
    debug_assert_eq!(padded_len, ciphertext_len);

    encrypt_cbc(
        &keys,
        &iv,
        &mut out[ciphertext_start..ciphertext_end],
        ciphertext_len,
    )?;

    let tag = hmac_sha256(keys.signing_key(), &out[..ciphertext_end])?;
    out[ciphertext_end..required].copy_from_slice(&tag);
    Ok(required)
}

pub fn token_decrypt(key: &[u8], token: &[u8], out: &mut [u8]) -> Result<usize, RnsCryptoError> {
    let keys = TokenKeys::split(key)?;
    if token.len() <= RNS_TOKEN_OVERHEAD {
        return Err(RnsCryptoError::InvalidToken);
    }

    let ciphertext_len = token.len() - RNS_TOKEN_OVERHEAD;
    if !ciphertext_len.is_multiple_of(RNS_TOKEN_IV_LEN) {
        return Err(RnsCryptoError::InvalidToken);
    }

    let tag_start = token.len() - RNS_TOKEN_HMAC_LEN;
    verify_hmac_sha256(keys.signing_key(), &token[..tag_start], &token[tag_start..])?;

    if out.len() < ciphertext_len {
        return Err(RnsCryptoError::OutputBufferTooShort {
            actual: out.len(),
            required: ciphertext_len,
        });
    }

    let iv = &token[..RNS_TOKEN_IV_LEN];
    let ciphertext = &token[RNS_TOKEN_IV_LEN..tag_start];
    out[..ciphertext_len].copy_from_slice(ciphertext);

    if let Err(error) = decrypt_cbc(&keys, iv, &mut out[..ciphertext_len]) {
        out[..ciphertext_len].zeroize();
        return Err(error);
    }

    let plaintext_len = match pkcs7_unpad(&out[..ciphertext_len]) {
        Ok(plaintext) => plaintext.len(),
        Err(error) => {
            out[..ciphertext_len].zeroize();
            return Err(error);
        }
    };

    out[plaintext_len..ciphertext_len].zeroize();
    Ok(plaintext_len)
}

fn token_len_for_ciphertext(ciphertext_len: usize) -> Result<usize, RnsCryptoError> {
    RNS_TOKEN_OVERHEAD
        .checked_add(ciphertext_len)
        .ok_or(RnsCryptoError::LengthOverflow)
}

fn encrypt_cbc(
    keys: &TokenKeys,
    iv: &[u8],
    buffer: &mut [u8],
    message_len: usize,
) -> Result<(), RnsCryptoError> {
    match keys.kind {
        TokenKeyKind::Aes128 => {
            Aes128CbcEnc::new_from_slices(keys.encryption_key(), iv)
                .map_err(|_| RnsCryptoError::CipherFailed)?
                .encrypt_padded::<NoPadding>(buffer, message_len)
                .map_err(|_| RnsCryptoError::CipherFailed)?;
        }
        TokenKeyKind::Aes256 => {
            Aes256CbcEnc::new_from_slices(keys.encryption_key(), iv)
                .map_err(|_| RnsCryptoError::CipherFailed)?
                .encrypt_padded::<NoPadding>(buffer, message_len)
                .map_err(|_| RnsCryptoError::CipherFailed)?;
        }
    }

    Ok(())
}

fn decrypt_cbc(keys: &TokenKeys, iv: &[u8], buffer: &mut [u8]) -> Result<(), RnsCryptoError> {
    match keys.kind {
        TokenKeyKind::Aes128 => {
            Aes128CbcDec::new_from_slices(keys.encryption_key(), iv)
                .map_err(|_| RnsCryptoError::CipherFailed)?
                .decrypt_padded::<NoPadding>(buffer)
                .map_err(|_| RnsCryptoError::CipherFailed)?;
        }
        TokenKeyKind::Aes256 => {
            Aes256CbcDec::new_from_slices(keys.encryption_key(), iv)
                .map_err(|_| RnsCryptoError::CipherFailed)?
                .decrypt_padded::<NoPadding>(buffer)
                .map_err(|_| RnsCryptoError::CipherFailed)?;
        }
    }

    Ok(())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; RNS_TOKEN_HMAC_LEN], RnsCryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| RnsCryptoError::CipherFailed)?;
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    let mut output = [0; RNS_TOKEN_HMAC_LEN];
    output.copy_from_slice(&tag);
    Ok(output)
}

fn verify_hmac_sha256(key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), RnsCryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| RnsCryptoError::CipherFailed)?;
    mac.update(message);
    mac.verify_slice(tag)
        .map_err(|_| RnsCryptoError::AuthenticationFailed)
}

#[cfg(any(test, feature = "test_vectors"))]
pub fn token_retag_for_test_vectors(key: &[u8], token: &mut [u8]) -> Result<(), RnsCryptoError> {
    let keys = TokenKeys::split(key)?;
    if token.len() <= RNS_TOKEN_HMAC_LEN {
        return Err(RnsCryptoError::InvalidToken);
    }

    let tag_start = token.len() - RNS_TOKEN_HMAC_LEN;
    let tag = hmac_sha256(keys.signing_key(), &token[..tag_start])?;
    token[tag_start..].copy_from_slice(&tag);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKeyKind {
    Aes128,
    Aes256,
}

struct TokenKeys {
    kind: TokenKeyKind,
    key_len: usize,
    signing_key: Zeroizing<[u8; 32]>,
    encryption_key: Zeroizing<[u8; 32]>,
}

impl TokenKeys {
    fn split(key: &[u8]) -> Result<Self, RnsCryptoError> {
        match key.len() {
            TOKEN_KEY_32_LEN => {
                let mut signing_key = Zeroizing::new([0; 32]);
                signing_key[..16].copy_from_slice(&key[..16]);
                let mut encryption_key = Zeroizing::new([0; 32]);
                encryption_key[..16].copy_from_slice(&key[16..]);
                Ok(Self {
                    kind: TokenKeyKind::Aes128,
                    key_len: 16,
                    signing_key,
                    encryption_key,
                })
            }
            TOKEN_KEY_64_LEN => {
                let mut signing_key = Zeroizing::new([0; 32]);
                signing_key.copy_from_slice(&key[..32]);
                let mut encryption_key = Zeroizing::new([0; 32]);
                encryption_key.copy_from_slice(&key[32..]);
                Ok(Self {
                    kind: TokenKeyKind::Aes256,
                    key_len: 32,
                    signing_key,
                    encryption_key,
                })
            }
            actual => Err(RnsCryptoError::InvalidTokenKeyLength { actual }),
        }
    }

    fn signing_key(&self) -> &[u8] {
        &self.signing_key[..self.key_len]
    }

    fn encryption_key(&self) -> &[u8] {
        &self.encryption_key[..self.key_len]
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RNS_TOKEN_HMAC_LEN, RNS_TOKEN_IV_LEN, RNS_TOKEN_OVERHEAD, token_decrypt, token_encrypt,
        token_encrypt_with_iv, token_retag_for_test_vectors,
    };
    use crate::RnsCryptoError;
    use rand_core::{Infallible, TryCryptoRng, TryRng};

    const KEY_32: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const KEY_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];
    const IV: [u8; RNS_TOKEN_IV_LEN] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];

    #[test]
    fn token_encrypt_decrypt_roundtrips_32_byte_key() -> Result<(), RnsCryptoError> {
        let mut token = [0; 128];
        let len = token_encrypt_with_iv(&KEY_32, b"hello token", IV, &mut token)?;
        let mut plaintext = [0; 64];
        let plaintext_len = token_decrypt(&KEY_32, &token[..len], &mut plaintext)?;

        assert_eq!(&plaintext[..plaintext_len], b"hello token");
        assert_eq!(len, RNS_TOKEN_OVERHEAD + 16);
        Ok(())
    }

    #[test]
    fn token_encrypt_decrypt_roundtrips_64_byte_key() -> Result<(), RnsCryptoError> {
        let mut token = [0; 128];
        let len = token_encrypt_with_iv(&KEY_64, b"hello token", IV, &mut token)?;
        let mut plaintext = [0; 64];
        let plaintext_len = token_decrypt(&KEY_64, &token[..len], &mut plaintext)?;

        assert_eq!(&plaintext[..plaintext_len], b"hello token");
        assert_eq!(len, RNS_TOKEN_OVERHEAD + 16);
        Ok(())
    }

    #[test]
    fn token_encrypt_rejects_invalid_key_length() {
        let mut token = [0; 128];

        assert_eq!(
            token_encrypt_with_iv(&[0; 7], b"hello", IV, &mut token),
            Err(RnsCryptoError::InvalidTokenKeyLength { actual: 7 })
        );
    }

    #[test]
    fn token_encrypt_rejects_short_output() {
        let mut token = [0; RNS_TOKEN_OVERHEAD];

        assert_eq!(
            token_encrypt_with_iv(&KEY_32, b"hello", IV, &mut token),
            Err(RnsCryptoError::OutputBufferTooShort {
                actual: RNS_TOKEN_OVERHEAD,
                required: RNS_TOKEN_OVERHEAD + 16
            })
        );
    }

    #[test]
    fn token_decrypt_rejects_bad_hmac_before_output_write() -> Result<(), RnsCryptoError> {
        let mut token = [0; 128];
        let len = token_encrypt_with_iv(&KEY_32, b"hello token", IV, &mut token)?;
        token[len - RNS_TOKEN_HMAC_LEN] ^= 0x01;
        let mut plaintext = [0x55; 64];

        assert_eq!(
            token_decrypt(&KEY_32, &token[..len], &mut plaintext),
            Err(RnsCryptoError::AuthenticationFailed)
        );
        assert_eq!(plaintext, [0x55; 64]);
        Ok(())
    }

    #[test]
    fn token_decrypt_rejects_invalid_padding_after_valid_hmac() -> Result<(), RnsCryptoError> {
        let mut token = [0; 128];
        let len = token_encrypt_with_iv(&KEY_32, b"hello token", IV, &mut token)?;
        token[RNS_TOKEN_IV_LEN - 1] ^= 0x01;
        token_retag_for_test_vectors(&KEY_32, &mut token[..len])?;
        let mut decrypted = [0x55; 64];

        assert_eq!(
            token_decrypt(&KEY_32, &token[..len], &mut decrypted),
            Err(RnsCryptoError::InvalidPadding)
        );
        assert_eq!(&decrypted[..16], &[0; 16]);
        assert_eq!(&decrypted[16..], &[0x55; 48]);
        Ok(())
    }

    #[test]
    fn token_decrypt_zeroes_padding_bytes_after_success() -> Result<(), RnsCryptoError> {
        let mut token = [0; 128];
        let len = token_encrypt_with_iv(&KEY_32, b"hello token", IV, &mut token)?;
        let mut decrypted = [0x55; 64];
        let plaintext_len = token_decrypt(&KEY_32, &token[..len], &mut decrypted)?;

        assert_eq!(&decrypted[..plaintext_len], b"hello token");
        assert_eq!(&decrypted[plaintext_len..16], &[0; 5]);
        assert_eq!(&decrypted[16..], &[0x55; 48]);
        Ok(())
    }

    #[test]
    fn token_encrypt_uses_rng_iv() -> Result<(), RnsCryptoError> {
        let mut rng = FixedRng::new(IV);
        let mut token = [0; 128];
        let len = token_encrypt(&KEY_32, b"hello token", &mut rng, &mut token)?;

        assert_eq!(&token[..RNS_TOKEN_IV_LEN], &IV);
        assert_eq!(&token[..RNS_TOKEN_IV_LEN], &token_encrypt_iv_prefix());
        assert_eq!(len, RNS_TOKEN_OVERHEAD + 16);
        Ok(())
    }

    fn token_encrypt_iv_prefix() -> [u8; RNS_TOKEN_IV_LEN] {
        IV
    }

    struct FixedRng {
        bytes: [u8; RNS_TOKEN_IV_LEN],
    }

    impl FixedRng {
        const fn new(bytes: [u8; RNS_TOKEN_IV_LEN]) -> Self {
            Self { bytes }
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
            dst.copy_from_slice(&self.bytes[..dst.len()]);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedRng {}
}
