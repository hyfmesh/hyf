#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod error;
#[cfg(feature = "crypto_token")]
mod hkdf;
mod identity;
#[cfg(feature = "crypto_token")]
mod pkcs7;
mod signing;
#[cfg(feature = "crypto_x25519")]
mod single_packet;
#[cfg(feature = "crypto_token")]
mod token;

pub use error::RnsCryptoError;
#[cfg(feature = "crypto_token")]
pub use hkdf::rns_hkdf_sha256;
pub use identity::{
    RNS_IDENTITY_KEY_LEN, RNS_PUBLIC_IDENTITY_LEN, RNS_SECRET_IDENTITY_LEN, RnsPublicIdentity,
    RnsSecretIdentity, identity_hash, public_identity_from_bytes, public_identity_to_bytes,
    secret_identity_from_bytes,
};
#[cfg(feature = "crypto_token")]
pub use pkcs7::{PKCS7_BLOCK_LEN, pkcs7_pad, pkcs7_padded_len, pkcs7_unpad};
pub use signing::{sign, verify};
#[cfg(feature = "crypto_x25519")]
pub use single_packet::{
    RNS_SINGLE_PACKET_DERIVED_KEY_LEN, RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN, RnsDecryptOutcome,
    RnsRatchetSecretRef, decrypt_for_identity, encrypt_for_identity,
};
#[cfg(any(test, feature = "test_vectors"))]
#[cfg(feature = "crypto_x25519")]
pub use single_packet::{
    derive_identity_token_key_for_test_vectors, encrypt_for_identity_with_ephemeral_and_iv,
};
#[cfg(feature = "crypto_token")]
pub use token::{
    RNS_TOKEN_HMAC_LEN, RNS_TOKEN_IV_LEN, RNS_TOKEN_OVERHEAD, token_decrypt, token_encrypt,
};
#[cfg(any(test, feature = "test_vectors"))]
#[cfg(feature = "crypto_token")]
pub use token::{token_encrypt_with_iv, token_retag_for_test_vectors};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
