use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{NostrError, decode_fixed_lower_hex, encode_lower_hex};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NostrPublicKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NostrSecretKey([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NostrEventId([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NostrSignature([u8; 64]);

impl fmt::Debug for NostrSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrSecretKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl NostrPublicKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, NostrError> {
        Ok(Self(decode_fixed_lower_hex(hex)?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn write_hex<'a>(&self, out: &'a mut [u8]) -> Result<&'a str, NostrError> {
        encode_lower_hex(&self.0, out)
    }
}

impl NostrSecretKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, NostrError> {
        Ok(Self(decode_fixed_lower_hex(hex)?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl NostrEventId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, NostrError> {
        Ok(Self(decode_fixed_lower_hex(hex)?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn write_hex<'a>(&self, out: &'a mut [u8]) -> Result<&'a str, NostrError> {
        encode_lower_hex(&self.0, out)
    }
}

impl NostrSignature {
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, NostrError> {
        Ok(Self(decode_fixed_lower_hex(hex)?))
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn write_hex<'a>(&self, out: &'a mut [u8]) -> Result<&'a str, NostrError> {
        encode_lower_hex(&self.0, out)
    }
}

#[cfg(test)]
mod tests {
    use super::{NostrEventId, NostrPublicKey, NostrSecretKey, NostrSignature};
    use crate::NostrError;

    #[test]
    fn key_id_and_signature_hex_roundtrip() -> Result<(), NostrError> {
        let public = NostrPublicKey::from_bytes([0xab; 32]);
        let event_id = NostrEventId::from_bytes([0xcd; 32]);
        let signature = NostrSignature::from_bytes([0xef; 64]);

        let mut public_hex = [0; 64];
        let mut event_id_hex = [0; 64];
        let mut signature_hex = [0; 128];

        let public_hex = public.write_hex(&mut public_hex)?;
        let event_id_hex = event_id.write_hex(&mut event_id_hex)?;
        let signature_hex = signature.write_hex(&mut signature_hex)?;

        assert_eq!(NostrPublicKey::from_hex(public_hex)?, public);
        assert_eq!(NostrEventId::from_hex(event_id_hex)?, event_id);
        assert_eq!(NostrSignature::from_hex(signature_hex)?, signature);
        Ok(())
    }

    #[test]
    fn key_material_rejects_wrong_lengths_and_non_canonical_hex() {
        assert!(matches!(
            NostrPublicKey::from_hex("00"),
            Err(NostrError::HexLength {
                expected: 64,
                actual: 2
            })
        ));
        assert!(matches!(
            NostrSignature::from_hex("0A"),
            Err(NostrError::HexLength {
                expected: 128,
                actual: 2
            })
        ));
        let uppercase_public_key = "AA".repeat(32);
        assert!(matches!(
            NostrPublicKey::from_hex(&uppercase_public_key),
            Err(NostrError::NonCanonicalHex {
                index: 0,
                byte: b'A'
            })
        ));
    }

    #[test]
    fn secret_key_debug_redacts_material() {
        let secret = NostrSecretKey::from_bytes([0x42; 32]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("NostrSecretKey"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("42"));
        assert_eq!(secret.as_bytes(), &[0x42; 32]);
    }

    #[test]
    fn secret_key_parses_lowercase_hex() -> Result<(), NostrError> {
        let hex = "11".repeat(32);
        let secret = NostrSecretKey::from_hex(&hex)?;
        assert_eq!(secret.as_bytes(), &[0x11; 32]);
        Ok(())
    }
}
