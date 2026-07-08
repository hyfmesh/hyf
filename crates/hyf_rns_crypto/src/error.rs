#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsCryptoError {
    InvalidPublicIdentity,
    InvalidSecretIdentity,
    InvalidSignature,
    EmptyHkdfOutput,
    EmptyHkdfInputKeyMaterial,
    InvalidHkdfLength,
    LengthOverflow,
    OutputBufferTooShort { actual: usize, required: usize },
    InvalidPadding,
    InvalidToken,
    InvalidTokenKeyLength { actual: usize },
    AuthenticationFailed,
    RandomSourceFailed,
    CipherFailed,
}

impl core::fmt::Display for RnsCryptoError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicIdentity => formatter.write_str("invalid public identity"),
            Self::InvalidSecretIdentity => formatter.write_str("invalid secret identity"),
            Self::InvalidSignature => formatter.write_str("invalid signature"),
            Self::EmptyHkdfOutput => formatter.write_str("empty hkdf output"),
            Self::EmptyHkdfInputKeyMaterial => formatter.write_str("empty hkdf input key material"),
            Self::InvalidHkdfLength => formatter.write_str("invalid hkdf length"),
            Self::LengthOverflow => formatter.write_str("length overflow"),
            Self::OutputBufferTooShort { actual, required } => {
                write!(
                    formatter,
                    "output buffer too short: actual {actual}, required {required}"
                )
            }
            Self::InvalidPadding => formatter.write_str("invalid padding"),
            Self::InvalidToken => formatter.write_str("invalid token"),
            Self::InvalidTokenKeyLength { actual } => {
                write!(formatter, "invalid token key length: actual {actual}")
            }
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
            Self::RandomSourceFailed => formatter.write_str("random source failed"),
            Self::CipherFailed => formatter.write_str("cipher failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RnsCryptoError;

    #[test]
    fn crypto_errors_have_stable_display_text() {
        assert_eq!(
            RnsCryptoError::InvalidPublicIdentity.to_string(),
            "invalid public identity"
        );
        assert_eq!(
            RnsCryptoError::InvalidSecretIdentity.to_string(),
            "invalid secret identity"
        );
        assert_eq!(
            RnsCryptoError::InvalidSignature.to_string(),
            "invalid signature"
        );
        assert_eq!(
            RnsCryptoError::EmptyHkdfOutput.to_string(),
            "empty hkdf output"
        );
        assert_eq!(
            RnsCryptoError::OutputBufferTooShort {
                actual: 1,
                required: 2
            }
            .to_string(),
            "output buffer too short: actual 1, required 2"
        );
        assert_eq!(
            RnsCryptoError::InvalidTokenKeyLength { actual: 7 }.to_string(),
            "invalid token key length: actual 7"
        );
    }
}
