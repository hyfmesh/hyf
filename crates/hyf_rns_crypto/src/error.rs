#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsCryptoError {
    InvalidPublicIdentity,
    InvalidSecretIdentity,
    InvalidSignature,
}

impl core::fmt::Display for RnsCryptoError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicIdentity => formatter.write_str("invalid public identity"),
            Self::InvalidSecretIdentity => formatter.write_str("invalid secret identity"),
            Self::InvalidSignature => formatter.write_str("invalid signature"),
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
    }
}
