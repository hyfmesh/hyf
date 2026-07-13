use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrError {
    ContentTooLarge { actual: usize, maximum: usize },
    Crypto,
    EventIdMismatch,
    HexLength { expected: usize, actual: usize },
    InvalidSignature,
    InvalidHexChar { index: usize, byte: u8 },
    InvalidSubscriptionId,
    NonCanonicalHex { index: usize, byte: u8 },
    OddHexLength { len: usize },
    OutputTooSmall { needed: usize, available: usize },
    PublicKeyMismatch,
    SubscriptionIdTooLong { len: usize, maximum: usize },
    TagEmpty,
    Unsupported,
    Utf8,
}

impl fmt::Display for NostrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "nostr content too large: length {actual}, maximum {maximum}"
                )
            }
            Self::Crypto => write!(formatter, "nostr cryptographic operation failed"),
            Self::EventIdMismatch => write!(formatter, "nostr event id mismatch"),
            Self::HexLength { expected, actual } => {
                write!(
                    formatter,
                    "hex length mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::InvalidSignature => write!(formatter, "invalid nostr signature"),
            Self::InvalidHexChar { index, byte } => {
                write!(formatter, "invalid hex byte 0x{byte:02x} at index {index}")
            }
            Self::InvalidSubscriptionId => write!(formatter, "invalid nostr subscription id"),
            Self::NonCanonicalHex { index, byte } => {
                write!(
                    formatter,
                    "non-canonical hex byte 0x{byte:02x} at index {index}"
                )
            }
            Self::OddHexLength { len } => write!(formatter, "odd hex length {len}"),
            Self::OutputTooSmall { needed, available } => {
                write!(
                    formatter,
                    "output too small: needed {needed}, available {available}"
                )
            }
            Self::PublicKeyMismatch => write!(formatter, "nostr public key does not match secret"),
            Self::SubscriptionIdTooLong { len, maximum } => {
                write!(
                    formatter,
                    "nostr subscription id too long: length {len}, maximum {maximum}"
                )
            }
            Self::TagEmpty => write!(formatter, "nostr tag is empty"),
            Self::Unsupported => write!(formatter, "unsupported nostr operation"),
            Self::Utf8 => write!(formatter, "invalid utf-8 output"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NostrError {}

#[cfg(test)]
mod tests {
    use super::NostrError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            NostrError::ContentTooLarge {
                actual: 4097,
                maximum: 4096,
            }
            .to_string(),
            "nostr content too large: length 4097, maximum 4096"
        );
        assert_eq!(
            NostrError::Crypto.to_string(),
            "nostr cryptographic operation failed"
        );
        assert_eq!(
            NostrError::EventIdMismatch.to_string(),
            "nostr event id mismatch"
        );
        assert_eq!(
            NostrError::HexLength {
                expected: 64,
                actual: 62,
            }
            .to_string(),
            "hex length mismatch: expected 64, actual 62"
        );
        assert_eq!(
            NostrError::InvalidSignature.to_string(),
            "invalid nostr signature"
        );
        assert_eq!(
            NostrError::InvalidHexChar {
                index: 4,
                byte: b'z',
            }
            .to_string(),
            "invalid hex byte 0x7a at index 4"
        );
        assert_eq!(
            NostrError::InvalidSubscriptionId.to_string(),
            "invalid nostr subscription id"
        );
        assert_eq!(
            NostrError::NonCanonicalHex {
                index: 1,
                byte: b'A',
            }
            .to_string(),
            "non-canonical hex byte 0x41 at index 1"
        );
        assert_eq!(
            NostrError::OddHexLength { len: 3 }.to_string(),
            "odd hex length 3"
        );
        assert_eq!(
            NostrError::OutputTooSmall {
                needed: 4,
                available: 3,
            }
            .to_string(),
            "output too small: needed 4, available 3"
        );
        assert_eq!(
            NostrError::PublicKeyMismatch.to_string(),
            "nostr public key does not match secret"
        );
        assert_eq!(
            NostrError::SubscriptionIdTooLong {
                len: 65,
                maximum: 64,
            }
            .to_string(),
            "nostr subscription id too long: length 65, maximum 64"
        );
        assert_eq!(NostrError::TagEmpty.to_string(), "nostr tag is empty");
        assert_eq!(
            NostrError::Unsupported.to_string(),
            "unsupported nostr operation"
        );
        assert_eq!(NostrError::Utf8.to_string(), "invalid utf-8 output");
    }
}
