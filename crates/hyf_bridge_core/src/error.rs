use core::fmt;

use hyf_core::{ForeignEndpointError, ForeignNetworkKind};
use hyf_wire::{HyfWireError, PayloadKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    InvalidVersion { actual: u8 },
    ZeroRoomId,
    ZeroMessageId,
    UnknownAuthorKind { tag: u8 },
    UnexpectedHyfAuthorNetworkTag { tag: u8 },
    InvalidForeignNetworkTag { tag: u8 },
    UnsupportedAuthorNetwork { network: ForeignNetworkKind },
    InvalidAuthorIdLen { len: usize },
    UnknownPayloadKind { tag: u8 },
    InvalidTextUtf8,
    PayloadTooLarge { actual: usize, maximum: usize },
    MessageTooLarge { actual: usize, maximum: usize },
    InputTooShort { actual: usize, minimum: usize },
    TrailingBytes { actual: usize, expected: usize },
    OutputTooSmall { actual: usize, required: usize },
    WrongPayloadKind { actual: PayloadKind },
    EnvelopeMessageIdMismatch,
    EnvelopeRoomMismatch,
    HyfWire(HyfWireError),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { actual } => {
                write!(formatter, "invalid bridge message version: {actual}")
            }
            Self::ZeroRoomId => formatter.write_str("bridge room id is zero"),
            Self::ZeroMessageId => formatter.write_str("bridge message id is zero"),
            Self::UnknownAuthorKind { tag } => {
                write!(formatter, "unknown bridge author kind: {tag}")
            }
            Self::UnexpectedHyfAuthorNetworkTag { tag } => {
                write!(
                    formatter,
                    "HYF bridge author has nonzero network tag: {tag}"
                )
            }
            Self::InvalidForeignNetworkTag { tag } => {
                write!(formatter, "invalid bridge foreign network tag: {tag}")
            }
            Self::UnsupportedAuthorNetwork { network } => {
                write!(formatter, "unsupported bridge author network: {network:?}")
            }
            Self::InvalidAuthorIdLen { len } => {
                write!(formatter, "invalid bridge author id length: {len}")
            }
            Self::UnknownPayloadKind { tag } => {
                write!(formatter, "unknown bridge payload kind: {tag}")
            }
            Self::InvalidTextUtf8 => formatter.write_str("bridge text payload is not valid UTF-8"),
            Self::PayloadTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "bridge payload too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::MessageTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "bridge message too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::InputTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "bridge message too short: actual {actual}, minimum {minimum}"
                )
            }
            Self::TrailingBytes { actual, expected } => {
                write!(
                    formatter,
                    "bridge message has trailing bytes: actual {actual}, expected {expected}"
                )
            }
            Self::OutputTooSmall { actual, required } => {
                write!(
                    formatter,
                    "bridge output buffer too small: actual {actual}, required {required}"
                )
            }
            Self::WrongPayloadKind { actual } => {
                write!(
                    formatter,
                    "hyf envelope payload kind is not bridge message v0: actual {actual:?}"
                )
            }
            Self::EnvelopeMessageIdMismatch => {
                formatter.write_str("bridge envelope message id mismatch")
            }
            Self::EnvelopeRoomMismatch => formatter.write_str("bridge envelope room mismatch"),
            Self::HyfWire(error) => write!(formatter, "{error}"),
        }
    }
}

impl From<HyfWireError> for BridgeError {
    fn from(error: HyfWireError) -> Self {
        Self::HyfWire(error)
    }
}

impl From<ForeignEndpointError> for BridgeError {
    fn from(error: ForeignEndpointError) -> Self {
        match error {
            ForeignEndpointError::InvalidNetworkTag { tag } => {
                Self::InvalidForeignNetworkTag { tag }
            }
            ForeignEndpointError::Empty => Self::InvalidAuthorIdLen { len: 0 },
            ForeignEndpointError::TooLong { actual, .. } => {
                Self::InvalidAuthorIdLen { len: actual }
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for BridgeError {}

#[cfg(test)]
mod tests {
    use hyf_wire::PayloadKind;

    use super::BridgeError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            BridgeError::InvalidVersion { actual: 9 }.to_string(),
            "invalid bridge message version: 9"
        );
        assert_eq!(
            BridgeError::WrongPayloadKind {
                actual: PayloadKind::HyfNativeV0,
            }
            .to_string(),
            "hyf envelope payload kind is not bridge message v0: actual HyfNativeV0"
        );
        assert_eq!(
            BridgeError::PayloadTooLarge {
                actual: 1025,
                maximum: 1024,
            }
            .to_string(),
            "bridge payload too large: actual 1025, maximum 1024"
        );
        assert_eq!(
            BridgeError::UnsupportedAuthorNetwork {
                network: hyf_core::ForeignNetworkKind::Rns,
            }
            .to_string(),
            "unsupported bridge author network: Rns"
        );
    }
}
