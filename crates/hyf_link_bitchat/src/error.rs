use core::fmt;

use hyf_bitchat_core::BitchatError;
use hyf_wire::{HyfWireError, PayloadKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyfLinkBitchatError {
    Bitchat(BitchatError),
    HyfWire(HyfWireError),
    PacketTooLargeForCarrier { actual: usize, maximum: usize },
    WrongPayloadKind { actual: PayloadKind },
}

impl fmt::Display for HyfLinkBitchatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitchat(error) => write!(formatter, "{error}"),
            Self::HyfWire(error) => write!(formatter, "{error}"),
            Self::PacketTooLargeForCarrier { actual, maximum } => {
                write!(
                    formatter,
                    "BitChat packet too large for HYF carrier: actual {actual}, maximum {maximum}"
                )
            }
            Self::WrongPayloadKind { actual } => {
                write!(
                    formatter,
                    "hyf envelope payload kind is not foreign bitchat: actual {actual:?}"
                )
            }
        }
    }
}

impl From<BitchatError> for HyfLinkBitchatError {
    fn from(error: BitchatError) -> Self {
        Self::Bitchat(error)
    }
}

impl From<HyfWireError> for HyfLinkBitchatError {
    fn from(error: HyfWireError) -> Self {
        Self::HyfWire(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for HyfLinkBitchatError {}

#[cfg(test)]
mod tests {
    use hyf_bitchat_core::BitchatError;
    use hyf_wire::PayloadKind;

    use super::HyfLinkBitchatError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            HyfLinkBitchatError::PacketTooLargeForCarrier {
                actual: 1537,
                maximum: 1536,
            }
            .to_string(),
            "BitChat packet too large for HYF carrier: actual 1537, maximum 1536"
        );
        assert_eq!(
            HyfLinkBitchatError::WrongPayloadKind {
                actual: PayloadKind::HyfNativeV0,
            }
            .to_string(),
            "hyf envelope payload kind is not foreign bitchat: actual HyfNativeV0"
        );
        assert_eq!(
            HyfLinkBitchatError::Bitchat(BitchatError::UnknownVersion { version: 3 }).to_string(),
            "unknown BitChat packet version: 3"
        );
    }
}
