use core::fmt;

use hyf_bitchat_core::{BitchatError, BitchatVersion};
use hyf_bridge_core::{BridgeError, BridgePayloadKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitchatBridgeError {
    Bitchat(BitchatError),
    Bridge(BridgeError),
    UnsupportedVersion { version: BitchatVersion },
    UnsupportedPacketType { packet_type: u8 },
    SignedPacket,
    CompressedPacket,
    DirectedPacket,
    RoutedPacket,
    RsrPacket,
    EmptyPayload,
    InvalidPayloadUtf8,
    TimestampZero,
    UnsupportedBridgePayloadKind { kind: BridgePayloadKind },
}

impl fmt::Display for BitchatBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitchat(error) => write!(formatter, "{error}"),
            Self::Bridge(error) => write!(formatter, "{error}"),
            Self::UnsupportedVersion { version } => {
                write!(
                    formatter,
                    "unsupported BitChat bridge packet version: {}",
                    version.wire_value()
                )
            }
            Self::UnsupportedPacketType { packet_type } => {
                write!(
                    formatter,
                    "unsupported BitChat bridge packet type: {packet_type:#04x}"
                )
            }
            Self::SignedPacket => formatter.write_str("signed BitChat bridge packets are rejected"),
            Self::CompressedPacket => {
                formatter.write_str("compressed BitChat bridge packets are rejected")
            }
            Self::DirectedPacket => {
                formatter.write_str("directed BitChat bridge packets are rejected")
            }
            Self::RoutedPacket => formatter.write_str("routed BitChat bridge packets are rejected"),
            Self::RsrPacket => formatter.write_str("RSR BitChat bridge packets are rejected"),
            Self::EmptyPayload => formatter.write_str("BitChat bridge payload is empty"),
            Self::InvalidPayloadUtf8 => {
                formatter.write_str("BitChat bridge payload is not valid UTF-8")
            }
            Self::TimestampZero => formatter.write_str("BitChat bridge timestamp is zero"),
            Self::UnsupportedBridgePayloadKind { kind } => {
                write!(
                    formatter,
                    "unsupported bridge payload kind for BitChat egress: {kind:?}"
                )
            }
        }
    }
}

impl From<BitchatError> for BitchatBridgeError {
    fn from(error: BitchatError) -> Self {
        Self::Bitchat(error)
    }
}

impl From<BridgeError> for BitchatBridgeError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for BitchatBridgeError {}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::BridgePayloadKind;

    use super::BitchatBridgeError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            BitchatBridgeError::UnsupportedPacketType { packet_type: 0x09 }.to_string(),
            "unsupported BitChat bridge packet type: 0x09"
        );
        assert_eq!(
            BitchatBridgeError::CompressedPacket.to_string(),
            "compressed BitChat bridge packets are rejected"
        );
        assert_eq!(
            BitchatBridgeError::UnsupportedBridgePayloadKind {
                kind: BridgePayloadKind::OpaqueBytes,
            }
            .to_string(),
            "unsupported bridge payload kind for BitChat egress: OpaqueBytes"
        );
    }
}
