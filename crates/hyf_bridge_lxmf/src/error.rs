use core::fmt;

use hyf_bridge_core::{BridgeError, BridgePayloadKind};
use hyf_lxmf_core::LxmfError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LxmfBridgeError {
    Lxmf(LxmfError),
    Bridge(BridgeError),
    NonEmptyTitle,
    NonEmptyFields,
    StampPresent,
    EmptyContent,
    InvalidContentUtf8,
    NegativeTimestamp,
    TimestampOverflow,
    UnsupportedBridgePayloadKind { kind: BridgePayloadKind },
}

impl fmt::Display for LxmfBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lxmf(error) => write!(formatter, "{error}"),
            Self::Bridge(error) => write!(formatter, "{error}"),
            Self::NonEmptyTitle => formatter.write_str("LXMF bridge title is not empty"),
            Self::NonEmptyFields => formatter.write_str("LXMF bridge fields map is not empty"),
            Self::StampPresent => formatter.write_str("LXMF bridge stamp is present"),
            Self::EmptyContent => formatter.write_str("LXMF bridge content is empty"),
            Self::InvalidContentUtf8 => {
                formatter.write_str("LXMF bridge content is not valid UTF-8")
            }
            Self::NegativeTimestamp => formatter.write_str("LXMF bridge timestamp is negative"),
            Self::TimestampOverflow => {
                formatter.write_str("LXMF bridge timestamp overflows u64 ms")
            }
            Self::UnsupportedBridgePayloadKind { kind } => {
                write!(
                    formatter,
                    "unsupported bridge payload kind for LXMF egress: {kind:?}"
                )
            }
        }
    }
}

impl From<LxmfError> for LxmfBridgeError {
    fn from(error: LxmfError) -> Self {
        Self::Lxmf(error)
    }
}

impl From<BridgeError> for LxmfBridgeError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for LxmfBridgeError {}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::BridgePayloadKind;

    use super::LxmfBridgeError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            LxmfBridgeError::NonEmptyTitle.to_string(),
            "LXMF bridge title is not empty"
        );
        assert_eq!(
            LxmfBridgeError::TimestampOverflow.to_string(),
            "LXMF bridge timestamp overflows u64 ms"
        );
        assert_eq!(
            LxmfBridgeError::UnsupportedBridgePayloadKind {
                kind: BridgePayloadKind::OpaqueBytes,
            }
            .to_string(),
            "unsupported bridge payload kind for LXMF egress: OpaqueBytes"
        );
    }
}
