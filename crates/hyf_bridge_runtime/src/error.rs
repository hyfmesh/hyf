use core::fmt;

use hyf_bridge_bitchat::BitchatBridgeError;
use hyf_bridge_core::BridgeError;
use hyf_bridge_lxmf::LxmfBridgeError;
use hyf_bridge_nostr::NostrBridgeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeRuntimeError {
    Bitchat(BitchatBridgeError),
    Bridge(BridgeError),
    DedupeCapacityZero,
    Lxmf(LxmfBridgeError),
    Nostr(NostrBridgeError),
    OutputTooSmall { actual: usize, required: usize },
}

impl fmt::Display for BridgeRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitchat(error) => write!(formatter, "{error}"),
            Self::Bridge(error) => write!(formatter, "{error}"),
            Self::DedupeCapacityZero => formatter.write_str("bridge dedupe capacity is zero"),
            Self::Lxmf(error) => write!(formatter, "{error}"),
            Self::Nostr(error) => write!(formatter, "{error}"),
            Self::OutputTooSmall { actual, required } => {
                write!(
                    formatter,
                    "bridge runtime output buffer too small: actual {actual}, required {required}"
                )
            }
        }
    }
}

impl From<BitchatBridgeError> for BridgeRuntimeError {
    fn from(error: BitchatBridgeError) -> Self {
        Self::Bitchat(error)
    }
}

impl From<BridgeError> for BridgeRuntimeError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge(error)
    }
}

impl From<LxmfBridgeError> for BridgeRuntimeError {
    fn from(error: LxmfBridgeError) -> Self {
        Self::Lxmf(error)
    }
}

impl From<NostrBridgeError> for BridgeRuntimeError {
    fn from(error: NostrBridgeError) -> Self {
        Self::Nostr(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for BridgeRuntimeError {}

#[cfg(test)]
mod tests {
    use super::BridgeRuntimeError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            BridgeRuntimeError::DedupeCapacityZero.to_string(),
            "bridge dedupe capacity is zero"
        );
        assert_eq!(
            BridgeRuntimeError::OutputTooSmall {
                actual: 1,
                required: 2,
            }
            .to_string(),
            "bridge runtime output buffer too small: actual 1, required 2"
        );
    }
}
