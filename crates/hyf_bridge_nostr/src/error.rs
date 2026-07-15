use core::fmt;

use hyf_bridge_core::BridgeError;
use hyf_link_nostr::NostrError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrBridgeError {
    Nostr(NostrError),
    Bridge(BridgeError),
    WrongKind { actual: u16 },
    MissingRequiredTag { tag: &'static str },
    CommunityTagMismatch,
    NostrAuthorPubkeyMismatch,
}

impl fmt::Display for NostrBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nostr(error) => write!(formatter, "{error}"),
            Self::Bridge(error) => write!(formatter, "{error}"),
            Self::WrongKind { actual } => {
                write!(formatter, "wrong HYF bridge Nostr event kind: {actual}")
            }
            Self::MissingRequiredTag { tag } => {
                write!(formatter, "missing HYF bridge Nostr tag: {tag}")
            }
            Self::CommunityTagMismatch => {
                formatter.write_str("HYF bridge Nostr community tag mismatch")
            }
            Self::NostrAuthorPubkeyMismatch => {
                formatter.write_str("HYF bridge Nostr author pubkey mismatch")
            }
        }
    }
}

impl From<NostrError> for NostrBridgeError {
    fn from(error: NostrError) -> Self {
        Self::Nostr(error)
    }
}

impl From<BridgeError> for NostrBridgeError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for NostrBridgeError {}

#[cfg(test)]
mod tests {
    use super::NostrBridgeError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            NostrBridgeError::WrongKind { actual: 1 }.to_string(),
            "wrong HYF bridge Nostr event kind: 1"
        );
        assert_eq!(
            NostrBridgeError::MissingRequiredTag { tag: "community" }.to_string(),
            "missing HYF bridge Nostr tag: community"
        );
        assert_eq!(
            NostrBridgeError::NostrAuthorPubkeyMismatch.to_string(),
            "HYF bridge Nostr author pubkey mismatch"
        );
    }
}
