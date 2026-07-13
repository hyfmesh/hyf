use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrError {
    Unsupported,
}

impl fmt::Display for NostrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(formatter, "unsupported nostr operation"),
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
            NostrError::Unsupported.to_string(),
            "unsupported nostr operation"
        );
    }
}
