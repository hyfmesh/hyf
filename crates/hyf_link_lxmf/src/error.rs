use core::fmt;

use hyf_lxmf_core::LxmfError;
use hyf_wire::HyfWireError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyfLinkLxmfError {
    Lxmf(LxmfError),
    HyfWire(HyfWireError),
    NotForeignLxmfMessage,
}

impl fmt::Display for HyfLinkLxmfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lxmf(error) => write!(formatter, "{error}"),
            Self::HyfWire(error) => write!(formatter, "{error}"),
            Self::NotForeignLxmfMessage => {
                formatter.write_str("hyf envelope payload is not a foreign lxmf message")
            }
        }
    }
}

impl From<LxmfError> for HyfLinkLxmfError {
    fn from(error: LxmfError) -> Self {
        Self::Lxmf(error)
    }
}

impl From<HyfWireError> for HyfLinkLxmfError {
    fn from(error: HyfWireError) -> Self {
        Self::HyfWire(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for HyfLinkLxmfError {}

#[cfg(test)]
mod tests {
    use hyf_lxmf_core::LxmfError;

    use super::HyfLinkLxmfError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            HyfLinkLxmfError::NotForeignLxmfMessage.to_string(),
            "hyf envelope payload is not a foreign lxmf message"
        );
        assert_eq!(
            HyfLinkLxmfError::Lxmf(LxmfError::MessageTooShort {
                actual: 3,
                minimum: 96,
            })
            .to_string(),
            "LXMF message too short: actual 3, minimum 96"
        );
    }
}
