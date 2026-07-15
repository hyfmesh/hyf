use core::fmt;

use hyf_lxmf_core::LxmfError;
use hyf_wire::{HyfWireError, PayloadKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyfLinkLxmfError {
    Lxmf(LxmfError),
    HyfWire(HyfWireError),
    WrongPayloadKind { actual: PayloadKind },
}

impl fmt::Display for HyfLinkLxmfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lxmf(error) => write!(formatter, "{error}"),
            Self::HyfWire(error) => write!(formatter, "{error}"),
            Self::WrongPayloadKind { actual } => {
                write!(
                    formatter,
                    "hyf envelope payload kind is not foreign lxmf: actual {actual:?}"
                )
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
    use hyf_wire::PayloadKind;

    use super::HyfLinkLxmfError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            HyfLinkLxmfError::WrongPayloadKind {
                actual: PayloadKind::HyfNativeV0,
            }
            .to_string(),
            "hyf envelope payload kind is not foreign lxmf: actual HyfNativeV0"
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
