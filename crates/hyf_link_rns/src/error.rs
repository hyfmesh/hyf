use core::fmt;

use hyf_rns_wire::RnsWireError;
use hyf_wire::HyfWireError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyfLinkRnsError {
    RnsWire(RnsWireError),
    HyfWire(HyfWireError),
    NotForeignRnsPacket,
}

impl fmt::Display for HyfLinkRnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RnsWire(error) => write!(formatter, "{error}"),
            Self::HyfWire(error) => write!(formatter, "{error}"),
            Self::NotForeignRnsPacket => {
                formatter.write_str("hyf envelope payload is not a foreign rns packet")
            }
        }
    }
}

impl From<RnsWireError> for HyfLinkRnsError {
    fn from(error: RnsWireError) -> Self {
        Self::RnsWire(error)
    }
}

impl From<HyfWireError> for HyfLinkRnsError {
    fn from(error: HyfWireError) -> Self {
        Self::HyfWire(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for HyfLinkRnsError {}

#[cfg(test)]
mod tests {
    use hyf_rns_wire::RnsWireError;

    use super::HyfLinkRnsError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            HyfLinkRnsError::NotForeignRnsPacket.to_string(),
            "hyf envelope payload is not a foreign rns packet"
        );
        assert_eq!(
            HyfLinkRnsError::RnsWire(RnsWireError::PacketTooShort {
                actual: 0,
                minimum: 1,
            })
            .to_string(),
            "packet too short: actual 0, minimum 1"
        );
    }
}
