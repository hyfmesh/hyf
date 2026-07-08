use core::fmt;

use hyf_link_kiss::KissError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeError {
    Kiss(KissError),
    InvalidFrequencyHz {
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    InvalidBandwidthHz {
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    InvalidTxPowerDbm {
        actual: u8,
        maximum: u8,
    },
    InvalidSpreadingFactor {
        actual: u8,
        minimum: u8,
        maximum: u8,
    },
    InvalidCodingRate {
        actual: u8,
        minimum: u8,
        maximum: u8,
    },
    InvalidPayloadLength {
        command: u8,
        actual: usize,
        expected: usize,
    },
}

impl From<KissError> for RNodeError {
    fn from(error: KissError) -> Self {
        Self::Kiss(error)
    }
}

impl fmt::Display for RNodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kiss(error) => write!(formatter, "kiss error: {error}"),
            Self::InvalidFrequencyHz {
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "invalid frequency hz: actual {actual}, minimum {minimum}, maximum {maximum}"
            ),
            Self::InvalidBandwidthHz {
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "invalid bandwidth hz: actual {actual}, minimum {minimum}, maximum {maximum}"
            ),
            Self::InvalidTxPowerDbm { actual, maximum } => write!(
                formatter,
                "invalid tx power dbm: actual {actual}, maximum {maximum}"
            ),
            Self::InvalidSpreadingFactor {
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "invalid spreading factor: actual {actual}, minimum {minimum}, maximum {maximum}"
            ),
            Self::InvalidCodingRate {
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "invalid coding rate: actual {actual}, minimum {minimum}, maximum {maximum}"
            ),
            Self::InvalidPayloadLength {
                command,
                actual,
                expected,
            } => write!(
                formatter,
                "invalid rnode payload length for command 0x{command:02x}: actual {actual}, expected {expected}"
            ),
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for RNodeError {}

#[cfg(test)]
mod tests {
    use super::RNodeError;

    #[test]
    fn rnode_errors_have_stable_display_text() {
        assert_eq!(
            RNodeError::InvalidFrequencyHz {
                actual: 1,
                minimum: 2,
                maximum: 3,
            }
            .to_string(),
            "invalid frequency hz: actual 1, minimum 2, maximum 3"
        );
        assert_eq!(
            RNodeError::InvalidPayloadLength {
                command: 0x50,
                actual: 1,
                expected: 2,
            }
            .to_string(),
            "invalid rnode payload length for command 0x50: actual 1, expected 2"
        );
    }
}
