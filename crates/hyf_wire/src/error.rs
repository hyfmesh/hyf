use core::fmt;

use hyf_core::ForeignEndpointError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyfWireError {
    InvalidVersion { actual: u8 },
    InvalidDestinationTag { tag: u8 },
    InvalidPayloadKind { tag: u8 },
    InputTooShort { actual: usize, minimum: usize },
    TrailingBytes { actual: usize, expected: usize },
    EnvelopeTooLarge { actual: usize, maximum: usize },
    OutputBufferTooShort { actual: usize, required: usize },
    InvalidExpiry,
    InvalidForeignEndpoint(ForeignEndpointError),
}

impl fmt::Display for HyfWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { actual } => {
                write!(formatter, "invalid hyf wire version: {actual}")
            }
            Self::InvalidDestinationTag { tag } => {
                write!(formatter, "invalid hyf destination tag: {tag}")
            }
            Self::InvalidPayloadKind { tag } => {
                write!(formatter, "invalid hyf payload kind: {tag}")
            }
            Self::InputTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "hyf envelope too short: actual {actual}, minimum {minimum}"
                )
            }
            Self::TrailingBytes { actual, expected } => {
                write!(
                    formatter,
                    "hyf envelope has trailing bytes: actual {actual}, expected {expected}"
                )
            }
            Self::EnvelopeTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "hyf envelope too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::OutputBufferTooShort { actual, required } => {
                write!(
                    formatter,
                    "hyf output buffer too short: actual {actual}, required {required}"
                )
            }
            Self::InvalidExpiry => formatter.write_str("invalid hyf envelope expiry"),
            Self::InvalidForeignEndpoint(error) => write!(formatter, "{error}"),
        }
    }
}

impl From<ForeignEndpointError> for HyfWireError {
    fn from(error: ForeignEndpointError) -> Self {
        Self::InvalidForeignEndpoint(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for HyfWireError {}

#[cfg(test)]
mod tests {
    use hyf_core::ForeignEndpointError;

    use super::HyfWireError;

    #[test]
    fn wire_errors_have_stable_display_text() {
        assert_eq!(
            HyfWireError::InvalidVersion { actual: 9 }.to_string(),
            "invalid hyf wire version: 9"
        );
        assert_eq!(
            HyfWireError::InputTooShort {
                actual: 2,
                minimum: 3,
            }
            .to_string(),
            "hyf envelope too short: actual 2, minimum 3"
        );
        assert_eq!(
            HyfWireError::OutputBufferTooShort {
                actual: 4,
                required: 5,
            }
            .to_string(),
            "hyf output buffer too short: actual 4, required 5"
        );
        assert_eq!(
            HyfWireError::InvalidForeignEndpoint(ForeignEndpointError::Empty).to_string(),
            "foreign endpoint is empty"
        );
    }
}
