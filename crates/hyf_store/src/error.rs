use core::fmt;

use hyf_wire::HyfWireError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    Full,
    Duplicate,
    Expired,
    FrameTooLarge { actual: usize, maximum: usize },
    InvalidEnvelope(HyfWireError),
    NotFound,
    OutputTooSmall { actual: usize, required: usize },
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => formatter.write_str("store is full"),
            Self::Duplicate => formatter.write_str("duplicate stored message"),
            Self::Expired => formatter.write_str("stored envelope is expired"),
            Self::FrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "stored frame too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::InvalidEnvelope(error) => write!(formatter, "invalid stored envelope: {error}"),
            Self::NotFound => formatter.write_str("stored message not found"),
            Self::OutputTooSmall { actual, required } => {
                write!(
                    formatter,
                    "store output too small: actual {actual}, required {required}"
                )
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::StoreError;

    #[test]
    fn store_errors_have_stable_display_text() {
        assert_eq!(StoreError::Full.to_string(), "store is full");
        assert_eq!(
            StoreError::Duplicate.to_string(),
            "duplicate stored message"
        );
        assert_eq!(
            StoreError::Expired.to_string(),
            "stored envelope is expired"
        );
        assert_eq!(
            StoreError::FrameTooLarge {
                actual: 3,
                maximum: 2,
            }
            .to_string(),
            "stored frame too large: actual 3, maximum 2"
        );
        assert_eq!(
            StoreError::OutputTooSmall {
                actual: 1,
                required: 2,
            }
            .to_string(),
            "store output too small: actual 1, required 2"
        );
    }
}
