use core::fmt;

use hyf_wire::HyfWireError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterError {
    OutputTooSmall { actual: usize, required: usize },
    TooManyLinks { maximum: usize },
    InvalidEnvelope(HyfWireError),
}

impl fmt::Display for RouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooSmall { actual, required } => {
                write!(
                    formatter,
                    "router output too small: actual {actual}, required {required}"
                )
            }
            Self::TooManyLinks { maximum } => {
                write!(formatter, "too many router links: maximum {maximum}")
            }
            Self::InvalidEnvelope(error) => write!(formatter, "{error}"),
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for RouterError {}

#[cfg(test)]
mod tests {
    use super::RouterError;

    #[test]
    fn router_errors_have_stable_display_text() {
        assert_eq!(
            RouterError::OutputTooSmall {
                actual: 0,
                required: 1,
            }
            .to_string(),
            "router output too small: actual 0, required 1"
        );
        assert_eq!(
            RouterError::TooManyLinks { maximum: 2 }.to_string(),
            "too many router links: maximum 2"
        );
    }
}
