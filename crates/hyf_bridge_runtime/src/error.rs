use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeRuntimeError {
    DedupeCapacityZero,
    OutputTooSmall { actual: usize, required: usize },
}

impl fmt::Display for BridgeRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DedupeCapacityZero => formatter.write_str("bridge dedupe capacity is zero"),
            Self::OutputTooSmall { actual, required } => {
                write!(
                    formatter,
                    "bridge runtime output buffer too small: actual {actual}, required {required}"
                )
            }
        }
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
