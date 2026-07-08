use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KissError {
    EncodedLengthOverflow,
    OutputBufferTooShort { actual: usize, required: usize },
    FrameTooLarge { actual: usize, maximum: usize },
    MalformedEscape { byte: u8 },
}

impl fmt::Display for KissError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedLengthOverflow => formatter.write_str("encoded kiss length overflow"),
            Self::OutputBufferTooShort { actual, required } => {
                write!(
                    formatter,
                    "kiss output buffer too short: actual {actual}, required {required}"
                )
            }
            Self::FrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "kiss frame too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::MalformedEscape { byte } => {
                write!(formatter, "malformed kiss escape byte: 0x{byte:02x}")
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for KissError {}

#[cfg(test)]
mod tests {
    use super::KissError;

    #[test]
    fn kiss_errors_have_stable_display_text() {
        assert_eq!(
            KissError::OutputBufferTooShort {
                actual: 4,
                required: 5,
            }
            .to_string(),
            "kiss output buffer too short: actual 4, required 5"
        );
        assert_eq!(
            KissError::FrameTooLarge {
                actual: 6,
                maximum: 5,
            }
            .to_string(),
            "kiss frame too large: actual 6, maximum 5"
        );
        assert_eq!(
            KissError::MalformedEscape { byte: 0x00 }.to_string(),
            "malformed kiss escape byte: 0x00"
        );
    }
}
