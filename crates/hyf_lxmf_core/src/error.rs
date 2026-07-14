use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LxmfError {
    MessageTooShort { actual: usize, minimum: usize },
    MessageTooLarge { actual: usize, maximum: usize },
    PayloadTooLarge { actual: usize, maximum: usize },
    InvalidPayloadArrayLen { actual: usize },
    UnsupportedMsgpackType { marker: u8 },
    MsgpackTruncated,
    MsgpackTrailingBytes,
    MsgpackDepthExceeded { maximum: usize },
    InvalidTimestamp,
    TitleTooLarge { actual: usize, maximum: usize },
    ContentTooLarge { actual: usize, maximum: usize },
    FieldsTooLarge { actual: usize, maximum: usize },
    StampTooLarge { actual: usize, maximum: usize },
    OutputTooSmall { needed: usize, available: usize },
}

impl fmt::Display for LxmfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "LXMF message too short: actual {actual}, minimum {minimum}"
                )
            }
            Self::MessageTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "LXMF message too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::PayloadTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "LXMF payload too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::InvalidPayloadArrayLen { actual } => {
                write!(formatter, "invalid LXMF payload array length: {actual}")
            }
            Self::UnsupportedMsgpackType { marker } => {
                write!(
                    formatter,
                    "unsupported LXMF MessagePack marker: 0x{marker:02x}"
                )
            }
            Self::MsgpackTruncated => formatter.write_str("LXMF MessagePack input is truncated"),
            Self::MsgpackTrailingBytes => {
                formatter.write_str("LXMF MessagePack input has trailing bytes")
            }
            Self::MsgpackDepthExceeded { maximum } => {
                write!(
                    formatter,
                    "LXMF MessagePack depth exceeds maximum {maximum}"
                )
            }
            Self::InvalidTimestamp => formatter.write_str("invalid LXMF timestamp"),
            Self::TitleTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "LXMF title too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::ContentTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "LXMF content too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::FieldsTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "LXMF fields too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::StampTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "LXMF stamp too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::OutputTooSmall { needed, available } => {
                write!(
                    formatter,
                    "LXMF output buffer too small: needed {needed}, available {available}"
                )
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for LxmfError {}

#[cfg(test)]
mod tests {
    use super::LxmfError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            LxmfError::MessageTooShort {
                actual: 3,
                minimum: 96,
            }
            .to_string(),
            "LXMF message too short: actual 3, minimum 96"
        );
        assert_eq!(
            LxmfError::UnsupportedMsgpackType { marker: 0xc1 }.to_string(),
            "unsupported LXMF MessagePack marker: 0xc1"
        );
        assert_eq!(
            LxmfError::OutputTooSmall {
                needed: 10,
                available: 9,
            }
            .to_string(),
            "LXMF output buffer too small: needed 10, available 9"
        );
    }
}
