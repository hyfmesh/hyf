use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitchatError {
    PacketTooShort {
        actual: usize,
        minimum: usize,
    },
    PacketTooLarge {
        actual: usize,
        maximum: usize,
    },
    UnknownVersion {
        version: u8,
    },
    ReservedFlags {
        flags: u8,
    },
    V1RouteFlag,
    PayloadTooLarge {
        actual: usize,
        maximum: usize,
    },
    RouteTooManyHops {
        actual: usize,
        maximum: usize,
    },
    MissingField {
        field: &'static str,
        needed: usize,
        remaining: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
    CompressedOriginalLenMissing {
        actual: usize,
        minimum: usize,
    },
    CompressedOriginalLenZero,
    CompressedOriginalLenTooLarge {
        actual: usize,
        maximum: usize,
    },
    CompressedBodyEmpty,
    UnsupportedEncodeVersion {
        version: u8,
    },
    UnsupportedCompressedEncode,
    InvalidRouteByteLength {
        hop_count: u8,
        actual: usize,
        expected: usize,
    },
    LengthOverflow,
    OutputTooSmall {
        needed: usize,
        available: usize,
    },
}

impl fmt::Display for BitchatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "BitChat packet too short: actual {actual}, minimum {minimum}"
                )
            }
            Self::PacketTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "BitChat packet too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::UnknownVersion { version } => {
                write!(formatter, "unknown BitChat packet version: {version}")
            }
            Self::ReservedFlags { flags } => {
                write!(
                    formatter,
                    "BitChat flags contain reserved bits: 0x{flags:02x}"
                )
            }
            Self::V1RouteFlag => formatter.write_str("BitChat v1 packets cannot contain routes"),
            Self::PayloadTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "BitChat payload too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::RouteTooManyHops { actual, maximum } => {
                write!(
                    formatter,
                    "BitChat route has too many hops: actual {actual}, maximum {maximum}"
                )
            }
            Self::MissingField {
                field,
                needed,
                remaining,
            } => {
                write!(
                    formatter,
                    "BitChat packet is missing {field}: needed {needed}, remaining {remaining}"
                )
            }
            Self::TrailingBytes { remaining } => {
                write!(
                    formatter,
                    "BitChat packet has trailing bytes: remaining {remaining}"
                )
            }
            Self::CompressedOriginalLenMissing { actual, minimum } => {
                write!(
                    formatter,
                    "BitChat compressed payload missing original length: actual {actual}, minimum {minimum}"
                )
            }
            Self::CompressedOriginalLenZero => {
                formatter.write_str("BitChat compressed original length is zero")
            }
            Self::CompressedOriginalLenTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "BitChat compressed original length too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::CompressedBodyEmpty => {
                formatter.write_str("BitChat compressed payload body is empty")
            }
            Self::UnsupportedEncodeVersion { version } => {
                write!(formatter, "unsupported BitChat encode version: {version}")
            }
            Self::UnsupportedCompressedEncode => {
                formatter.write_str("BitChat encoder only supports plain payloads")
            }
            Self::InvalidRouteByteLength {
                hop_count,
                actual,
                expected,
            } => {
                write!(
                    formatter,
                    "BitChat route byte length mismatch: hop_count {hop_count}, actual {actual}, expected {expected}"
                )
            }
            Self::LengthOverflow => formatter.write_str("BitChat packet length overflow"),
            Self::OutputTooSmall { needed, available } => {
                write!(
                    formatter,
                    "BitChat output buffer too small: needed {needed}, available {available}"
                )
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for BitchatError {}

#[cfg(test)]
mod tests {
    use super::BitchatError;

    #[test]
    fn error_display_text_is_stable() {
        assert_eq!(
            BitchatError::PacketTooShort {
                actual: 13,
                minimum: 14,
            }
            .to_string(),
            "BitChat packet too short: actual 13, minimum 14"
        );
        assert_eq!(
            BitchatError::ReservedFlags { flags: 0xe0 }.to_string(),
            "BitChat flags contain reserved bits: 0xe0"
        );
        assert_eq!(
            BitchatError::MissingField {
                field: "sender ID",
                needed: 8,
                remaining: 7,
            }
            .to_string(),
            "BitChat packet is missing sender ID: needed 8, remaining 7"
        );
        assert_eq!(
            BitchatError::OutputTooSmall {
                needed: 32,
                available: 31,
            }
            .to_string(),
            "BitChat output buffer too small: needed 32, available 31"
        );
    }
}
