#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsWireError {
    UnsupportedPacketAccessCode,
    InvalidFlags,
    InvalidHeaderType,
    InvalidTransportType,
    InvalidDestinationType,
    InvalidPacketType,
    PacketTooShort { actual: usize, minimum: usize },
    PacketTooLarge { actual: usize, maximum: usize },
    MissingTransportId,
    UnexpectedTransportId,
    OutputBufferTooShort { actual: usize, required: usize },
    MalformedAnnounce,
    InvalidPublicIdentity,
    InvalidSignature,
    CryptoFailed,
    InvalidIfacSize { actual: usize, maximum: usize },
    InvalidIfacKey,
    MissingPacketAccessCode,
    InvalidPacketAccessCode,
    DestinationMismatch,
    TimestampOverflow,
    RandomSourceFailed,
    InvalidDestinationName,
}

impl core::fmt::Display for RnsWireError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedPacketAccessCode => {
                formatter.write_str("unsupported packet access code")
            }
            Self::InvalidFlags => formatter.write_str("invalid flags"),
            Self::InvalidHeaderType => formatter.write_str("invalid header type"),
            Self::InvalidTransportType => formatter.write_str("invalid transport type"),
            Self::InvalidDestinationType => formatter.write_str("invalid destination type"),
            Self::InvalidPacketType => formatter.write_str("invalid packet type"),
            Self::PacketTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "packet too short: actual {actual}, minimum {minimum}"
                )
            }
            Self::PacketTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "packet too large: actual {actual}, maximum {maximum}"
                )
            }
            Self::MissingTransportId => formatter.write_str("missing transport id"),
            Self::UnexpectedTransportId => formatter.write_str("unexpected transport id"),
            Self::OutputBufferTooShort { actual, required } => {
                write!(
                    formatter,
                    "output buffer too short: actual {actual}, required {required}"
                )
            }
            Self::MalformedAnnounce => formatter.write_str("malformed announce"),
            Self::InvalidPublicIdentity => formatter.write_str("invalid public identity"),
            Self::InvalidSignature => formatter.write_str("invalid signature"),
            Self::CryptoFailed => formatter.write_str("crypto failed"),
            Self::InvalidIfacSize { actual, maximum } => {
                write!(
                    formatter,
                    "invalid ifac size: actual {actual}, maximum {maximum}"
                )
            }
            Self::InvalidIfacKey => formatter.write_str("invalid ifac key"),
            Self::MissingPacketAccessCode => formatter.write_str("missing packet access code"),
            Self::InvalidPacketAccessCode => formatter.write_str("invalid packet access code"),
            Self::DestinationMismatch => formatter.write_str("destination mismatch"),
            Self::TimestampOverflow => formatter.write_str("timestamp overflow"),
            Self::RandomSourceFailed => formatter.write_str("random source failed"),
            Self::InvalidDestinationName => formatter.write_str("invalid destination name"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RnsWireError;

    #[test]
    fn wire_errors_have_stable_display_text() {
        assert_eq!(
            RnsWireError::UnsupportedPacketAccessCode.to_string(),
            "unsupported packet access code"
        );
        assert_eq!(
            RnsWireError::PacketTooShort {
                actual: 1,
                minimum: 2,
            }
            .to_string(),
            "packet too short: actual 1, minimum 2"
        );
        assert_eq!(
            RnsWireError::OutputBufferTooShort {
                actual: 3,
                required: 4,
            }
            .to_string(),
            "output buffer too short: actual 3, required 4"
        );
        assert_eq!(
            RnsWireError::InvalidDestinationName.to_string(),
            "invalid destination name"
        );
        assert_eq!(
            RnsWireError::InvalidIfacSize {
                actual: 65,
                maximum: 64,
            }
            .to_string(),
            "invalid ifac size: actual 65, maximum 64"
        );
        assert_eq!(
            RnsWireError::InvalidPacketAccessCode.to_string(),
            "invalid packet access code"
        );
    }
}
