use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FipsError {
    LinkDown,
    UnknownPeer,
    DuplicatePeer,
    PeerTableFull { capacity: usize },
    InvalidEndpoint,
    FrameTooLarge { len: usize, mtu: usize },
    OutboundFull { capacity: usize },
    InboundFull { capacity: usize },
    OutputTooSmall { needed: usize, available: usize },
    ControlResponseTooLarge { len: usize, maximum: usize },
    MalformedControlStatus,
    Utf8,
}

impl fmt::Display for FipsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkDown => formatter.write_str("FIPS link is down"),
            Self::UnknownPeer => formatter.write_str("FIPS peer is not registered"),
            Self::DuplicatePeer => formatter.write_str("FIPS peer is already registered"),
            Self::PeerTableFull { capacity } => {
                write!(formatter, "FIPS peer table is full at capacity {capacity}")
            }
            Self::InvalidEndpoint => formatter.write_str("FIPS endpoint is invalid"),
            Self::FrameTooLarge { len, mtu } => {
                write!(formatter, "FIPS frame length {len} exceeds MTU {mtu}")
            }
            Self::OutboundFull { capacity } => {
                write!(
                    formatter,
                    "FIPS outbound queue is full at capacity {capacity}"
                )
            }
            Self::InboundFull { capacity } => {
                write!(
                    formatter,
                    "FIPS inbound queue is full at capacity {capacity}"
                )
            }
            Self::OutputTooSmall { needed, available } => write!(
                formatter,
                "FIPS output buffer length {available} is smaller than required length {needed}"
            ),
            Self::ControlResponseTooLarge { len, maximum } => write!(
                formatter,
                "FIPS control response length {len} exceeds maximum {maximum}"
            ),
            Self::MalformedControlStatus => formatter.write_str("FIPS control status is malformed"),
            Self::Utf8 => formatter.write_str("FIPS control response is not valid UTF-8"),
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for FipsError {}
