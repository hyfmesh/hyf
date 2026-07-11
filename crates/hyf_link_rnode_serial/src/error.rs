use core::fmt;

use hyf_link_kiss::KissError;
use hyf_link_rnode::RNodeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeSerialError {
    InvalidMtu { mtu: usize },
    InvalidFrameCapacity { mtu: usize, capacity: usize },
    ReadBufferTooSmall { actual: usize, required: usize },
    WriteBufferFull { required: usize, capacity: usize },
    InjectedReadFailure,
    InjectedWriteFailure,
    FlowControlBlocked,
    Kiss(KissError),
    RNode(RNodeError),
}

impl fmt::Display for RNodeSerialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMtu { mtu } => write!(formatter, "invalid rnode serial mtu: {mtu}"),
            Self::InvalidFrameCapacity { mtu, capacity } => write!(
                formatter,
                "rnode serial frame capacity too small: mtu {mtu}, capacity {capacity}"
            ),
            Self::ReadBufferTooSmall { actual, required } => write!(
                formatter,
                "rnode serial read buffer too small: actual {actual}, required {required}"
            ),
            Self::WriteBufferFull { required, capacity } => write!(
                formatter,
                "rnode serial write buffer full: required {required}, capacity {capacity}"
            ),
            Self::InjectedReadFailure => formatter.write_str("injected rnode serial read failure"),
            Self::InjectedWriteFailure => {
                formatter.write_str("injected rnode serial write failure")
            }
            Self::FlowControlBlocked => formatter.write_str("rnode serial flow control blocked"),
            Self::Kiss(error) => write!(formatter, "kiss error: {error}"),
            Self::RNode(error) => write!(formatter, "rnode error: {error}"),
        }
    }
}

impl From<KissError> for RNodeSerialError {
    fn from(error: KissError) -> Self {
        Self::Kiss(error)
    }
}

impl From<RNodeError> for RNodeSerialError {
    fn from(error: RNodeError) -> Self {
        Self::RNode(error)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for RNodeSerialError {}

#[cfg(test)]
mod tests {
    use super::RNodeSerialError;

    #[test]
    fn errors_have_stable_display_text() {
        assert_eq!(
            RNodeSerialError::InvalidMtu { mtu: 0 }.to_string(),
            "invalid rnode serial mtu: 0"
        );
        assert_eq!(
            RNodeSerialError::WriteBufferFull {
                required: 5,
                capacity: 4,
            }
            .to_string(),
            "rnode serial write buffer full: required 5, capacity 4"
        );
        assert_eq!(
            RNodeSerialError::FlowControlBlocked.to_string(),
            "rnode serial flow control blocked"
        );
    }
}
