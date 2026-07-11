use core::fmt;

use hyf_link::LinkId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopbackError {
    Down { link_id: LinkId },
    FrameTooLarge { actual: usize, mtu: usize },
    InternalFrameTooLarge { actual: usize, maximum: usize },
    QueueFull { link_id: LinkId, capacity: usize },
    OutputTooSmall { actual: usize, required: usize },
    LinkMismatch { expected: LinkId, actual: LinkId },
}

impl fmt::Display for LoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Down { link_id } => write!(formatter, "loopback link is down: {link_id:?}"),
            Self::FrameTooLarge { actual, mtu } => {
                write!(
                    formatter,
                    "loopback frame too large: actual {actual}, mtu {mtu}"
                )
            }
            Self::InternalFrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "loopback frame exceeds internal maximum: actual {actual}, maximum {maximum}"
                )
            }
            Self::QueueFull { link_id, capacity } => {
                write!(
                    formatter,
                    "loopback queue full: link {link_id:?}, capacity {capacity}"
                )
            }
            Self::OutputTooSmall { actual, required } => {
                write!(
                    formatter,
                    "loopback output too small: actual {actual}, required {required}"
                )
            }
            Self::LinkMismatch { expected, actual } => {
                write!(
                    formatter,
                    "loopback link mismatch: expected {expected:?}, actual {actual:?}"
                )
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for LoopbackError {}

#[cfg(test)]
mod tests {
    use hyf_link::LinkId;

    use super::LoopbackError;

    #[test]
    fn loopback_errors_have_stable_display_text() {
        assert_eq!(
            LoopbackError::FrameTooLarge { actual: 6, mtu: 5 }.to_string(),
            "loopback frame too large: actual 6, mtu 5"
        );
        assert_eq!(
            LoopbackError::OutputTooSmall {
                actual: 1,
                required: 2,
            }
            .to_string(),
            "loopback output too small: actual 1, required 2"
        );
        assert!(
            LoopbackError::Down {
                link_id: LinkId([1; 16]),
            }
            .to_string()
            .contains("loopback link is down")
        );
    }
}
