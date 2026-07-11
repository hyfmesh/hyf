use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkError {
    FrameTooLarge { actual: usize, mtu: usize },
}

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { actual, mtu } => {
                write!(
                    formatter,
                    "link frame too large: actual {actual}, mtu {mtu}"
                )
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for LinkError {}

#[cfg(test)]
mod tests {
    use super::LinkError;

    #[test]
    fn link_errors_have_stable_display_text() {
        assert_eq!(
            LinkError::FrameTooLarge {
                actual: 101,
                mtu: 100,
            }
            .to_string(),
            "link frame too large: actual 101, mtu 100"
        );
    }
}
