use core::fmt;

use hyf_config::ConfigError;
use hyf_link::{LinkDriverError, LinkDriverErrorKind, LinkId};
use hyf_link_loopback::LoopbackError;
use hyf_router::RouterError;
use hyf_store::StoreError;
use hyf_wire::HyfWireError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    Config(ConfigError),
    Router(RouterError),
    Store(StoreError),
    Wire(HyfWireError),
    Loopback(LoopbackError),
    UnsupportedLink {
        link_id: LinkId,
    },
    Driver {
        link_id: LinkId,
        kind: LinkDriverErrorKind,
    },
    RuntimeCapacity {
        name: &'static str,
        configured: usize,
        maximum: usize,
    },
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::Router(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::UnsupportedLink { link_id } => {
                write!(formatter, "unsupported gateway link {link_id:?}")
            }
            Self::Driver { link_id, kind } => {
                write!(
                    formatter,
                    "gateway driver error on link {link_id:?}: {kind:?}"
                )
            }
            Self::RuntimeCapacity {
                name,
                configured,
                maximum,
            } => {
                write!(
                    formatter,
                    "gateway {name} capacity mismatch: configured {configured}, maximum {maximum}"
                )
            }
        }
    }
}

impl GatewayError {
    pub fn is_recoverable_send_failure(&self) -> bool {
        match self {
            Self::Driver { kind, .. } => kind.is_recoverable_send_failure(),
            Self::Loopback(error) => error.driver_error_kind().is_recoverable_send_failure(),
            _ => false,
        }
    }
}

impl From<ConfigError> for GatewayError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<RouterError> for GatewayError {
    fn from(error: RouterError) -> Self {
        Self::Router(error)
    }
}

impl From<StoreError> for GatewayError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<HyfWireError> for GatewayError {
    fn from(error: HyfWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<LoopbackError> for GatewayError {
    fn from(error: LoopbackError) -> Self {
        Self::Loopback(error)
    }
}

impl std::error::Error for GatewayError {}

#[cfg(test)]
mod tests {
    use hyf_link::LinkId;

    use super::GatewayError;

    #[test]
    fn gateway_errors_have_stable_display_text() {
        assert_eq!(
            GatewayError::UnsupportedLink {
                link_id: LinkId([1; 16]),
            }
            .to_string(),
            "unsupported gateway link LinkId([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])"
        );
        assert_eq!(
            GatewayError::RuntimeCapacity {
                name: "store",
                configured: 3,
                maximum: 2,
            }
            .to_string(),
            "gateway store capacity mismatch: configured 3, maximum 2"
        );
        assert_eq!(
            GatewayError::Driver {
                link_id: LinkId([2; 16]),
                kind: hyf_link::LinkDriverErrorKind::Backpressure,
            }
            .to_string(),
            "gateway driver error on link LinkId([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]): Backpressure"
        );
    }

    #[test]
    fn gateway_errors_classify_recoverable_send_failures() {
        assert!(
            GatewayError::Driver {
                link_id: LinkId([1; 16]),
                kind: hyf_link::LinkDriverErrorKind::Backpressure,
            }
            .is_recoverable_send_failure()
        );
        assert!(
            GatewayError::Loopback(hyf_link_loopback::LoopbackError::Down {
                link_id: LinkId([1; 16]),
            })
            .is_recoverable_send_failure()
        );
        assert!(
            !GatewayError::UnsupportedLink {
                link_id: LinkId([1; 16]),
            }
            .is_recoverable_send_failure()
        );
    }
}
