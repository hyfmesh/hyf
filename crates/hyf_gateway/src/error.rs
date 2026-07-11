use core::fmt;

use hyf_config::ConfigError;
use hyf_link::LinkId;
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
    }
}
