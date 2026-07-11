#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod core;
mod error;
mod metrics;
mod runtime;

pub use core::{GATEWAY_FRAME_BUFFER_LEN, GatewayCore, GatewayLinkExecutor};
pub use error::GatewayError;
pub use metrics::GatewayMetrics;
pub use runtime::GatewayRuntime;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
