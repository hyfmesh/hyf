#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod error;
mod metrics;
mod runtime;

pub use error::GatewayError;
pub use metrics::GatewayMetrics;
pub use runtime::{GATEWAY_FRAME_BUFFER_LEN, GatewayRuntime};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
