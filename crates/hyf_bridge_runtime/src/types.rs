use core::fmt;

use hyf_bridge_core::BridgeProtocol;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BridgeOrigin {
    pub protocol: BridgeProtocol,
    pub endpoint_hash: [u8; 32],
}

impl BridgeOrigin {
    pub const fn new(protocol: BridgeProtocol, endpoint_hash: [u8; 32]) -> Self {
        Self {
            protocol,
            endpoint_hash,
        }
    }
}

impl fmt::Debug for BridgeOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeOrigin")
            .field("protocol", &self.protocol)
            .field("endpoint_hash", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::BridgeOrigin;
    use hyf_bridge_core::BridgeProtocol;

    #[test]
    fn origin_preserves_protocol_and_redacts_endpoint_hash() {
        let origin = BridgeOrigin::new(BridgeProtocol::BitChat, [0x42; 32]);
        let debug = format!("{origin:?}");

        assert_eq!(origin.protocol, BridgeProtocol::BitChat);
        assert_eq!(origin.endpoint_hash, [0x42; 32]);
        assert!(debug.contains("BridgeOrigin"));
        assert!(debug.contains("BitChat"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("66"));
    }
}
