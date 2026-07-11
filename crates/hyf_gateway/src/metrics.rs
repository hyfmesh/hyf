#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayMetrics {
    pub submitted: u64,
    pub sent: u64,
    pub stored: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub expired: u64,
    pub link_errors: u64,
    pub bytes_sent: u64,
}

#[cfg(test)]
mod tests {
    use super::GatewayMetrics;

    #[test]
    fn metrics_debug_contains_only_counters() {
        let metrics = GatewayMetrics {
            submitted: 1,
            sent: 2,
            ..GatewayMetrics::default()
        };
        let debug = format!("{metrics:?}");

        assert!(debug.contains("submitted"));
        assert!(debug.contains("sent"));
        assert!(!debug.contains("payload"));
        assert!(!debug.contains("secret"));
    }
}
