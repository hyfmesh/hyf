#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorePolicy {
    pub reject_expired_on_put: bool,
}

impl StorePolicy {
    pub const fn new() -> Self {
        Self {
            reject_expired_on_put: true,
        }
    }
}

impl Default for StorePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::StorePolicy;

    #[test]
    fn default_policy_rejects_expired_envelopes() {
        assert!(StorePolicy::new().reject_expired_on_put);
        assert_eq!(StorePolicy::default(), StorePolicy::new());
    }
}
