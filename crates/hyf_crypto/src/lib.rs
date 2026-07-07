#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Domain(&'static [u8]);

impl Domain {
    pub const fn new(bytes: &'static [u8]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> &'static [u8] {
        self.0
    }
}

pub const HYF_MESSAGE_ID_V1: Domain = Domain::new(b"hyf.message_id.v1");
pub const HYF_NODE_ANNOUNCE_V1: Domain = Domain::new(b"hyf.node_announce.v1");

pub fn domain_hash(domain: Domain, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.as_bytes().len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{HYF_MESSAGE_ID_V1, HYF_NODE_ANNOUNCE_V1, domain_hash};

    #[test]
    fn crate_builds() {}

    #[test]
    fn domain_hash_is_deterministic() {
        let first = domain_hash(HYF_MESSAGE_ID_V1, b"payload");
        let second = domain_hash(HYF_MESSAGE_ID_V1, b"payload");

        assert_eq!(first, second);
    }

    #[test]
    fn domain_hash_separates_domains() {
        let message_hash = domain_hash(HYF_MESSAGE_ID_V1, b"payload");
        let announce_hash = domain_hash(HYF_NODE_ANNOUNCE_V1, b"payload");

        assert_ne!(message_hash, announce_hash);
    }

    #[test]
    fn domain_hash_separates_payloads() {
        let first = domain_hash(HYF_MESSAGE_ID_V1, b"payload");
        let second = domain_hash(HYF_MESSAGE_ID_V1, b"payload!");

        assert_ne!(first, second);
    }
}
