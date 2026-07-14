use core::fmt;

use sha2::{Digest, Sha256};

use crate::FipsError;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FipsPublicKey([u8; 32]);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FipsNodeAddr([u8; 16]);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FipsIpv6Addr([u8; 16]);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FipsEndpoint {
    public_key: FipsPublicKey,
    node_addr: FipsNodeAddr,
    ipv6_addr: FipsIpv6Addr,
}

impl FipsPublicKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FipsNodeAddr {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl FipsIpv6Addr {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl FipsEndpoint {
    pub fn from_public_key(public_key: FipsPublicKey) -> Self {
        derive_fips_endpoint(public_key)
    }

    pub fn from_parts(
        public_key: FipsPublicKey,
        node_addr: FipsNodeAddr,
        ipv6_addr: FipsIpv6Addr,
    ) -> Result<Self, FipsError> {
        let endpoint = Self {
            public_key,
            node_addr,
            ipv6_addr,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn validate(&self) -> Result<(), FipsError> {
        let expected_node_addr = derive_fips_node_addr(self.public_key);
        let expected_ipv6_addr = derive_fips_ipv6_addr(expected_node_addr);
        if self.node_addr == expected_node_addr && self.ipv6_addr == expected_ipv6_addr {
            Ok(())
        } else {
            Err(FipsError::InvalidEndpoint)
        }
    }

    pub const fn public_key(&self) -> FipsPublicKey {
        self.public_key
    }

    pub const fn node_addr(&self) -> FipsNodeAddr {
        self.node_addr
    }

    pub const fn ipv6_addr(&self) -> FipsIpv6Addr {
        self.ipv6_addr
    }
}

pub fn derive_fips_node_addr(public_key: FipsPublicKey) -> FipsNodeAddr {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let digest = hasher.finalize();
    let mut node_addr = [0; 16];
    node_addr.copy_from_slice(&digest[..16]);
    FipsNodeAddr(node_addr)
}

pub fn derive_fips_ipv6_addr(node_addr: FipsNodeAddr) -> FipsIpv6Addr {
    let mut ipv6_addr = [0; 16];
    ipv6_addr[0] = 0xfd;
    ipv6_addr[1..].copy_from_slice(&node_addr.as_bytes()[..15]);
    FipsIpv6Addr(ipv6_addr)
}

pub fn derive_fips_endpoint(public_key: FipsPublicKey) -> FipsEndpoint {
    let node_addr = derive_fips_node_addr(public_key);
    let ipv6_addr = derive_fips_ipv6_addr(node_addr);
    FipsEndpoint {
        public_key,
        node_addr,
        ipv6_addr,
    }
}

impl fmt::Debug for FipsPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FipsPublicKey")
            .field("bytes", &"<redacted>")
            .field("len", &self.0.len())
            .finish()
    }
}

impl fmt::Debug for FipsNodeAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FipsNodeAddr")
            .field("bytes", &"<redacted>")
            .field("len", &self.0.len())
            .finish()
    }
}

impl fmt::Debug for FipsIpv6Addr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FipsIpv6Addr")
            .field("bytes", &"<redacted>")
            .field("len", &self.0.len())
            .finish()
    }
}

impl fmt::Debug for FipsEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FipsEndpoint")
            .field("public_key", &self.public_key)
            .field("node_addr", &self.node_addr)
            .field("ipv6_addr", &self.ipv6_addr)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FipsEndpoint, FipsIpv6Addr, FipsNodeAddr, FipsPublicKey, derive_fips_endpoint,
        derive_fips_ipv6_addr, derive_fips_node_addr,
    };
    use crate::FipsError;

    #[test]
    fn identity_vectors_match_approved_formula() {
        let zero_key = FipsPublicKey::from_bytes([0; 32]);
        let one_key = FipsPublicKey::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let repeated_key = FipsPublicKey::from_bytes([0x11; 32]);

        assert_eq!(
            derive_fips_node_addr(zero_key).as_bytes(),
            &[
                0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f,
                0x8e, 0x20,
            ]
        );
        assert_eq!(
            derive_fips_node_addr(one_key).as_bytes(),
            &[
                0xec, 0x49, 0x16, 0xdd, 0x28, 0xfc, 0x4c, 0x10, 0xd7, 0x8e, 0x28, 0x7c, 0xa5, 0xd9,
                0xcc, 0x51,
            ]
        );
        assert_eq!(
            derive_fips_node_addr(repeated_key).as_bytes(),
            &[
                0x02, 0xd4, 0x49, 0xa3, 0x1f, 0xbb, 0x26, 0x7c, 0x8f, 0x35, 0x2e, 0x99, 0x68, 0xa7,
                0x9e, 0x3e,
            ]
        );
    }

    #[test]
    fn ipv6_addr_uses_fd_prefix_and_first_fifteen_node_bytes() {
        let node_addr = FipsNodeAddr::from_bytes([
            0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f,
            0x8e, 0x20,
        ]);

        assert_eq!(
            derive_fips_ipv6_addr(node_addr).as_bytes(),
            &[
                0xfd, 0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e,
                0x9f, 0x8e,
            ]
        );
    }

    #[test]
    fn endpoint_from_public_key_derives_consistent_parts() -> Result<(), FipsError> {
        let public_key = FipsPublicKey::from_bytes([0xff; 32]);
        let endpoint = FipsEndpoint::from_public_key(public_key);

        assert_eq!(endpoint.public_key(), public_key);
        assert_eq!(endpoint.node_addr(), derive_fips_node_addr(public_key));
        assert_eq!(
            endpoint.ipv6_addr(),
            derive_fips_ipv6_addr(endpoint.node_addr())
        );
        endpoint.validate()
    }

    #[test]
    fn endpoint_from_parts_rejects_inconsistent_parts() {
        let public_key = FipsPublicKey::from_bytes([0x11; 32]);
        let node_addr = derive_fips_node_addr(public_key);
        let wrong_ipv6_addr = FipsIpv6Addr::from_bytes([0xfd; 16]);

        assert!(matches!(
            FipsEndpoint::from_parts(public_key, node_addr, wrong_ipv6_addr),
            Err(FipsError::InvalidEndpoint)
        ));
    }

    #[test]
    fn endpoint_from_parts_accepts_consistent_parts() -> Result<(), FipsError> {
        let public_key = FipsPublicKey::from_bytes([0x11; 32]);
        let node_addr = derive_fips_node_addr(public_key);
        let ipv6_addr = derive_fips_ipv6_addr(node_addr);
        let endpoint = FipsEndpoint::from_parts(public_key, node_addr, ipv6_addr)?;

        assert_eq!(endpoint, derive_fips_endpoint(public_key));
        Ok(())
    }

    #[test]
    fn debug_output_redacts_key_and_endpoint_bytes() {
        let public_key = FipsPublicKey::from_bytes([0x42; 32]);
        let endpoint = derive_fips_endpoint(public_key);

        for debug in [
            format!("{public_key:?}"),
            format!("{:?}", endpoint.node_addr()),
            format!("{:?}", endpoint.ipv6_addr()),
            format!("{endpoint:?}"),
        ] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("42, 42"));
            assert!(!debug.contains("424242"));
            assert!(!debug.contains("0x42"));
        }
    }
}
