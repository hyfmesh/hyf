use core::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MessageId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CommunityId(pub [u8; 16]);

pub const FOREIGN_ENDPOINT_MAX_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ForeignNetworkKind {
    Fips = 0,
    Rns = 1,
    Nostr = 2,
    Lxmf = 3,
    BitChat = 4,
}

impl ForeignNetworkKind {
    pub const fn wire_tag(self) -> u8 {
        self as u8
    }

    pub const fn from_wire_tag(tag: u8) -> Result<Self, ForeignEndpointError> {
        match tag {
            0 => Ok(Self::Fips),
            1 => Ok(Self::Rns),
            2 => Ok(Self::Nostr),
            3 => Ok(Self::Lxmf),
            4 => Ok(Self::BitChat),
            _ => Err(ForeignEndpointError::InvalidNetworkTag { tag }),
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ForeignEndpointId {
    network: ForeignNetworkKind,
    bytes: [u8; FOREIGN_ENDPOINT_MAX_LEN],
    len: u8,
}

impl fmt::Debug for ForeignEndpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForeignEndpointId")
            .field("network", &self.network)
            .field("bytes", &"<redacted>")
            .field("len", &self.len())
            .finish()
    }
}

impl ForeignEndpointId {
    pub fn new(network: ForeignNetworkKind, bytes: &[u8]) -> Result<Self, ForeignEndpointError> {
        let len = bytes.len();
        if len == 0 {
            return Err(ForeignEndpointError::Empty);
        }
        if len > FOREIGN_ENDPOINT_MAX_LEN {
            return Err(ForeignEndpointError::TooLong {
                actual: len,
                maximum: FOREIGN_ENDPOINT_MAX_LEN,
            });
        }

        let mut fixed = [0; FOREIGN_ENDPOINT_MAX_LEN];
        fixed[..len].copy_from_slice(bytes);

        Ok(Self {
            network,
            bytes: fixed,
            len: len as u8,
        })
    }

    pub fn from_fixed_16(network: ForeignNetworkKind, bytes: [u8; 16]) -> Self {
        let mut fixed = [0; FOREIGN_ENDPOINT_MAX_LEN];
        fixed[..16].copy_from_slice(&bytes);
        Self {
            network,
            bytes: fixed,
            len: 16,
        }
    }

    pub const fn from_fixed_32(network: ForeignNetworkKind, bytes: [u8; 32]) -> Self {
        Self {
            network,
            bytes,
            len: 32,
        }
    }

    pub const fn network(&self) -> ForeignNetworkKind {
        self.network
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForeignEndpointError {
    Empty,
    TooLong { actual: usize, maximum: usize },
    InvalidNetworkTag { tag: u8 },
}

impl fmt::Display for ForeignEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("foreign endpoint is empty"),
            Self::TooLong { actual, maximum } => {
                write!(
                    formatter,
                    "foreign endpoint too long: actual {actual}, maximum {maximum}"
                )
            }
            Self::InvalidNetworkTag { tag } => {
                write!(formatter, "invalid foreign network tag: {tag}")
            }
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for ForeignEndpointError {}

#[cfg(test)]
mod tests {
    use super::{
        CommunityId, FOREIGN_ENDPOINT_MAX_LEN, ForeignEndpointError, ForeignEndpointId,
        ForeignNetworkKind, MessageId, NodeId,
    };

    #[test]
    fn node_ids_are_copyable_and_comparable() {
        let first = NodeId([1; 32]);
        let second = first;

        assert_eq!(first, second);
    }

    #[test]
    fn message_ids_preserve_bytes() {
        let bytes = [2; 32];
        let id = MessageId(bytes);

        assert_eq!(id.0, bytes);
    }

    #[test]
    fn community_ids_use_sixteen_bytes() {
        let bytes = [3; 16];
        let id = CommunityId(bytes);

        assert_eq!(id.0, bytes);
    }

    #[test]
    fn foreign_network_tags_are_stable() {
        assert_eq!(ForeignNetworkKind::Fips.wire_tag(), 0);
        assert_eq!(ForeignNetworkKind::Rns.wire_tag(), 1);
        assert_eq!(ForeignNetworkKind::Nostr.wire_tag(), 2);
        assert_eq!(ForeignNetworkKind::Lxmf.wire_tag(), 3);
        assert_eq!(ForeignNetworkKind::BitChat.wire_tag(), 4);
        assert_eq!(
            ForeignNetworkKind::from_wire_tag(5),
            Err(ForeignEndpointError::InvalidNetworkTag { tag: 5 })
        );
    }

    #[test]
    fn foreign_endpoint_rejects_empty_and_oversized_ids() {
        assert_eq!(
            ForeignEndpointId::new(ForeignNetworkKind::Fips, &[]),
            Err(ForeignEndpointError::Empty)
        );
        assert_eq!(
            ForeignEndpointId::new(ForeignNetworkKind::Fips, &[7; FOREIGN_ENDPOINT_MAX_LEN + 1]),
            Err(ForeignEndpointError::TooLong {
                actual: FOREIGN_ENDPOINT_MAX_LEN + 1,
                maximum: FOREIGN_ENDPOINT_MAX_LEN,
            })
        );
    }

    #[test]
    fn foreign_endpoint_preserves_sixteen_and_thirty_two_byte_ids() {
        let fips_16 = ForeignEndpointId::from_fixed_16(ForeignNetworkKind::Fips, [0x11; 16]);
        let fips_32 = ForeignEndpointId::from_fixed_32(ForeignNetworkKind::Fips, [0x22; 32]);

        assert_eq!(fips_16.network(), ForeignNetworkKind::Fips);
        assert_eq!(fips_16.as_bytes(), &[0x11; 16]);
        assert_eq!(fips_32.as_bytes(), &[0x22; 32]);
    }

    #[test]
    fn foreign_endpoint_debug_redacts_identifier_bytes() -> Result<(), ForeignEndpointError> {
        let endpoint = ForeignEndpointId::new(ForeignNetworkKind::BitChat, b"secret")?;
        let debug = format!("{endpoint:?}");

        assert!(debug.contains("ForeignEndpointId"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }
}
