use core::fmt;

use crate::{BitchatFlags, BitchatPeerId, BitchatSignature, BitchatVersion};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BitchatRouteRef<'a> {
    pub hop_count: u8,
    pub raw_hops: &'a [u8],
}

impl fmt::Debug for BitchatRouteRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitchatRouteRef")
            .field("hop_count", &self.hop_count)
            .field("raw_hops", &"<redacted>")
            .field("raw_hops_len", &self.raw_hops.len())
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum BitchatPayloadRef<'a> {
    Plain(&'a [u8]),
    Compressed {
        original_len: usize,
        compressed_bytes: &'a [u8],
    },
}

impl fmt::Debug for BitchatPayloadRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(bytes) => formatter
                .debug_tuple("Plain")
                .field(&"<redacted>")
                .field(&bytes.len())
                .finish(),
            Self::Compressed {
                original_len,
                compressed_bytes,
            } => formatter
                .debug_struct("Compressed")
                .field("original_len", original_len)
                .field("compressed_bytes", &"<redacted>")
                .field("compressed_bytes_len", &compressed_bytes.len())
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BitchatPacketRef<'a> {
    pub version: BitchatVersion,
    pub packet_type: u8,
    pub ttl: u8,
    pub timestamp: u64,
    pub flags: BitchatFlags,
    pub sender_id: BitchatPeerId,
    pub recipient_id: Option<BitchatPeerId>,
    pub route: Option<BitchatRouteRef<'a>>,
    pub payload: BitchatPayloadRef<'a>,
    pub signature: Option<BitchatSignature>,
}

impl fmt::Debug for BitchatPacketRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitchatPacketRef")
            .field("version", &self.version)
            .field("packet_type", &self.packet_type)
            .field("ttl", &self.ttl)
            .field("timestamp", &self.timestamp)
            .field("flags", &self.flags)
            .field("sender_id", &self.sender_id)
            .field("recipient_id", &self.recipient_id)
            .field("route", &self.route)
            .field("payload", &self.payload)
            .field("signature", &"<redacted>")
            .field("has_signature", &self.signature.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{BitchatPacketRef, BitchatPayloadRef, BitchatRouteRef};
    use crate::{BitchatFlags, BitchatPeerId, BitchatSignature, BitchatVersion};

    #[test]
    fn packet_refs_preserve_borrowed_fields() {
        let route_hops = [1; 16];
        let payload = b"hello";
        let packet = BitchatPacketRef {
            version: BitchatVersion::V2,
            packet_type: 0x7f,
            ttl: 0,
            timestamp: 0,
            flags: BitchatFlags {
                has_recipient: true,
                has_signature: true,
                is_compressed: false,
                has_route: true,
                is_rsr: true,
            },
            sender_id: BitchatPeerId::from_bytes([2; 8]),
            recipient_id: Some(BitchatPeerId::from_bytes([3; 8])),
            route: Some(BitchatRouteRef {
                hop_count: 2,
                raw_hops: &route_hops,
            }),
            payload: BitchatPayloadRef::Plain(payload),
            signature: Some(BitchatSignature::from_bytes([4; 64])),
        };

        assert_eq!(
            packet.route,
            Some(BitchatRouteRef {
                hop_count: 2,
                raw_hops: &route_hops,
            })
        );
        assert_eq!(packet.payload, BitchatPayloadRef::Plain(payload));
        assert_eq!(packet.packet_type, 0x7f);
    }

    #[test]
    fn packet_debug_redacts_route_payload_and_signature_bytes() {
        let route_hops = b"secret-route-hop";
        let payload = b"secret-payload";
        let packet = BitchatPacketRef {
            version: BitchatVersion::V2,
            packet_type: 1,
            ttl: 5,
            timestamp: 10,
            flags: BitchatFlags::empty(),
            sender_id: BitchatPeerId::from_bytes([1; 8]),
            recipient_id: None,
            route: Some(BitchatRouteRef {
                hop_count: 1,
                raw_hops: route_hops,
            }),
            payload: BitchatPayloadRef::Compressed {
                original_len: 128,
                compressed_bytes: payload,
            },
            signature: Some(BitchatSignature::from_bytes([9; 64])),
        };
        let debug = format!("{packet:?}");

        assert!(debug.contains("BitchatPacketRef"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-route-hop"));
        assert!(!debug.contains("secret-payload"));
        assert!(!debug.contains("9, 9"));
    }
}
