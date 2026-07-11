use core::fmt;

use hyf_rns_wire::decode_packet;

use crate::HyfLinkRnsError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RnsPacketRef<'a> {
    pub raw: &'a [u8],
    pub destination_hash: [u8; 16],
}

impl fmt::Debug for RnsPacketRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnsPacketRef")
            .field("raw", &"<redacted>")
            .field("raw_len", &self.raw.len())
            .field("destination_hash", &self.destination_hash)
            .finish()
    }
}

pub fn validate_rns_packet(raw: &[u8]) -> Result<RnsPacketRef<'_>, HyfLinkRnsError> {
    let packet = decode_packet(raw)?;
    Ok(RnsPacketRef {
        raw,
        destination_hash: packet.destination_hash.into_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use hyf_rns_wire::RnsWireError;

    use super::validate_rns_packet;
    use crate::HyfLinkRnsError;

    const HEADER_1_PACKET: &[u8] = &[
        0x00, 0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x00, b'h', b'e', b'a', b'd', b'e', b'r', b'-', b'o', b'n', b'e',
    ];

    #[test]
    fn validate_accepts_valid_rns_packet_and_extracts_destination_hash()
    -> Result<(), HyfLinkRnsError> {
        let packet = validate_rns_packet(HEADER_1_PACKET)?;

        assert_eq!(packet.raw, HEADER_1_PACKET);
        assert_eq!(
            packet.destination_hash,
            [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                0x1f, 0x20,
            ]
        );
        Ok(())
    }

    #[test]
    fn validate_rejects_empty_too_short_and_malformed_packets() {
        assert_eq!(
            validate_rns_packet(&[]),
            Err(HyfLinkRnsError::RnsWire(RnsWireError::PacketTooShort {
                actual: 0,
                minimum: 1,
            }))
        );
        assert!(validate_rns_packet(&[0x00, 0x00]).is_err());
        assert_eq!(
            validate_rns_packet(&[0x80]),
            Err(HyfLinkRnsError::RnsWire(
                RnsWireError::UnsupportedPacketAccessCode
            ))
        );
    }

    #[test]
    fn packet_debug_redacts_raw_bytes() -> Result<(), HyfLinkRnsError> {
        let packet = validate_rns_packet(HEADER_1_PACKET)?;
        let debug = format!("{packet:?}");

        assert!(debug.contains("RnsPacketRef"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("raw_len"));
        assert!(!debug.contains("header-one"));
        assert!(!debug.contains("104, 101, 97"));
        Ok(())
    }
}
