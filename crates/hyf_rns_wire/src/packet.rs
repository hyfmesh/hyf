use hyf_rns_core::{
    RNS_HEADER_1_LEN, RNS_HEADER_2_LEN, RNS_MTU, RNS_TRUNCATED_HASH_LEN, RnsDestinationHash,
};

use crate::{RnsHeaderType, RnsPacketFlags, RnsWireError, decode_flags};

const FLAGS_INDEX: usize = 0;
const HOPS_INDEX: usize = 1;
const HEADER_1_DESTINATION_START: usize = 2;
const HEADER_1_DESTINATION_END: usize = HEADER_1_DESTINATION_START + RNS_TRUNCATED_HASH_LEN;
const HEADER_1_CONTEXT_INDEX: usize = HEADER_1_DESTINATION_END;
const HEADER_1_DATA_START: usize = HEADER_1_CONTEXT_INDEX + 1;
const HEADER_2_TRANSPORT_START: usize = 2;
const HEADER_2_TRANSPORT_END: usize = HEADER_2_TRANSPORT_START + RNS_TRUNCATED_HASH_LEN;
const HEADER_2_DESTINATION_START: usize = HEADER_2_TRANSPORT_END;
const HEADER_2_DESTINATION_END: usize = HEADER_2_DESTINATION_START + RNS_TRUNCATED_HASH_LEN;
const HEADER_2_CONTEXT_INDEX: usize = HEADER_2_DESTINATION_END;
const HEADER_2_DATA_START: usize = HEADER_2_CONTEXT_INDEX + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnsPacketRef<'a> {
    pub flags: RnsPacketFlags,
    pub hops: u8,
    pub transport_id: Option<[u8; RNS_TRUNCATED_HASH_LEN]>,
    pub destination_hash: RnsDestinationHash,
    pub context: u8,
    pub data: &'a [u8],
}

pub fn decode_packet(input: &[u8]) -> Result<RnsPacketRef<'_>, RnsWireError> {
    if input.len() > RNS_MTU {
        return Err(RnsWireError::PacketTooLarge {
            actual: input.len(),
            maximum: RNS_MTU,
        });
    }

    if input.is_empty() {
        return Err(RnsWireError::PacketTooShort {
            actual: input.len(),
            minimum: 1,
        });
    }

    let flags = decode_flags(input[FLAGS_INDEX])?;
    let minimum = header_len(flags.header_type);
    if input.len() < minimum {
        return Err(RnsWireError::PacketTooShort {
            actual: input.len(),
            minimum,
        });
    }

    match flags.header_type {
        RnsHeaderType::Header1 => decode_header_1_packet(input, flags),
        RnsHeaderType::Header2 => decode_header_2_packet(input, flags),
    }
}

const fn header_len(header_type: RnsHeaderType) -> usize {
    match header_type {
        RnsHeaderType::Header1 => RNS_HEADER_1_LEN,
        RnsHeaderType::Header2 => RNS_HEADER_2_LEN,
    }
}

fn decode_header_1_packet<'a>(
    input: &'a [u8],
    flags: RnsPacketFlags,
) -> Result<RnsPacketRef<'a>, RnsWireError> {
    Ok(RnsPacketRef {
        flags,
        hops: input[HOPS_INDEX],
        transport_id: None,
        destination_hash: RnsDestinationHash::new(read_truncated_hash(
            &input[HEADER_1_DESTINATION_START..HEADER_1_DESTINATION_END],
        )),
        context: input[HEADER_1_CONTEXT_INDEX],
        data: &input[HEADER_1_DATA_START..],
    })
}

fn decode_header_2_packet<'a>(
    input: &'a [u8],
    flags: RnsPacketFlags,
) -> Result<RnsPacketRef<'a>, RnsWireError> {
    Ok(RnsPacketRef {
        flags,
        hops: input[HOPS_INDEX],
        transport_id: Some(read_truncated_hash(
            &input[HEADER_2_TRANSPORT_START..HEADER_2_TRANSPORT_END],
        )),
        destination_hash: RnsDestinationHash::new(read_truncated_hash(
            &input[HEADER_2_DESTINATION_START..HEADER_2_DESTINATION_END],
        )),
        context: input[HEADER_2_CONTEXT_INDEX],
        data: &input[HEADER_2_DATA_START..],
    })
}

fn read_truncated_hash(input: &[u8]) -> [u8; RNS_TRUNCATED_HASH_LEN] {
    let mut output = [0; RNS_TRUNCATED_HASH_LEN];
    output.copy_from_slice(input);
    output
}

#[cfg(test)]
mod tests {
    use hyf_rns_core::{RNS_HEADER_1_LEN, RNS_HEADER_2_LEN, RNS_MTU};

    use super::decode_packet;
    use crate::{
        RNS_CONTEXT_NONE, RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketType,
        RnsTransportType, RnsWireError, encode_flags,
    };

    #[test]
    fn decodes_header_1_packet_and_borrows_payload() -> Result<(), RnsWireError> {
        let data = [0xaa, 0xbb, 0xcc];
        let raw = header_1_packet(&data);
        let packet = decode_packet(&raw)?;

        assert_eq!(packet.flags.header_type, RnsHeaderType::Header1);
        assert_eq!(packet.hops, 7);
        assert_eq!(packet.transport_id, None);
        assert_eq!(packet.destination_hash.as_bytes(), &[0x11; 16]);
        assert_eq!(packet.context, RNS_CONTEXT_NONE);
        assert_eq!(packet.data, data);
        assert_eq!(packet.data.as_ptr(), raw[RNS_HEADER_1_LEN..].as_ptr());

        Ok(())
    }

    #[test]
    fn decodes_header_2_packet_with_transport_id() -> Result<(), RnsWireError> {
        let data = [0x44, 0x55];
        let raw = header_2_packet(&data);
        let packet = decode_packet(&raw)?;

        assert_eq!(packet.flags.header_type, RnsHeaderType::Header2);
        assert_eq!(packet.hops, 9);
        assert_eq!(packet.transport_id, Some([0x22; 16]));
        assert_eq!(packet.destination_hash.as_bytes(), &[0x33; 16]);
        assert_eq!(packet.context, RNS_CONTEXT_NONE);
        assert_eq!(packet.data, data);
        assert_eq!(packet.data.as_ptr(), raw[RNS_HEADER_2_LEN..].as_ptr());

        Ok(())
    }

    #[test]
    fn rejects_packets_larger_than_mtu() {
        let oversized = [0; RNS_MTU + 1];

        assert_eq!(
            decode_packet(&oversized),
            Err(RnsWireError::PacketTooLarge {
                actual: RNS_MTU + 1,
                maximum: RNS_MTU,
            })
        );
    }

    #[test]
    fn rejects_too_short_header_1_before_slicing() {
        let mut raw = [0; RNS_HEADER_1_LEN - 1];
        raw[0] = encode_flags(header_1_flags());

        assert_eq!(
            decode_packet(&raw),
            Err(RnsWireError::PacketTooShort {
                actual: RNS_HEADER_1_LEN - 1,
                minimum: RNS_HEADER_1_LEN,
            })
        );
    }

    #[test]
    fn rejects_too_short_header_2_before_slicing() {
        let mut raw = [0; RNS_HEADER_2_LEN - 1];
        raw[0] = encode_flags(header_2_flags());

        assert_eq!(
            decode_packet(&raw),
            Err(RnsWireError::PacketTooShort {
                actual: RNS_HEADER_2_LEN - 1,
                minimum: RNS_HEADER_2_LEN,
            })
        );
    }

    #[test]
    fn rejects_empty_packets_before_reading_flags() {
        assert_eq!(
            decode_packet(&[]),
            Err(RnsWireError::PacketTooShort {
                actual: 0,
                minimum: 1,
            })
        );
    }

    #[test]
    fn rejects_ifac_flag_during_packet_decode() {
        let mut raw = header_1_packet(&[]);
        raw[0] |= 0b1000_0000;

        assert_eq!(
            decode_packet(&raw),
            Err(RnsWireError::UnsupportedPacketAccessCode)
        );
    }

    fn header_1_packet(data: &[u8]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(RNS_HEADER_1_LEN + data.len());
        raw.push(encode_flags(header_1_flags()));
        raw.push(7);
        raw.extend_from_slice(&[0x11; 16]);
        raw.push(RNS_CONTEXT_NONE);
        raw.extend_from_slice(data);
        raw
    }

    const fn header_1_flags() -> RnsPacketFlags {
        RnsPacketFlags {
            header_type: RnsHeaderType::Header1,
            context_flag: false,
            transport_type: RnsTransportType::Broadcast,
            destination_type: RnsDestinationType::Single,
            packet_type: RnsPacketType::Announce,
        }
    }

    fn header_2_packet(data: &[u8]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(RNS_HEADER_2_LEN + data.len());
        raw.push(encode_flags(header_2_flags()));
        raw.push(9);
        raw.extend_from_slice(&[0x22; 16]);
        raw.extend_from_slice(&[0x33; 16]);
        raw.push(RNS_CONTEXT_NONE);
        raw.extend_from_slice(data);
        raw
    }

    const fn header_2_flags() -> RnsPacketFlags {
        RnsPacketFlags {
            header_type: RnsHeaderType::Header2,
            context_flag: true,
            transport_type: RnsTransportType::Transport,
            destination_type: RnsDestinationType::Group,
            packet_type: RnsPacketType::Data,
        }
    }
}
