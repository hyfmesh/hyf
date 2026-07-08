use hyf_rns_core::{
    RNS_HEADER_1_LEN, RNS_HEADER_2_LEN, RNS_MTU, RNS_TRUNCATED_HASH_LEN, RnsDestinationHash,
};

use crate::{RnsHeaderType, RnsPacketFlags, RnsWireError, decode_flags, encode_flags};

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

pub fn encode_packet(packet: RnsPacketRef<'_>, output: &mut [u8]) -> Result<usize, RnsWireError> {
    let required = encoded_len(packet)?;
    if output.len() < required {
        return Err(RnsWireError::OutputBufferTooShort {
            actual: output.len(),
            required,
        });
    }
    let transport_id = validate_transport_id(packet)?;

    output[FLAGS_INDEX] = encode_flags(packet.flags);
    output[HOPS_INDEX] = packet.hops;

    match packet.flags.header_type {
        RnsHeaderType::Header1 => encode_header_1_packet(packet, output),
        RnsHeaderType::Header2 => {
            let Some(transport_id) = transport_id else {
                return Err(RnsWireError::MissingTransportId);
            };
            encode_header_2_packet(packet, output, transport_id);
        }
    }

    Ok(required)
}

fn encoded_len(packet: RnsPacketRef<'_>) -> Result<usize, RnsWireError> {
    let Some(required) = header_len(packet.flags.header_type).checked_add(packet.data.len()) else {
        return Err(RnsWireError::PacketTooLarge {
            actual: packet.data.len(),
            maximum: RNS_MTU,
        });
    };

    if required > RNS_MTU {
        return Err(RnsWireError::PacketTooLarge {
            actual: required,
            maximum: RNS_MTU,
        });
    }

    Ok(required)
}

fn validate_transport_id(
    packet: RnsPacketRef<'_>,
) -> Result<Option<[u8; RNS_TRUNCATED_HASH_LEN]>, RnsWireError> {
    match (packet.flags.header_type, packet.transport_id) {
        (RnsHeaderType::Header1, None) => Ok(None),
        (RnsHeaderType::Header2, Some(transport_id)) => Ok(Some(transport_id)),
        (RnsHeaderType::Header1, Some(_)) => Err(RnsWireError::UnexpectedTransportId),
        (RnsHeaderType::Header2, None) => Err(RnsWireError::MissingTransportId),
    }
}

const fn header_len(header_type: RnsHeaderType) -> usize {
    match header_type {
        RnsHeaderType::Header1 => RNS_HEADER_1_LEN,
        RnsHeaderType::Header2 => RNS_HEADER_2_LEN,
    }
}

fn encode_header_1_packet(packet: RnsPacketRef<'_>, output: &mut [u8]) {
    output[HEADER_1_DESTINATION_START..HEADER_1_DESTINATION_END]
        .copy_from_slice(packet.destination_hash.as_bytes());
    output[HEADER_1_CONTEXT_INDEX] = packet.context;
    output[HEADER_1_DATA_START..HEADER_1_DATA_START + packet.data.len()]
        .copy_from_slice(packet.data);
}

fn encode_header_2_packet(
    packet: RnsPacketRef<'_>,
    output: &mut [u8],
    transport_id: [u8; RNS_TRUNCATED_HASH_LEN],
) {
    output[HEADER_2_TRANSPORT_START..HEADER_2_TRANSPORT_END].copy_from_slice(&transport_id);
    output[HEADER_2_DESTINATION_START..HEADER_2_DESTINATION_END]
        .copy_from_slice(packet.destination_hash.as_bytes());
    output[HEADER_2_CONTEXT_INDEX] = packet.context;
    output[HEADER_2_DATA_START..HEADER_2_DATA_START + packet.data.len()]
        .copy_from_slice(packet.data);
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
    use hyf_rns_core::{RNS_HEADER_1_LEN, RNS_HEADER_2_LEN, RNS_MTU, RnsDestinationHash};

    use super::{RnsPacketRef, decode_packet, encode_packet};
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

    #[test]
    fn encodes_header_1_packet_and_roundtrips_decode() -> Result<(), RnsWireError> {
        let raw = header_1_packet(&[0xde, 0xad, 0xbe, 0xef]);
        let packet = decode_packet(&raw)?;
        let mut output = [0; RNS_MTU];
        let len = encode_packet(packet, &mut output)?;

        assert_eq!(len, raw.len());
        assert_eq!(&output[..len], raw.as_slice());
        assert_eq!(decode_packet(&output[..len])?, packet);

        Ok(())
    }

    #[test]
    fn encodes_header_2_packet_and_roundtrips_decode() -> Result<(), RnsWireError> {
        let raw = header_2_packet(&[0xde, 0xad]);
        let packet = decode_packet(&raw)?;
        let mut output = [0; RNS_MTU];
        let len = encode_packet(packet, &mut output)?;

        assert_eq!(len, raw.len());
        assert_eq!(&output[..len], raw.as_slice());
        assert_eq!(decode_packet(&output[..len])?, packet);

        Ok(())
    }

    #[test]
    fn encode_rejects_missing_header_2_transport_id() {
        let data = [];
        let packet = RnsPacketRef {
            flags: header_2_flags(),
            hops: 0,
            transport_id: None,
            destination_hash: RnsDestinationHash::new([0x33; 16]),
            context: RNS_CONTEXT_NONE,
            data: &data,
        };
        let mut output = [0; RNS_MTU];

        assert_eq!(
            encode_packet(packet, &mut output),
            Err(RnsWireError::MissingTransportId)
        );
    }

    #[test]
    fn encode_rejects_unexpected_header_1_transport_id() {
        let data = [];
        let packet = RnsPacketRef {
            flags: header_1_flags(),
            hops: 0,
            transport_id: Some([0x22; 16]),
            destination_hash: RnsDestinationHash::new([0x11; 16]),
            context: RNS_CONTEXT_NONE,
            data: &data,
        };
        let mut output = [0; RNS_MTU];

        assert_eq!(
            encode_packet(packet, &mut output),
            Err(RnsWireError::UnexpectedTransportId)
        );
    }

    #[test]
    fn encode_rejects_output_buffers_that_are_too_short() -> Result<(), RnsWireError> {
        let raw = header_1_packet(&[0xde, 0xad]);
        let packet = decode_packet(&raw)?;
        let mut output = [0; RNS_HEADER_1_LEN + 1];

        assert_eq!(
            encode_packet(packet, &mut output),
            Err(RnsWireError::OutputBufferTooShort {
                actual: RNS_HEADER_1_LEN + 1,
                required: raw.len(),
            })
        );

        Ok(())
    }

    #[test]
    fn encode_rejects_packets_larger_than_mtu() {
        let data = [0; RNS_MTU];
        let packet = RnsPacketRef {
            flags: header_1_flags(),
            hops: 0,
            transport_id: None,
            destination_hash: RnsDestinationHash::new([0x11; 16]),
            context: RNS_CONTEXT_NONE,
            data: &data,
        };
        let mut output = [0; RNS_MTU + RNS_HEADER_1_LEN];

        assert_eq!(
            encode_packet(packet, &mut output),
            Err(RnsWireError::PacketTooLarge {
                actual: RNS_MTU + RNS_HEADER_1_LEN,
                maximum: RNS_MTU,
            })
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
