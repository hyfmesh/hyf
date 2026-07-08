use hyf_rns_core::{RNS_MTU, RNS_TRUNCATED_HASH_LEN, RnsFullHash, RnsTruncatedHash, full_hash};

use crate::{RnsHeaderType, RnsWireError, decode_packet};

const HASHABLE_FLAGS_MASK: u8 = 0b0000_1111;
const HEADER_1_HASHABLE_REST_START: usize = 2;
const HEADER_2_HASHABLE_REST_START: usize = 2 + RNS_TRUNCATED_HASH_LEN;

pub fn write_packet_hashable_part(input: &[u8], output: &mut [u8]) -> Result<usize, RnsWireError> {
    let packet = decode_packet(input)?;
    let hashable_len = packet_hashable_len(input.len(), packet.flags.header_type);
    if output.len() < hashable_len {
        return Err(RnsWireError::OutputBufferTooShort {
            actual: output.len(),
            required: hashable_len,
        });
    }

    output[0] = input[0] & HASHABLE_FLAGS_MASK;
    match packet.flags.header_type {
        RnsHeaderType::Header1 => {
            output[1..hashable_len].copy_from_slice(&input[HEADER_1_HASHABLE_REST_START..]);
        }
        RnsHeaderType::Header2 => {
            output[1..hashable_len].copy_from_slice(&input[HEADER_2_HASHABLE_REST_START..]);
        }
    }

    Ok(hashable_len)
}

pub fn packet_hash(input: &[u8]) -> Result<RnsFullHash, RnsWireError> {
    let mut hashable = [0; RNS_MTU - 1];
    let hashable_len = write_packet_hashable_part(input, &mut hashable)?;

    Ok(full_hash(&hashable[..hashable_len]))
}

pub fn packet_truncated_hash(input: &[u8]) -> Result<RnsTruncatedHash, RnsWireError> {
    let full_hash = packet_hash(input)?.into_bytes();
    let mut truncated = [0; RNS_TRUNCATED_HASH_LEN];
    truncated.copy_from_slice(&full_hash[..RNS_TRUNCATED_HASH_LEN]);

    Ok(RnsTruncatedHash::new(truncated))
}

const fn packet_hashable_len(input_len: usize, header_type: RnsHeaderType) -> usize {
    match header_type {
        RnsHeaderType::Header1 => input_len - 1,
        RnsHeaderType::Header2 => input_len - RNS_TRUNCATED_HASH_LEN - 1,
    }
}

#[cfg(test)]
mod tests {
    use hyf_rns_core::{RNS_MTU, RNS_TRUNCATED_HASH_LEN, full_hash};

    use super::{packet_hash, packet_truncated_hash, write_packet_hashable_part};
    use crate::{
        RNS_CONTEXT_NONE, RNS_CONTEXT_PATH_RESPONSE, RnsDestinationType, RnsHeaderType,
        RnsPacketFlags, RnsPacketType, RnsTransportType, RnsWireError, encode_flags,
    };

    #[test]
    fn header_1_hashable_part_masks_flags_and_excludes_hops() -> Result<(), RnsWireError> {
        let raw = header_1_packet(&[0xaa, 0xbb]);
        let mut hashable = [0; RNS_MTU];
        let len = write_packet_hashable_part(&raw, &mut hashable)?;

        assert_eq!(hashable[0], raw[0] & 0x0f);
        assert_eq!(&hashable[1..len], &raw[2..]);
        assert_eq!(packet_hash(&raw)?, full_hash(&hashable[..len]));

        Ok(())
    }

    #[test]
    fn header_2_hashable_part_excludes_hops_and_transport_id() -> Result<(), RnsWireError> {
        let raw = header_2_packet([0x22; RNS_TRUNCATED_HASH_LEN], &[0xaa, 0xbb]);
        let mut hashable = [0; RNS_MTU];
        let len = write_packet_hashable_part(&raw, &mut hashable)?;

        assert_eq!(hashable[0], raw[0] & 0x0f);
        assert_eq!(&hashable[1..len], &raw[18..]);
        assert_eq!(packet_hash(&raw)?, full_hash(&hashable[..len]));

        Ok(())
    }

    #[test]
    fn header_2_packet_hash_excludes_transport_id() -> Result<(), RnsWireError> {
        let raw_a = header_2_packet([0x22; RNS_TRUNCATED_HASH_LEN], &[0xaa, 0xbb]);
        let raw_b = header_2_packet([0x99; RNS_TRUNCATED_HASH_LEN], &[0xaa, 0xbb]);

        assert_ne!(raw_a, raw_b);
        assert_eq!(packet_hash(&raw_a)?, packet_hash(&raw_b)?);

        Ok(())
    }

    #[test]
    fn packet_truncated_hash_is_first_sixteen_full_hash_bytes() -> Result<(), RnsWireError> {
        let raw = header_1_packet(&[0xaa, 0xbb]);
        let full_hash = packet_hash(&raw)?.into_bytes();
        let mut expected = [0; RNS_TRUNCATED_HASH_LEN];
        expected.copy_from_slice(&full_hash[..RNS_TRUNCATED_HASH_LEN]);

        assert_eq!(packet_truncated_hash(&raw)?.into_bytes(), expected);
        Ok(())
    }

    #[test]
    fn hashing_validates_packets_before_hashing() {
        let mut short = header_2_packet([0x22; RNS_TRUNCATED_HASH_LEN], &[]);
        short.truncate(34);

        assert_eq!(
            packet_hash(&short),
            Err(RnsWireError::PacketTooShort {
                actual: 34,
                minimum: 35,
            })
        );
    }

    #[test]
    fn hashable_part_rejects_short_output_buffers() {
        let raw = header_1_packet(&[0xaa, 0xbb]);
        let mut output = [0; 1];

        assert_eq!(
            write_packet_hashable_part(&raw, &mut output),
            Err(RnsWireError::OutputBufferTooShort {
                actual: 1,
                required: raw.len() - 1,
            })
        );
    }

    fn header_1_packet(data: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(encode_flags(RnsPacketFlags {
            header_type: RnsHeaderType::Header1,
            context_flag: true,
            transport_type: RnsTransportType::Transport,
            destination_type: RnsDestinationType::Group,
            packet_type: RnsPacketType::Announce,
        }));
        raw.push(12);
        raw.extend_from_slice(&[0x11; RNS_TRUNCATED_HASH_LEN]);
        raw.push(RNS_CONTEXT_NONE);
        raw.extend_from_slice(data);
        raw
    }

    fn header_2_packet(transport_id: [u8; RNS_TRUNCATED_HASH_LEN], data: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(encode_flags(RnsPacketFlags {
            header_type: RnsHeaderType::Header2,
            context_flag: true,
            transport_type: RnsTransportType::Transport,
            destination_type: RnsDestinationType::Group,
            packet_type: RnsPacketType::Announce,
        }));
        raw.push(34);
        raw.extend_from_slice(&transport_id);
        raw.extend_from_slice(&[0x33; RNS_TRUNCATED_HASH_LEN]);
        raw.push(RNS_CONTEXT_PATH_RESPONSE);
        raw.extend_from_slice(data);
        raw
    }
}
