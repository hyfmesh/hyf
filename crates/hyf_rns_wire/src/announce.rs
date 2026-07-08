use hyf_rns_core::{RNS_NAME_HASH_LEN, RnsDestinationHash, RnsNameHash};
use hyf_rns_crypto::RNS_PUBLIC_IDENTITY_LEN;

use crate::{RnsPacketRef, RnsPacketType, RnsWireError};

pub const RNS_ANNOUNCE_RANDOM_HASH_LEN: usize = 10;
pub const RNS_ANNOUNCE_RATCHET_LEN: usize = 32;
pub const RNS_ANNOUNCE_SIGNATURE_LEN: usize = 64;

const ANNOUNCE_PUBLIC_IDENTITY_START: usize = 0;
const ANNOUNCE_PUBLIC_IDENTITY_END: usize =
    ANNOUNCE_PUBLIC_IDENTITY_START + RNS_PUBLIC_IDENTITY_LEN;
const ANNOUNCE_NAME_HASH_START: usize = ANNOUNCE_PUBLIC_IDENTITY_END;
const ANNOUNCE_NAME_HASH_END: usize = ANNOUNCE_NAME_HASH_START + RNS_NAME_HASH_LEN;
const ANNOUNCE_RANDOM_HASH_START: usize = ANNOUNCE_NAME_HASH_END;
const ANNOUNCE_RANDOM_HASH_END: usize = ANNOUNCE_RANDOM_HASH_START + RNS_ANNOUNCE_RANDOM_HASH_LEN;
const ANNOUNCE_RATCHET_START: usize = ANNOUNCE_RANDOM_HASH_END;
const ANNOUNCE_RATCHET_END: usize = ANNOUNCE_RATCHET_START + RNS_ANNOUNCE_RATCHET_LEN;
const ANNOUNCE_NO_RATCHET_SIGNATURE_START: usize = ANNOUNCE_RANDOM_HASH_END;
const ANNOUNCE_NO_RATCHET_SIGNATURE_END: usize =
    ANNOUNCE_NO_RATCHET_SIGNATURE_START + RNS_ANNOUNCE_SIGNATURE_LEN;
const ANNOUNCE_RATCHET_SIGNATURE_START: usize = ANNOUNCE_RATCHET_END;
const ANNOUNCE_RATCHET_SIGNATURE_END: usize =
    ANNOUNCE_RATCHET_SIGNATURE_START + RNS_ANNOUNCE_SIGNATURE_LEN;
const ANNOUNCE_NO_RATCHET_MIN_LEN: usize = ANNOUNCE_NO_RATCHET_SIGNATURE_END;
const ANNOUNCE_RATCHET_MIN_LEN: usize = ANNOUNCE_RATCHET_SIGNATURE_END;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnsAnnounceRef<'a> {
    pub destination_hash: RnsDestinationHash,
    pub public_identity: [u8; RNS_PUBLIC_IDENTITY_LEN],
    pub name_hash: RnsNameHash,
    pub random_hash: [u8; RNS_ANNOUNCE_RANDOM_HASH_LEN],
    pub ratchet: Option<[u8; RNS_ANNOUNCE_RATCHET_LEN]>,
    pub signature: [u8; RNS_ANNOUNCE_SIGNATURE_LEN],
    pub app_data: &'a [u8],
}

pub fn decode_announce_packet<'a>(
    packet: RnsPacketRef<'a>,
) -> Result<RnsAnnounceRef<'a>, RnsWireError> {
    if packet.flags.packet_type != RnsPacketType::Announce {
        return Err(RnsWireError::InvalidPacketType);
    }

    if packet.flags.context_flag {
        decode_ratchet_announce(packet)
    } else {
        decode_no_ratchet_announce(packet)
    }
}

fn decode_no_ratchet_announce<'a>(
    packet: RnsPacketRef<'a>,
) -> Result<RnsAnnounceRef<'a>, RnsWireError> {
    if packet.data.len() < ANNOUNCE_NO_RATCHET_MIN_LEN {
        return Err(RnsWireError::MalformedAnnounce);
    }

    Ok(RnsAnnounceRef {
        destination_hash: packet.destination_hash,
        public_identity: read_array(
            &packet.data[ANNOUNCE_PUBLIC_IDENTITY_START..ANNOUNCE_PUBLIC_IDENTITY_END],
        ),
        name_hash: RnsNameHash::new(read_array(
            &packet.data[ANNOUNCE_NAME_HASH_START..ANNOUNCE_NAME_HASH_END],
        )),
        random_hash: read_array(&packet.data[ANNOUNCE_RANDOM_HASH_START..ANNOUNCE_RANDOM_HASH_END]),
        ratchet: None,
        signature: read_array(
            &packet.data[ANNOUNCE_NO_RATCHET_SIGNATURE_START..ANNOUNCE_NO_RATCHET_SIGNATURE_END],
        ),
        app_data: &packet.data[ANNOUNCE_NO_RATCHET_SIGNATURE_END..],
    })
}

fn decode_ratchet_announce<'a>(
    packet: RnsPacketRef<'a>,
) -> Result<RnsAnnounceRef<'a>, RnsWireError> {
    if packet.data.len() < ANNOUNCE_RATCHET_MIN_LEN {
        return Err(RnsWireError::MalformedAnnounce);
    }

    Ok(RnsAnnounceRef {
        destination_hash: packet.destination_hash,
        public_identity: read_array(
            &packet.data[ANNOUNCE_PUBLIC_IDENTITY_START..ANNOUNCE_PUBLIC_IDENTITY_END],
        ),
        name_hash: RnsNameHash::new(read_array(
            &packet.data[ANNOUNCE_NAME_HASH_START..ANNOUNCE_NAME_HASH_END],
        )),
        random_hash: read_array(&packet.data[ANNOUNCE_RANDOM_HASH_START..ANNOUNCE_RANDOM_HASH_END]),
        ratchet: Some(read_array(
            &packet.data[ANNOUNCE_RATCHET_START..ANNOUNCE_RATCHET_END],
        )),
        signature: read_array(
            &packet.data[ANNOUNCE_RATCHET_SIGNATURE_START..ANNOUNCE_RATCHET_SIGNATURE_END],
        ),
        app_data: &packet.data[ANNOUNCE_RATCHET_SIGNATURE_END..],
    })
}

fn read_array<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(input);
    output
}

#[cfg(test)]
mod tests {
    use hyf_rns_core::{RnsDestinationHash, RnsNameHash};

    use super::{
        ANNOUNCE_NO_RATCHET_MIN_LEN, ANNOUNCE_RATCHET_MIN_LEN, RNS_ANNOUNCE_RANDOM_HASH_LEN,
        RNS_ANNOUNCE_RATCHET_LEN, RNS_ANNOUNCE_SIGNATURE_LEN, decode_announce_packet,
    };
    use crate::{
        RNS_CONTEXT_NONE, RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketRef,
        RnsPacketType, RnsTransportType, RnsWireError,
    };

    #[test]
    fn decodes_no_ratchet_announce_with_app_data() -> Result<(), RnsWireError> {
        let data = announce_data(None, b"app-data");
        let packet = announce_packet(false, &data);
        let announce = decode_announce_packet(packet)?;

        assert_eq!(
            announce.destination_hash,
            RnsDestinationHash::new([0x99; 16])
        );
        assert_eq!(announce.public_identity, [0x11; 64]);
        assert_eq!(announce.name_hash, RnsNameHash::new([0x22; 10]));
        assert_eq!(announce.random_hash, [0x33; RNS_ANNOUNCE_RANDOM_HASH_LEN]);
        assert_eq!(announce.ratchet, None);
        assert_eq!(announce.signature, [0x44; RNS_ANNOUNCE_SIGNATURE_LEN]);
        assert_eq!(announce.app_data, b"app-data");

        Ok(())
    }

    #[test]
    fn decodes_ratchet_when_context_flag_is_set() -> Result<(), RnsWireError> {
        let data = announce_data(Some([0x55; RNS_ANNOUNCE_RATCHET_LEN]), b"app-data");
        let packet = announce_packet(true, &data);
        let announce = decode_announce_packet(packet)?;

        assert_eq!(announce.ratchet, Some([0x55; RNS_ANNOUNCE_RATCHET_LEN]));
        assert_eq!(announce.signature, [0x44; RNS_ANNOUNCE_SIGNATURE_LEN]);
        assert_eq!(announce.app_data, b"app-data");

        Ok(())
    }

    #[test]
    fn rejects_non_announce_packets() {
        let data = announce_data(None, b"");
        let mut packet = announce_packet(false, &data);
        packet.flags.packet_type = RnsPacketType::Data;

        assert_eq!(
            decode_announce_packet(packet),
            Err(RnsWireError::InvalidPacketType)
        );
    }

    #[test]
    fn rejects_too_short_no_ratchet_announce() {
        let data = [0; ANNOUNCE_NO_RATCHET_MIN_LEN - 1];
        let packet = announce_packet(false, &data);

        assert_eq!(
            decode_announce_packet(packet),
            Err(RnsWireError::MalformedAnnounce)
        );
    }

    #[test]
    fn rejects_too_short_ratchet_announce() {
        let data = [0; ANNOUNCE_RATCHET_MIN_LEN - 1];
        let packet = announce_packet(true, &data);

        assert_eq!(
            decode_announce_packet(packet),
            Err(RnsWireError::MalformedAnnounce)
        );
    }

    fn announce_packet<'a>(context_flag: bool, data: &'a [u8]) -> RnsPacketRef<'a> {
        RnsPacketRef {
            flags: RnsPacketFlags {
                header_type: RnsHeaderType::Header1,
                context_flag,
                transport_type: RnsTransportType::Broadcast,
                destination_type: RnsDestinationType::Single,
                packet_type: RnsPacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: RnsDestinationHash::new([0x99; 16]),
            context: RNS_CONTEXT_NONE,
            data,
        }
    }

    fn announce_data(ratchet: Option<[u8; RNS_ANNOUNCE_RATCHET_LEN]>, app_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x11; 64]);
        data.extend_from_slice(&[0x22; 10]);
        data.extend_from_slice(&[0x33; RNS_ANNOUNCE_RANDOM_HASH_LEN]);
        if let Some(ratchet) = ratchet {
            data.extend_from_slice(&ratchet);
        }
        data.extend_from_slice(&[0x44; RNS_ANNOUNCE_SIGNATURE_LEN]);
        data.extend_from_slice(app_data);
        data
    }
}
