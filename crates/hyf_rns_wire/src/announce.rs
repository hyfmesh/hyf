use hyf_rns_core::{RNS_MTU, RNS_NAME_HASH_LEN, RnsDestinationHash, RnsNameHash, destination_hash};
use hyf_rns_crypto::{
    RNS_PUBLIC_IDENTITY_LEN, RnsCryptoError, RnsSecretIdentity, identity_hash,
    public_identity_from_bytes, public_identity_to_bytes, sign, verify,
};
use rand_core::TryRng;

use crate::{
    RNS_CONTEXT_NONE, RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketRef,
    RnsPacketType, RnsTransportType, RnsWireError, encode_packet,
};

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
const ANNOUNCE_NO_RATCHET_DATA_LEN: usize = ANNOUNCE_NO_RATCHET_MIN_LEN;
const MAX_RETICULUM_RANDOM_HASH_TIMESTAMP: u64 = 0xff_ffff_ffff;
const RETICULUM_RANDOM_HASH_RNG_LEN: usize = 5;
const RETICULUM_RANDOM_HASH_TIME_LEN: usize = 5;
const RETICULUM_RANDOM_HASH_TIME_OFFSET: usize = 8 - RETICULUM_RANDOM_HASH_TIME_LEN;

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

pub struct RnsAnnounceEncodeParams<'a> {
    pub secret_identity: &'a RnsSecretIdentity,
    pub app_name: &'a str,
    pub aspects: &'a [&'a str],
    pub app_data: &'a [u8],
}

pub trait RnsClock {
    fn now_unix_secs(&self) -> u64;
}

pub fn decode_announce_packet<'a>(
    packet: RnsPacketRef<'a>,
) -> Result<RnsAnnounceRef<'a>, RnsWireError> {
    if packet.flags.packet_type != RnsPacketType::Announce {
        return Err(RnsWireError::InvalidPacketType);
    }
    if packet.flags.destination_type != RnsDestinationType::Single {
        return Err(RnsWireError::InvalidDestinationType);
    }

    if packet.flags.context_flag {
        decode_ratchet_announce(packet)
    } else {
        decode_no_ratchet_announce(packet)
    }
}

pub fn encode_announce_packet<R, C>(
    params: RnsAnnounceEncodeParams<'_>,
    rng: &mut R,
    clock: &C,
    output: &mut [u8],
) -> Result<usize, RnsWireError>
where
    R: TryRng + ?Sized,
    C: RnsClock + ?Sized,
{
    let announce_data_len = announce_encode_data_len(params.app_data.len())?;
    let packet_len = packet_len_for_announce_data(announce_data_len)?;
    if output.len() < packet_len {
        return Err(RnsWireError::OutputBufferTooShort {
            actual: output.len(),
            required: packet_len,
        });
    }

    let public_identity = params
        .secret_identity
        .public_identity()
        .map_err(map_crypto_error)?;
    let public_identity_bytes = public_identity_to_bytes(&public_identity);
    let name_hash = hyf_rns_core::destination_name_hash(params.app_name, params.aspects)
        .map_err(|_| RnsWireError::InvalidDestinationName)?;
    let destination_hash = destination_hash(name_hash, Some(identity_hash(&public_identity)));
    let random_hash = reticulum_random_hash(rng, clock)?;
    let unsigned_announce = RnsAnnounceRef {
        destination_hash,
        public_identity: public_identity_bytes,
        name_hash,
        random_hash,
        ratchet: None,
        signature: [0; RNS_ANNOUNCE_SIGNATURE_LEN],
        app_data: params.app_data,
    };
    let mut signed_data = [0; RNS_MTU];
    let signed_data_len = build_announce_signed_data(&unsigned_announce, &mut signed_data)?;
    let signature =
        sign(params.secret_identity, &signed_data[..signed_data_len]).map_err(map_crypto_error)?;

    let mut announce_data = [0; RNS_MTU - hyf_rns_core::RNS_HEADER_1_LEN];
    let mut offset = 0;
    write_part(&mut announce_data, &mut offset, &public_identity_bytes);
    write_part(&mut announce_data, &mut offset, name_hash.as_bytes());
    write_part(&mut announce_data, &mut offset, &random_hash);
    write_part(&mut announce_data, &mut offset, &signature);
    write_part(&mut announce_data, &mut offset, params.app_data);

    encode_packet(
        RnsPacketRef {
            flags: RnsPacketFlags {
                header_type: RnsHeaderType::Header1,
                context_flag: false,
                transport_type: RnsTransportType::Broadcast,
                destination_type: RnsDestinationType::Single,
                packet_type: RnsPacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash,
            context: RNS_CONTEXT_NONE,
            data: &announce_data[..offset],
        },
        output,
    )
}

pub fn build_announce_signed_data(
    announce: &RnsAnnounceRef<'_>,
    output: &mut [u8],
) -> Result<usize, RnsWireError> {
    let required = announce_signed_data_len(announce)?;
    if output.len() < required {
        return Err(RnsWireError::OutputBufferTooShort {
            actual: output.len(),
            required,
        });
    }

    let mut offset = 0;
    write_part(output, &mut offset, announce.destination_hash.as_bytes());
    write_part(output, &mut offset, &announce.public_identity);
    write_part(output, &mut offset, announce.name_hash.as_bytes());
    write_part(output, &mut offset, &announce.random_hash);
    if let Some(ratchet) = announce.ratchet {
        write_part(output, &mut offset, &ratchet);
    }
    write_part(output, &mut offset, announce.app_data);

    Ok(offset)
}

pub fn validate_announce_packet<'a>(
    packet: RnsPacketRef<'a>,
) -> Result<RnsAnnounceRef<'a>, RnsWireError> {
    let announce = decode_announce_packet(packet)?;
    let public_identity =
        public_identity_from_bytes(&announce.public_identity).map_err(map_crypto_error)?;
    let expected_destination_hash =
        destination_hash(announce.name_hash, Some(identity_hash(&public_identity)));
    if expected_destination_hash != announce.destination_hash {
        return Err(RnsWireError::DestinationMismatch);
    }

    let mut signed_data = [0; RNS_MTU];
    let signed_data_len = build_announce_signed_data(&announce, &mut signed_data)?;
    verify(
        &public_identity,
        &signed_data[..signed_data_len],
        &announce.signature,
    )
    .map_err(map_crypto_error)?;

    Ok(announce)
}

fn announce_encode_data_len(app_data_len: usize) -> Result<usize, RnsWireError> {
    ANNOUNCE_NO_RATCHET_DATA_LEN
        .checked_add(app_data_len)
        .ok_or(RnsWireError::PacketTooLarge {
            actual: app_data_len,
            maximum: RNS_MTU,
        })
}

fn packet_len_for_announce_data(announce_data_len: usize) -> Result<usize, RnsWireError> {
    let packet_len = hyf_rns_core::RNS_HEADER_1_LEN
        .checked_add(announce_data_len)
        .ok_or(RnsWireError::PacketTooLarge {
            actual: announce_data_len,
            maximum: RNS_MTU,
        })?;
    if packet_len > RNS_MTU {
        return Err(RnsWireError::PacketTooLarge {
            actual: packet_len,
            maximum: RNS_MTU,
        });
    }

    Ok(packet_len)
}

fn reticulum_random_hash<R, C>(
    rng: &mut R,
    clock: &C,
) -> Result<[u8; RNS_ANNOUNCE_RANDOM_HASH_LEN], RnsWireError>
where
    R: TryRng + ?Sized,
    C: RnsClock + ?Sized,
{
    let timestamp = clock.now_unix_secs();
    if timestamp > MAX_RETICULUM_RANDOM_HASH_TIMESTAMP {
        return Err(RnsWireError::TimestampOverflow);
    }

    let mut random_hash = [0; RNS_ANNOUNCE_RANDOM_HASH_LEN];
    rng.try_fill_bytes(&mut random_hash[..RETICULUM_RANDOM_HASH_RNG_LEN])
        .map_err(|_| RnsWireError::RandomSourceFailed)?;
    let timestamp = timestamp.to_be_bytes();
    random_hash[RETICULUM_RANDOM_HASH_RNG_LEN..]
        .copy_from_slice(&timestamp[RETICULUM_RANDOM_HASH_TIME_OFFSET..]);

    Ok(random_hash)
}

fn announce_signed_data_len(announce: &RnsAnnounceRef<'_>) -> Result<usize, RnsWireError> {
    let mut len = RnsDestinationHash::LEN;
    len = checked_signed_data_len_add(len, RNS_PUBLIC_IDENTITY_LEN)?;
    len = checked_signed_data_len_add(len, RNS_NAME_HASH_LEN)?;
    len = checked_signed_data_len_add(len, RNS_ANNOUNCE_RANDOM_HASH_LEN)?;
    if announce.ratchet.is_some() {
        len = checked_signed_data_len_add(len, RNS_ANNOUNCE_RATCHET_LEN)?;
    }
    checked_signed_data_len_add(len, announce.app_data.len())
}

fn checked_signed_data_len_add(len: usize, addend: usize) -> Result<usize, RnsWireError> {
    len.checked_add(addend).ok_or(RnsWireError::PacketTooLarge {
        actual: len,
        maximum: RNS_MTU,
    })
}

fn write_part(output: &mut [u8], offset: &mut usize, input: &[u8]) {
    let end = *offset + input.len();
    output[*offset..end].copy_from_slice(input);
    *offset = end;
}

fn map_crypto_error(error: RnsCryptoError) -> RnsWireError {
    match error {
        RnsCryptoError::InvalidPublicIdentity => RnsWireError::InvalidPublicIdentity,
        RnsCryptoError::InvalidSecretIdentity | RnsCryptoError::InvalidSignature => {
            RnsWireError::InvalidSignature
        }
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
    use hyf_rns_core::{RNS_MTU, RnsDestinationHash, RnsNameHash, destination_hash};
    use hyf_rns_crypto::{
        identity_hash, public_identity_to_bytes, secret_identity_from_bytes, sign,
    };
    use rand_core::{Infallible, TryRng};

    use super::{
        ANNOUNCE_NO_RATCHET_MIN_LEN, ANNOUNCE_RATCHET_MIN_LEN, RNS_ANNOUNCE_RANDOM_HASH_LEN,
        RNS_ANNOUNCE_RATCHET_LEN, RNS_ANNOUNCE_SIGNATURE_LEN, RnsAnnounceEncodeParams,
        RnsAnnounceRef, RnsClock, build_announce_signed_data, decode_announce_packet,
        encode_announce_packet, validate_announce_packet,
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
    fn rejects_non_single_announce_destinations() {
        let data = announce_data(None, b"");
        for destination_type in [
            RnsDestinationType::Group,
            RnsDestinationType::Plain,
            RnsDestinationType::Link,
        ] {
            let mut packet = announce_packet(false, &data);
            packet.flags.destination_type = destination_type;

            assert_eq!(
                decode_announce_packet(packet),
                Err(RnsWireError::InvalidDestinationType)
            );
        }
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

    #[test]
    fn builds_signed_data_with_destination_and_app_data() -> Result<(), RnsWireError> {
        let (data, destination_hash) = signed_announce_data(None, b"app-data")?;
        let packet = announce_packet_with_destination(false, &data, destination_hash);
        let announce = decode_announce_packet(packet)?;
        let mut signed_data = [0; RNS_MTU];
        let len = build_announce_signed_data(&announce, &mut signed_data)?;

        assert_eq!(&signed_data[..16], announce.destination_hash.as_bytes());
        assert_eq!(&signed_data[len - b"app-data".len()..len], b"app-data");

        Ok(())
    }

    #[test]
    fn validates_signed_announce_with_app_data() -> Result<(), RnsWireError> {
        let (data, destination_hash) = signed_announce_data(None, b"app-data")?;
        let packet = announce_packet_with_destination(false, &data, destination_hash);
        let announce = validate_announce_packet(packet)?;

        assert_eq!(announce.app_data, b"app-data");
        Ok(())
    }

    #[test]
    fn validates_signed_ratchet_announce() -> Result<(), RnsWireError> {
        let (data, destination_hash) =
            signed_announce_data(Some([0x55; RNS_ANNOUNCE_RATCHET_LEN]), b"app-data")?;
        let packet = announce_packet_with_destination(true, &data, destination_hash);
        let announce = validate_announce_packet(packet)?;

        assert_eq!(announce.ratchet, Some([0x55; RNS_ANNOUNCE_RATCHET_LEN]));
        Ok(())
    }

    #[test]
    fn validation_rejects_destination_mismatch() -> Result<(), RnsWireError> {
        let (data, _destination_hash) = signed_announce_data(None, b"app-data")?;
        let packet =
            announce_packet_with_destination(false, &data, RnsDestinationHash::new([0x88; 16]));

        assert_eq!(
            validate_announce_packet(packet),
            Err(RnsWireError::DestinationMismatch)
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_altered_signature() -> Result<(), RnsWireError> {
        let (mut data, destination_hash) = signed_announce_data(None, b"app-data")?;
        data[84] ^= 0x01;
        let packet = announce_packet_with_destination(false, &data, destination_hash);

        assert_eq!(
            validate_announce_packet(packet),
            Err(RnsWireError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_altered_ratchet() -> Result<(), RnsWireError> {
        let (mut data, destination_hash) =
            signed_announce_data(Some([0x55; RNS_ANNOUNCE_RATCHET_LEN]), b"app-data")?;
        data[84] ^= 0x01;
        let packet = announce_packet_with_destination(true, &data, destination_hash);

        assert_eq!(
            validate_announce_packet(packet),
            Err(RnsWireError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn signed_data_builder_rejects_short_output_buffer() -> Result<(), RnsWireError> {
        let (data, destination_hash) = signed_announce_data(None, b"app-data")?;
        let packet = announce_packet_with_destination(false, &data, destination_hash);
        let announce = decode_announce_packet(packet)?;
        let mut signed_data = [0; 1];

        assert_eq!(
            build_announce_signed_data(&announce, &mut signed_data),
            Err(RnsWireError::OutputBufferTooShort {
                actual: 1,
                required: 16 + 64 + 10 + 10 + b"app-data".len(),
            })
        );

        Ok(())
    }

    #[test]
    fn encodes_deterministic_announce_and_validates_it() -> Result<(), RnsWireError> {
        let secret = test_secret_identity()?;
        let aspects = ["announce"];
        let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
        let clock = FixedClock(0x01_0203_0405);
        let mut output = [0; RNS_MTU];
        let len = encode_announce_packet(
            RnsAnnounceEncodeParams {
                secret_identity: &secret,
                app_name: "hyf",
                aspects: &aspects,
                app_data: b"app-data",
            },
            &mut rng,
            &clock,
            &mut output,
        )?;
        let packet = crate::decode_packet(&output[..len])?;
        let announce = validate_announce_packet(packet)?;

        assert_eq!(
            announce.random_hash,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]
        );
        assert_eq!(announce.ratchet, None);
        assert_eq!(announce.app_data, b"app-data");

        Ok(())
    }

    #[test]
    fn encode_rejects_timestamp_overflow() -> Result<(), RnsWireError> {
        let secret = test_secret_identity()?;
        let aspects = ["announce"];
        let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
        let clock = FixedClock(0x0100_0000_0000);
        let mut output = [0; RNS_MTU];

        assert_eq!(
            encode_announce_packet(
                RnsAnnounceEncodeParams {
                    secret_identity: &secret,
                    app_name: "hyf",
                    aspects: &aspects,
                    app_data: b"",
                },
                &mut rng,
                &clock,
                &mut output,
            ),
            Err(RnsWireError::TimestampOverflow)
        );

        Ok(())
    }

    #[test]
    fn encode_rejects_failed_random_source() -> Result<(), RnsWireError> {
        let secret = test_secret_identity()?;
        let aspects = ["announce"];
        let mut rng = FailingRng;
        let clock = FixedClock(0);
        let mut output = [0; RNS_MTU];

        assert_eq!(
            encode_announce_packet(
                RnsAnnounceEncodeParams {
                    secret_identity: &secret,
                    app_name: "hyf",
                    aspects: &aspects,
                    app_data: b"",
                },
                &mut rng,
                &clock,
                &mut output,
            ),
            Err(RnsWireError::RandomSourceFailed)
        );

        Ok(())
    }

    #[test]
    fn encode_rejects_short_output_buffer() -> Result<(), RnsWireError> {
        let secret = test_secret_identity()?;
        let aspects = ["announce"];
        let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
        let clock = FixedClock(0);
        let mut output = [0; 1];

        assert_eq!(
            encode_announce_packet(
                RnsAnnounceEncodeParams {
                    secret_identity: &secret,
                    app_name: "hyf",
                    aspects: &aspects,
                    app_data: b"",
                },
                &mut rng,
                &clock,
                &mut output,
            ),
            Err(RnsWireError::OutputBufferTooShort {
                actual: 1,
                required: 167,
            })
        );

        Ok(())
    }

    #[test]
    fn encode_rejects_announce_packets_larger_than_mtu() -> Result<(), RnsWireError> {
        let secret = test_secret_identity()?;
        let aspects = ["announce"];
        let app_data = [0; 334];
        let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
        let clock = FixedClock(0);
        let mut output = [0; RNS_MTU];

        assert_eq!(
            encode_announce_packet(
                RnsAnnounceEncodeParams {
                    secret_identity: &secret,
                    app_name: "hyf",
                    aspects: &aspects,
                    app_data: &app_data,
                },
                &mut rng,
                &clock,
                &mut output,
            ),
            Err(RnsWireError::PacketTooLarge {
                actual: 501,
                maximum: RNS_MTU,
            })
        );

        Ok(())
    }

    #[test]
    fn encode_rejects_invalid_destination_name() -> Result<(), RnsWireError> {
        let secret = test_secret_identity()?;
        let aspects = ["announce"];
        let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
        let clock = FixedClock(0);
        let mut output = [0; RNS_MTU];

        assert_eq!(
            encode_announce_packet(
                RnsAnnounceEncodeParams {
                    secret_identity: &secret,
                    app_name: "hyf.bad",
                    aspects: &aspects,
                    app_data: b"",
                },
                &mut rng,
                &clock,
                &mut output,
            ),
            Err(RnsWireError::InvalidDestinationName)
        );

        Ok(())
    }

    fn announce_packet<'a>(context_flag: bool, data: &'a [u8]) -> RnsPacketRef<'a> {
        announce_packet_with_destination(context_flag, data, RnsDestinationHash::new([0x99; 16]))
    }

    fn announce_packet_with_destination<'a>(
        context_flag: bool,
        data: &'a [u8],
        destination_hash: RnsDestinationHash,
    ) -> RnsPacketRef<'a> {
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
            destination_hash,
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

    fn signed_announce_data(
        ratchet: Option<[u8; RNS_ANNOUNCE_RATCHET_LEN]>,
        app_data: &[u8],
    ) -> Result<(Vec<u8>, RnsDestinationHash), RnsWireError> {
        let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY)
            .map_err(|_| RnsWireError::InvalidPublicIdentity)?;
        let public_identity = secret
            .public_identity()
            .map_err(|_| RnsWireError::InvalidPublicIdentity)?;
        let public_identity_bytes = public_identity_to_bytes(&public_identity);
        let name_hash = RnsNameHash::new([0x22; 10]);
        let destination_hash = destination_hash(name_hash, Some(identity_hash(&public_identity)));
        let random_hash = [0x33; RNS_ANNOUNCE_RANDOM_HASH_LEN];
        let announce = RnsAnnounceRef {
            destination_hash,
            public_identity: public_identity_bytes,
            name_hash,
            random_hash,
            ratchet,
            signature: [0; RNS_ANNOUNCE_SIGNATURE_LEN],
            app_data,
        };
        let mut signed_data = [0; RNS_MTU];
        let signed_data_len = build_announce_signed_data(&announce, &mut signed_data)?;
        let signature = sign(&secret, &signed_data[..signed_data_len])
            .map_err(|_| RnsWireError::InvalidSignature)?;

        let mut data = Vec::new();
        data.extend_from_slice(&public_identity_bytes);
        data.extend_from_slice(name_hash.as_bytes());
        data.extend_from_slice(&random_hash);
        if let Some(ratchet) = ratchet {
            data.extend_from_slice(&ratchet);
        }
        data.extend_from_slice(&signature);
        data.extend_from_slice(app_data);

        Ok((data, destination_hash))
    }

    fn test_secret_identity() -> Result<hyf_rns_crypto::RnsSecretIdentity, RnsWireError> {
        secret_identity_from_bytes(&TEST_SECRET_IDENTITY)
            .map_err(|_| RnsWireError::InvalidPublicIdentity)
    }

    struct FixedClock(u64);

    impl RnsClock for FixedClock {
        fn now_unix_secs(&self) -> u64 {
            self.0
        }
    }

    struct FixedRng {
        bytes: [u8; 5],
        offset: usize,
    }

    impl FixedRng {
        const fn new(bytes: [u8; 5]) -> Self {
            Self { bytes, offset: 0 }
        }

        fn next_byte(&mut self) -> u8 {
            let byte = self.bytes[self.offset % self.bytes.len()];
            self.offset += 1;
            byte
        }
    }

    impl TryRng for FixedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dst {
                *byte = self.next_byte();
            }
            Ok(())
        }
    }

    struct FailingRng;

    #[derive(Debug)]
    struct FailingRngError;

    impl core::fmt::Display for FailingRngError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("failing rng")
        }
    }

    impl std::error::Error for FailingRngError {}

    impl TryRng for FailingRng {
        type Error = FailingRngError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(FailingRngError)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(FailingRngError)
        }

        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
            Err(FailingRngError)
        }
    }

    const TEST_SECRET_IDENTITY: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];
}
