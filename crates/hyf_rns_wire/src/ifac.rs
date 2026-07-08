use hyf_rns_core::RNS_MTU;
use hyf_rns_crypto::{RnsCryptoError, RnsSecretIdentity, rns_hkdf_sha256, sign};

use crate::{RnsWireError, flags::IFAC_FLAG};

pub const RNS_IFAC_MIN_SIZE: usize = 1;
pub const RNS_IFAC_MAX_SIZE: usize = 64;

const HEADER_LEN: usize = 2;

pub fn ifac_apply_outbound(
    raw_packet: &[u8],
    ifac_identity: &RnsSecretIdentity,
    ifac_key: &[u8],
    ifac_size: usize,
    out: &mut [u8],
) -> Result<usize, RnsWireError> {
    validate_ifac_size(ifac_size)?;
    validate_ifac_key(ifac_key)?;
    validate_raw_packet_len(raw_packet.len())?;
    if raw_packet[0] & IFAC_FLAG != 0 {
        return Err(RnsWireError::UnsupportedPacketAccessCode);
    }

    let required = raw_packet
        .len()
        .checked_add(ifac_size)
        .ok_or(RnsWireError::PacketTooLarge {
            actual: raw_packet.len(),
            maximum: RNS_MTU,
        })?;
    validate_wire_len(required)?;
    if out.len() < required {
        return Err(RnsWireError::OutputBufferTooShort {
            actual: out.len(),
            required,
        });
    }

    let signature = sign(ifac_identity, raw_packet).map_err(map_crypto_error)?;
    let ifac = &signature[signature.len() - ifac_size..];
    rns_hkdf_sha256(&mut out[..required], ifac, Some(ifac_key), None).map_err(map_crypto_error)?;

    out[0] = ((raw_packet[0] | IFAC_FLAG) ^ out[0]) | IFAC_FLAG;
    out[1] ^= raw_packet[1];
    out[HEADER_LEN..HEADER_LEN + ifac_size].copy_from_slice(ifac);

    for index in HEADER_LEN + ifac_size..required {
        let mask = out[index];
        out[index] = raw_packet[index - ifac_size] ^ mask;
    }

    Ok(required)
}

pub fn ifac_verify_inbound(
    masked_packet: &[u8],
    ifac_identity: &RnsSecretIdentity,
    ifac_key: &[u8],
    ifac_size: usize,
    out: &mut [u8],
) -> Result<usize, RnsWireError> {
    validate_ifac_size(ifac_size)?;
    validate_ifac_key(ifac_key)?;
    validate_wire_len(masked_packet.len())?;
    if masked_packet.len() <= HEADER_LEN + ifac_size {
        return Err(RnsWireError::PacketTooShort {
            actual: masked_packet.len(),
            minimum: HEADER_LEN + ifac_size + 1,
        });
    }
    if masked_packet[0] & IFAC_FLAG == 0 {
        return Err(RnsWireError::MissingPacketAccessCode);
    }

    let required = masked_packet.len() - ifac_size;
    if out.len() < required {
        return Err(RnsWireError::OutputBufferTooShort {
            actual: out.len(),
            required,
        });
    }

    let ifac = &masked_packet[HEADER_LEN..HEADER_LEN + ifac_size];
    let mut mask = [0; RNS_MTU];
    rns_hkdf_sha256(&mut mask[..masked_packet.len()], ifac, Some(ifac_key), None)
        .map_err(map_crypto_error)?;

    out[0] = (masked_packet[0] ^ mask[0]) & !IFAC_FLAG;
    out[1] = masked_packet[1] ^ mask[1];
    for (output_index, output_byte) in out.iter_mut().enumerate().take(required).skip(HEADER_LEN) {
        let masked_index = output_index + ifac_size;
        *output_byte = masked_packet[masked_index] ^ mask[masked_index];
    }

    let signature = sign(ifac_identity, &out[..required]).map_err(map_crypto_error)?;
    let expected_ifac = &signature[signature.len() - ifac_size..];
    if constant_time_eq(ifac, expected_ifac) {
        Ok(required)
    } else {
        out[..required].fill(0);
        Err(RnsWireError::InvalidPacketAccessCode)
    }
}

fn validate_ifac_size(ifac_size: usize) -> Result<(), RnsWireError> {
    if (RNS_IFAC_MIN_SIZE..=RNS_IFAC_MAX_SIZE).contains(&ifac_size) {
        Ok(())
    } else {
        Err(RnsWireError::InvalidIfacSize {
            actual: ifac_size,
            maximum: RNS_IFAC_MAX_SIZE,
        })
    }
}

fn validate_ifac_key(ifac_key: &[u8]) -> Result<(), RnsWireError> {
    if ifac_key.is_empty() {
        Err(RnsWireError::InvalidIfacKey)
    } else {
        Ok(())
    }
}

fn validate_raw_packet_len(len: usize) -> Result<(), RnsWireError> {
    if len <= HEADER_LEN {
        return Err(RnsWireError::PacketTooShort {
            actual: len,
            minimum: HEADER_LEN + 1,
        });
    }
    validate_wire_len(len)
}

fn validate_wire_len(len: usize) -> Result<(), RnsWireError> {
    if len > RNS_MTU {
        Err(RnsWireError::PacketTooLarge {
            actual: len,
            maximum: RNS_MTU,
        })
    } else {
        Ok(())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn map_crypto_error(error: RnsCryptoError) -> RnsWireError {
    match error {
        RnsCryptoError::InvalidPublicIdentity => RnsWireError::InvalidPublicIdentity,
        RnsCryptoError::InvalidSecretIdentity | RnsCryptoError::InvalidSignature => {
            RnsWireError::InvalidSignature
        }
        RnsCryptoError::EmptyHkdfOutput
        | RnsCryptoError::EmptyHkdfInputKeyMaterial
        | RnsCryptoError::InvalidHkdfLength
        | RnsCryptoError::LengthOverflow
        | RnsCryptoError::OutputBufferTooShort { .. }
        | RnsCryptoError::InvalidPadding
        | RnsCryptoError::InvalidToken
        | RnsCryptoError::InvalidTokenKeyLength { .. }
        | RnsCryptoError::AuthenticationFailed
        | RnsCryptoError::RandomSourceFailed
        | RnsCryptoError::CipherFailed => RnsWireError::CryptoFailed,
    }
}

#[cfg(test)]
mod tests {
    use hyf_rns_core::RnsDestinationHash;
    use hyf_rns_crypto::secret_identity_from_bytes;

    use super::{RNS_IFAC_MAX_SIZE, ifac_apply_outbound, ifac_verify_inbound, validate_ifac_size};
    use crate::{
        RNS_CONTEXT_NONE, RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketRef,
        RnsPacketType, RnsTransportType, RnsWireError, decode_packet, encode_packet,
    };

    const IFAC_SIZE: usize = 8;
    const IFAC_KEY: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];
    const IFAC_SECRET_IDENTITY: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    #[test]
    fn ifac_apply_and_verify_roundtrips() -> Result<(), RnsWireError> {
        let identity = secret_identity_from_bytes(&IFAC_SECRET_IDENTITY)
            .map_err(|_| RnsWireError::InvalidSignature)?;
        let raw = raw_packet()?;
        let mut masked = [0; 128];
        let masked_len = ifac_apply_outbound(&raw, &identity, &IFAC_KEY, IFAC_SIZE, &mut masked)?;
        let mut verified = [0; 128];
        let verified_len = ifac_verify_inbound(
            &masked[..masked_len],
            &identity,
            &IFAC_KEY,
            IFAC_SIZE,
            &mut verified,
        )?;

        assert_ne!(&masked[..masked_len], &raw[..]);
        assert_ne!(decode_packet(&masked[..masked_len]), decode_packet(&raw));
        assert_eq!(verified_len, raw.len());
        assert_eq!(&verified[..verified_len], &raw);
        assert!(decode_packet(&verified[..verified_len]).is_ok());
        Ok(())
    }

    #[test]
    fn ifac_verify_rejects_bad_code_and_zeros_output() -> Result<(), RnsWireError> {
        let identity = secret_identity_from_bytes(&IFAC_SECRET_IDENTITY)
            .map_err(|_| RnsWireError::InvalidSignature)?;
        let raw = raw_packet()?;
        let mut masked = [0; 128];
        let masked_len = ifac_apply_outbound(&raw, &identity, &IFAC_KEY, IFAC_SIZE, &mut masked)?;
        masked[2] ^= 0x01;
        let mut verified = [0x55; 128];

        assert_eq!(
            ifac_verify_inbound(
                &masked[..masked_len],
                &identity,
                &IFAC_KEY,
                IFAC_SIZE,
                &mut verified
            ),
            Err(RnsWireError::InvalidPacketAccessCode)
        );
        assert!(verified[..raw.len()].iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn ifac_verify_rejects_missing_flag_without_writing() -> Result<(), RnsWireError> {
        let identity = secret_identity_from_bytes(&IFAC_SECRET_IDENTITY)
            .map_err(|_| RnsWireError::InvalidSignature)?;
        let raw = raw_packet()?;
        let mut verified = [0x55; 128];

        assert_eq!(
            ifac_verify_inbound(&raw, &identity, &IFAC_KEY, IFAC_SIZE, &mut verified),
            Err(RnsWireError::MissingPacketAccessCode)
        );
        assert!(verified.iter().all(|byte| *byte == 0x55));
        Ok(())
    }

    #[test]
    fn ifac_rejects_invalid_sizes_and_keys() -> Result<(), RnsWireError> {
        let identity = secret_identity_from_bytes(&IFAC_SECRET_IDENTITY)
            .map_err(|_| RnsWireError::InvalidSignature)?;
        let raw = raw_packet()?;
        let mut masked = [0; 128];

        assert_eq!(
            validate_ifac_size(0),
            Err(RnsWireError::InvalidIfacSize {
                actual: 0,
                maximum: RNS_IFAC_MAX_SIZE,
            })
        );
        assert_eq!(
            validate_ifac_size(RNS_IFAC_MAX_SIZE + 1),
            Err(RnsWireError::InvalidIfacSize {
                actual: RNS_IFAC_MAX_SIZE + 1,
                maximum: RNS_IFAC_MAX_SIZE,
            })
        );
        assert_eq!(
            ifac_apply_outbound(&raw, &identity, &[], IFAC_SIZE, &mut masked),
            Err(RnsWireError::InvalidIfacKey)
        );
        Ok(())
    }

    #[test]
    fn ifac_verify_rejects_short_output_without_writing() -> Result<(), RnsWireError> {
        let identity = secret_identity_from_bytes(&IFAC_SECRET_IDENTITY)
            .map_err(|_| RnsWireError::InvalidSignature)?;
        let raw = raw_packet()?;
        let mut masked = [0; 128];
        let masked_len = ifac_apply_outbound(&raw, &identity, &IFAC_KEY, IFAC_SIZE, &mut masked)?;
        let mut verified = [0x55; 4];

        assert_eq!(
            ifac_verify_inbound(
                &masked[..masked_len],
                &identity,
                &IFAC_KEY,
                IFAC_SIZE,
                &mut verified
            ),
            Err(RnsWireError::OutputBufferTooShort {
                actual: 4,
                required: raw.len(),
            })
        );
        assert_eq!(verified, [0x55; 4]);
        Ok(())
    }

    fn raw_packet() -> Result<[u8; 22], RnsWireError> {
        let packet = RnsPacketRef {
            flags: RnsPacketFlags {
                header_type: RnsHeaderType::Header1,
                context_flag: false,
                transport_type: RnsTransportType::Broadcast,
                destination_type: RnsDestinationType::Single,
                packet_type: RnsPacketType::Data,
            },
            hops: 3,
            transport_id: None,
            destination_hash: RnsDestinationHash::new([0x11; 16]),
            context: RNS_CONTEXT_NONE,
            data: &[0xaa, 0xbb, 0xcc],
        };
        let mut output = [0; 22];
        let len = encode_packet(packet, &mut output)?;
        debug_assert_eq!(len, output.len());
        Ok(output)
    }
}
