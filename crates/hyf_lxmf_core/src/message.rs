use crate::{
    LXMF_DESTINATION_HASH_LEN, LXMF_FIXED_HEADER_LEN, LXMF_MESSAGE_MAX_LEN, LXMF_SIGNATURE_LEN,
    LXMF_SOURCE_HASH_LEN, LxmfDestinationHash, LxmfError, LxmfMessageRef, LxmfPayloadRef,
    LxmfSignature, LxmfSourceHash, decode_lxmf_payload, encode_lxmf_payload,
    lxmf_payload_encoded_len,
};

pub fn decode_lxmf_message(input: &[u8]) -> Result<LxmfMessageRef<'_>, LxmfError> {
    if input.len() < LXMF_FIXED_HEADER_LEN {
        return Err(LxmfError::MessageTooShort {
            actual: input.len(),
            minimum: LXMF_FIXED_HEADER_LEN,
        });
    }
    if input.len() > LXMF_MESSAGE_MAX_LEN {
        return Err(LxmfError::MessageTooLarge {
            actual: input.len(),
            maximum: LXMF_MESSAGE_MAX_LEN,
        });
    }

    let mut destination_hash = [0; LXMF_DESTINATION_HASH_LEN];
    destination_hash.copy_from_slice(&input[..LXMF_DESTINATION_HASH_LEN]);
    let source_start = LXMF_DESTINATION_HASH_LEN;
    let source_end = source_start + LXMF_SOURCE_HASH_LEN;
    let mut source_hash = [0; LXMF_SOURCE_HASH_LEN];
    source_hash.copy_from_slice(&input[source_start..source_end]);
    let signature_end = source_end + LXMF_SIGNATURE_LEN;
    let mut signature = [0; LXMF_SIGNATURE_LEN];
    signature.copy_from_slice(&input[source_end..signature_end]);
    let packed_payload = &input[LXMF_FIXED_HEADER_LEN..];
    let payload = decode_lxmf_payload(packed_payload)?;

    Ok(LxmfMessageRef::from_decoded_parts(
        LxmfDestinationHash::from_bytes(destination_hash),
        LxmfSourceHash::from_bytes(source_hash),
        LxmfSignature::from_bytes(signature),
        packed_payload,
        payload,
    ))
}

pub fn encode_lxmf_message(
    destination: LxmfDestinationHash,
    source: LxmfSourceHash,
    signature: LxmfSignature,
    payload: LxmfPayloadRef<'_>,
    output: &mut [u8],
) -> Result<usize, LxmfError> {
    let payload_len = lxmf_payload_encoded_len(payload)?;
    let required =
        LXMF_FIXED_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(LxmfError::MessageTooLarge {
                actual: payload_len,
                maximum: LXMF_MESSAGE_MAX_LEN,
            })?;
    if required > LXMF_MESSAGE_MAX_LEN {
        return Err(LxmfError::MessageTooLarge {
            actual: required,
            maximum: LXMF_MESSAGE_MAX_LEN,
        });
    }
    if output.len() < required {
        return Err(LxmfError::OutputTooSmall {
            needed: required,
            available: output.len(),
        });
    }

    output[..LXMF_DESTINATION_HASH_LEN].copy_from_slice(destination.as_bytes());
    let source_start = LXMF_DESTINATION_HASH_LEN;
    let source_end = source_start + LXMF_SOURCE_HASH_LEN;
    output[source_start..source_end].copy_from_slice(source.as_bytes());
    let signature_end = source_end + LXMF_SIGNATURE_LEN;
    output[source_end..signature_end].copy_from_slice(signature.as_bytes());
    let written = encode_lxmf_payload(payload, &mut output[LXMF_FIXED_HEADER_LEN..required])?;
    Ok(LXMF_FIXED_HEADER_LEN + written)
}

#[cfg(test)]
mod tests {
    use super::{decode_lxmf_message, encode_lxmf_message};
    use crate::{
        LXMF_FIXED_HEADER_LEN, LXMF_MESSAGE_MAX_LEN, LxmfDestinationHash, LxmfError,
        LxmfPayloadRef, LxmfRawMapRef, LxmfSignature, LxmfSourceHash,
    };

    const DESTINATION_HASH: [u8; 16] = [0x01; 16];
    const SOURCE_HASH: [u8; 16] = [0x02; 16];
    const SIGNATURE: [u8; 64] = [0x03; 64];
    const PAYLOAD4: &[u8] = &[
        0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4,
        0x05, b'h', b'e', b'l', b'l', b'o', 0x80,
    ];
    const PAYLOAD5: &[u8] = &[
        0x95, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4,
        0x05, b'h', b'e', b'l', b'l', b'o', 0x80, 0xc4, 0x02, b'x', b'x',
    ];

    #[test]
    fn message_decode_accepts_full_array4_vector() -> Result<(), LxmfError> {
        let mut input = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        write_header_and_payload(PAYLOAD4, &mut input);

        let message = decode_lxmf_message(&input)?;

        assert_eq!(message.destination_hash().as_bytes(), &DESTINATION_HASH);
        assert_eq!(message.source_hash().as_bytes(), &SOURCE_HASH);
        assert_eq!(message.signature().as_bytes(), &SIGNATURE);
        assert_eq!(message.packed_payload(), PAYLOAD4);
        assert_eq!(message.payload().title, b"title");
        assert_eq!(message.payload().content, b"hello");
        Ok(())
    }

    #[test]
    fn message_decode_accepts_full_array5_vector() -> Result<(), LxmfError> {
        let mut input = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD5.len()];
        write_header_and_payload(PAYLOAD5, &mut input);

        let message = decode_lxmf_message(&input)?;

        assert_eq!(message.packed_payload(), PAYLOAD5);
        assert_eq!(
            message.payload().stamp.map(|stamp| stamp.bytes),
            Some(&PAYLOAD5[PAYLOAD5.len() - 4..])
        );
        Ok(())
    }

    #[test]
    fn message_decode_rejects_too_short_and_too_large_inputs() {
        assert_eq!(
            decode_lxmf_message(&[0; LXMF_FIXED_HEADER_LEN - 1]),
            Err(LxmfError::MessageTooShort {
                actual: LXMF_FIXED_HEADER_LEN - 1,
                minimum: LXMF_FIXED_HEADER_LEN,
            })
        );
        let too_large = [0; LXMF_MESSAGE_MAX_LEN + 1];
        assert_eq!(
            decode_lxmf_message(&too_large),
            Err(LxmfError::MessageTooLarge {
                actual: LXMF_MESSAGE_MAX_LEN + 1,
                maximum: LXMF_MESSAGE_MAX_LEN,
            })
        );
    }

    #[test]
    fn message_decode_rejects_malformed_payload_and_payload_trailing_bytes() {
        let mut malformed = [0; LXMF_FIXED_HEADER_LEN + 1];
        write_header_and_payload(&[0x80], &mut malformed);
        assert_eq!(
            decode_lxmf_message(&malformed),
            Err(LxmfError::UnsupportedMsgpackType { marker: 0x80 })
        );

        let mut trailing = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len() + 1];
        write_header_and_payload(
            PAYLOAD4,
            &mut trailing[..LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()],
        );
        trailing[LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()] = 0;
        assert_eq!(
            decode_lxmf_message(&trailing),
            Err(LxmfError::MsgpackTrailingBytes)
        );
    }

    #[test]
    fn message_encode_writes_full_vector() -> Result<(), LxmfError> {
        let payload = payload_ref();
        let mut output = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];

        let len = encode_lxmf_message(
            LxmfDestinationHash::from_bytes(DESTINATION_HASH),
            LxmfSourceHash::from_bytes(SOURCE_HASH),
            LxmfSignature::from_bytes(SIGNATURE),
            payload,
            &mut output,
        )?;

        assert_eq!(len, LXMF_FIXED_HEADER_LEN + PAYLOAD4.len());
        let decoded = decode_lxmf_message(&output)?;
        assert_eq!(decoded.destination_hash().as_bytes(), &DESTINATION_HASH);
        assert_eq!(decoded.source_hash().as_bytes(), &SOURCE_HASH);
        assert_eq!(decoded.signature().as_bytes(), &SIGNATURE);
        assert_eq!(decoded.packed_payload(), PAYLOAD4);
        Ok(())
    }

    #[test]
    fn message_encode_rejects_short_output() {
        let mut output = [0; 1];

        assert_eq!(
            encode_lxmf_message(
                LxmfDestinationHash::from_bytes(DESTINATION_HASH),
                LxmfSourceHash::from_bytes(SOURCE_HASH),
                LxmfSignature::from_bytes(SIGNATURE),
                payload_ref(),
                &mut output,
            ),
            Err(LxmfError::OutputTooSmall {
                needed: LXMF_FIXED_HEADER_LEN + PAYLOAD4.len(),
                available: 1,
            })
        );
    }

    fn payload_ref<'a>() -> LxmfPayloadRef<'a> {
        LxmfPayloadRef {
            timestamp_secs: 1.5,
            title: b"title",
            content: b"hello",
            fields: LxmfRawMapRef { bytes: &[0x80] },
            stamp: None,
        }
    }

    fn write_header_and_payload(payload: &[u8], output: &mut [u8]) {
        output[..16].copy_from_slice(&DESTINATION_HASH);
        output[16..32].copy_from_slice(&SOURCE_HASH);
        output[32..96].copy_from_slice(&SIGNATURE);
        output[96..96 + payload.len()].copy_from_slice(payload);
    }
}
