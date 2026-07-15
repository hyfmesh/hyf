use sha2::{Digest, Sha256};

use crate::{
    LXMF_DESTINATION_HASH_LEN, LXMF_MESSAGE_ID_LEN, LXMF_SOURCE_HASH_LEN, LxmfError, LxmfMessageId,
    LxmfMessageRef, msgpack::MsgpackCursor,
};

const LXMF_PAYLOAD_ARRAY_LEN: usize = 4;
const LXMF_PAYLOAD_ARRAY_WITH_STAMP_LEN: usize = 5;
const FIXED_ARRAY4_MARKER: u8 = 0x90 | LXMF_PAYLOAD_ARRAY_LEN as u8;

pub fn lxmf_message_id(message: LxmfMessageRef<'_>) -> Result<LxmfMessageId, LxmfError> {
    let signing_payload = SigningPayload::parse(message.packed_payload())?;
    Ok(message_id_with_signing_payload(message, &signing_payload))
}

pub fn lxmf_signature_input_len(message: LxmfMessageRef<'_>) -> Result<usize, LxmfError> {
    let signing_payload = SigningPayload::parse(message.packed_payload())?;
    Ok(LXMF_DESTINATION_HASH_LEN
        + LXMF_SOURCE_HASH_LEN
        + signing_payload.len()
        + LXMF_MESSAGE_ID_LEN)
}

pub fn write_lxmf_signature_input(
    message: LxmfMessageRef<'_>,
    output: &mut [u8],
) -> Result<usize, LxmfError> {
    let signing_payload = SigningPayload::parse(message.packed_payload())?;
    let required = LXMF_DESTINATION_HASH_LEN
        .checked_add(LXMF_SOURCE_HASH_LEN)
        .and_then(|len| len.checked_add(signing_payload.len()))
        .and_then(|len| len.checked_add(LXMF_MESSAGE_ID_LEN))
        .ok_or(LxmfError::OutputTooSmall {
            needed: usize::MAX,
            available: output.len(),
        })?;
    if output.len() < required {
        return Err(LxmfError::OutputTooSmall {
            needed: required,
            available: output.len(),
        });
    }

    let mut sink = OutputSink::new(output);
    sink.write(message.destination_hash().as_bytes());
    sink.write(message.source_hash().as_bytes());
    signing_payload.write_to(&mut sink);
    let message_id = message_id_with_signing_payload(message, &signing_payload);
    sink.write(message_id.as_bytes());
    Ok(required)
}

fn message_id_with_signing_payload(
    message: LxmfMessageRef<'_>,
    signing_payload: &SigningPayload<'_>,
) -> LxmfMessageId {
    let mut hasher = message_id_hasher(message);
    signing_payload.update_hasher(&mut hasher);
    finish_message_id(hasher)
}

fn message_id_hasher(message: LxmfMessageRef<'_>) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(message.destination_hash().as_bytes());
    hasher.update(message.source_hash().as_bytes());
    hasher
}

fn finish_message_id(hasher: Sha256) -> LxmfMessageId {
    LxmfMessageId::from_bytes(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SigningPayload<'a> {
    Original(&'a [u8]),
    CanonicalArray4 { elements: [&'a [u8]; 4], len: usize },
}

impl<'a> SigningPayload<'a> {
    fn parse(packed_payload: &'a [u8]) -> Result<Self, LxmfError> {
        let mut cursor = MsgpackCursor::new(packed_payload);
        let array_len = cursor.read_array_len()?;
        match array_len {
            LXMF_PAYLOAD_ARRAY_LEN => {
                for _ in 0..LXMF_PAYLOAD_ARRAY_LEN {
                    cursor.read_raw_value()?;
                }
                cursor.finish()?;
                Ok(Self::Original(packed_payload))
            }
            LXMF_PAYLOAD_ARRAY_WITH_STAMP_LEN => {
                let timestamp = cursor.read_raw_value()?;
                let title = cursor.read_raw_value()?;
                let content = cursor.read_raw_value()?;
                let fields = cursor.read_raw_value()?;
                cursor.read_raw_value()?;
                cursor.finish()?;
                let elements = [timestamp, title, content, fields];
                let len = canonical_array4_len(elements)?;
                Ok(Self::CanonicalArray4 { elements, len })
            }
            actual => Err(LxmfError::InvalidPayloadArrayLen { actual }),
        }
    }

    const fn len(self) -> usize {
        match self {
            Self::Original(bytes) => bytes.len(),
            Self::CanonicalArray4 { len, .. } => len,
        }
    }

    fn update_hasher(self, hasher: &mut Sha256) {
        match self {
            Self::Original(bytes) => hasher.update(bytes),
            Self::CanonicalArray4 { elements, .. } => {
                hasher.update([FIXED_ARRAY4_MARKER]);
                for element in elements {
                    hasher.update(element);
                }
            }
        }
    }

    fn write_to(self, sink: &mut OutputSink<'_>) {
        match self {
            Self::Original(bytes) => sink.write(bytes),
            Self::CanonicalArray4 { elements, .. } => {
                sink.write(&[FIXED_ARRAY4_MARKER]);
                for element in elements {
                    sink.write(element);
                }
            }
        }
    }
}

fn canonical_array4_len(elements: [&[u8]; 4]) -> Result<usize, LxmfError> {
    let mut len = 1usize;
    for element in elements {
        len = len
            .checked_add(element.len())
            .ok_or(LxmfError::PayloadTooLarge {
                actual: usize::MAX,
                maximum: crate::LXMF_PAYLOAD_MAX_LEN,
            })?;
    }
    Ok(len)
}

struct OutputSink<'a> {
    output: &'a mut [u8],
    index: usize,
}

impl<'a> OutputSink<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, index: 0 }
    }

    fn write(&mut self, bytes: &[u8]) {
        let end = self.index + bytes.len();
        self.output[self.index..end].copy_from_slice(bytes);
        self.index = end;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SigningPayload, lxmf_message_id, lxmf_signature_input_len, write_lxmf_signature_input,
    };
    use crate::{
        LXMF_DESTINATION_HASH_LEN, LXMF_FIXED_HEADER_LEN, LXMF_MESSAGE_ID_LEN,
        LXMF_SOURCE_HASH_LEN, LxmfDestinationHash, LxmfError, LxmfMessageId, LxmfMessageRef,
        LxmfPayloadRef, LxmfRawMapRef, LxmfSignature, LxmfSourceHash, decode_lxmf_message,
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
    const PAYLOAD5_WITH_EXT_STAMP: &[u8] = &[
        0x95, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4,
        0x05, b'h', b'e', b'l', b'l', b'o', 0x80, 0xc7, 0x02, 0x01, 0xaa, 0xbb,
    ];
    const PAYLOAD5_WITH_STRINGS: &[u8] = &[
        0x95, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xa5, b't', b'i', b't', b'l', b'e', 0xa5, b'h',
        b'e', b'l', b'l', b'o', 0x80, 0xc4, 0x02, b'x', b'x',
    ];
    const EXPECTED_PAYLOAD5_STRING_SIGNING_PAYLOAD: &[u8] = &[
        0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xa5, b't', b'i', b't', b'l', b'e', 0xa5, b'h',
        b'e', b'l', b'l', b'o', 0x80,
    ];
    const EXPECTED_MESSAGE_ID: [u8; 32] = [
        0x18, 0x93, 0xa6, 0xcf, 0x0c, 0xca, 0x60, 0x56, 0x8b, 0x39, 0xf7, 0xa7, 0x00, 0xa1, 0x7a,
        0x67, 0xc0, 0x1c, 0x05, 0xb1, 0xc1, 0xea, 0xbc, 0x6b, 0xa5, 0xf5, 0xd9, 0xf6, 0xfa, 0x17,
        0xe3, 0xe3,
    ];
    const SIGNATURE_INPUT_LEN: usize =
        LXMF_DESTINATION_HASH_LEN + LXMF_SOURCE_HASH_LEN + PAYLOAD4.len() + LXMF_MESSAGE_ID_LEN;

    #[test]
    fn signing_payload_uses_original_array4_bytes() -> Result<(), LxmfError> {
        let signing_payload = SigningPayload::parse(PAYLOAD4)?;
        let mut output = [0; PAYLOAD4.len()];
        let mut sink = super::OutputSink::new(&mut output);

        signing_payload.write_to(&mut sink);

        assert_eq!(signing_payload.len(), PAYLOAD4.len());
        assert_eq!(&output, PAYLOAD4);
        Ok(())
    }

    #[test]
    fn signing_payload_excludes_array5_stamp() -> Result<(), LxmfError> {
        let signing_payload = SigningPayload::parse(PAYLOAD5)?;
        let mut output = [0; PAYLOAD4.len()];
        let mut sink = super::OutputSink::new(&mut output);

        signing_payload.write_to(&mut sink);

        assert_eq!(signing_payload.len(), PAYLOAD4.len());
        assert_eq!(&output, PAYLOAD4);
        Ok(())
    }

    #[test]
    fn signing_payload_preserves_raw_first_four_array5_items() -> Result<(), LxmfError> {
        let signing_payload = SigningPayload::parse(PAYLOAD5_WITH_STRINGS)?;
        let mut output = [0; EXPECTED_PAYLOAD5_STRING_SIGNING_PAYLOAD.len()];
        let mut sink = super::OutputSink::new(&mut output);

        signing_payload.write_to(&mut sink);

        assert_eq!(signing_payload.len(), output.len());
        assert_eq!(&output, EXPECTED_PAYLOAD5_STRING_SIGNING_PAYLOAD);
        Ok(())
    }

    #[test]
    fn message_id_matches_vector_and_excludes_stamp() -> Result<(), LxmfError> {
        let mut full_message4 = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        let mut full_message5 = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD5.len()];
        write_full_message(PAYLOAD4, &mut full_message4);
        write_full_message(PAYLOAD5, &mut full_message5);
        let message4 = decode_lxmf_message(&full_message4)?;
        let message5 = decode_lxmf_message(&full_message5)?;
        let expected = LxmfMessageId::from_bytes(EXPECTED_MESSAGE_ID);

        assert_eq!(lxmf_message_id(message4)?, expected);
        assert_eq!(lxmf_message_id(message5)?, expected);
        Ok(())
    }

    #[test]
    fn message_id_and_signature_input_exclude_extension_stamp() -> Result<(), LxmfError> {
        let mut full_message4 = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        let mut full_message5 = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD5_WITH_EXT_STAMP.len()];
        write_full_message(PAYLOAD4, &mut full_message4);
        write_full_message(PAYLOAD5_WITH_EXT_STAMP, &mut full_message5);
        let message4 = decode_lxmf_message(&full_message4)?;
        let message5 = decode_lxmf_message(&full_message5)?;
        let expected = LxmfMessageId::from_bytes(EXPECTED_MESSAGE_ID);
        let mut output4 = [0; SIGNATURE_INPUT_LEN];
        let mut output5 = [0; SIGNATURE_INPUT_LEN];

        assert_eq!(lxmf_message_id(message4)?, expected);
        assert_eq!(lxmf_message_id(message5)?, expected);
        assert_eq!(
            write_lxmf_signature_input(message4, &mut output4)?,
            SIGNATURE_INPUT_LEN
        );
        assert_eq!(
            write_lxmf_signature_input(message5, &mut output5)?,
            SIGNATURE_INPUT_LEN
        );
        assert_eq!(lxmf_signature_input_len(message5)?, SIGNATURE_INPUT_LEN);
        assert_eq!(output4, output5);
        Ok(())
    }

    #[test]
    fn signature_input_matches_vector_and_excludes_stamp() -> Result<(), LxmfError> {
        let mut full_message4 = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        let mut full_message5 = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD5.len()];
        write_full_message(PAYLOAD4, &mut full_message4);
        write_full_message(PAYLOAD5, &mut full_message5);
        let message4 = decode_lxmf_message(&full_message4)?;
        let message5 = decode_lxmf_message(&full_message5)?;
        let mut output4 = [0; SIGNATURE_INPUT_LEN];
        let mut output5 = [0; SIGNATURE_INPUT_LEN];

        let len4 = write_lxmf_signature_input(message4, &mut output4)?;
        let len5 = write_lxmf_signature_input(message5, &mut output5)?;

        assert_eq!(len4, SIGNATURE_INPUT_LEN);
        assert_eq!(len5, SIGNATURE_INPUT_LEN);
        assert_eq!(lxmf_signature_input_len(message4)?, SIGNATURE_INPUT_LEN);
        assert_eq!(lxmf_signature_input_len(message5)?, SIGNATURE_INPUT_LEN);
        assert_eq!(output4, output5);
        assert_eq!(&output4[..16], &DESTINATION_HASH);
        assert_eq!(&output4[16..32], &SOURCE_HASH);
        assert_eq!(&output4[32..32 + PAYLOAD4.len()], PAYLOAD4);
        assert_eq!(&output4[32 + PAYLOAD4.len()..], &EXPECTED_MESSAGE_ID);
        Ok(())
    }

    #[test]
    fn signature_input_rejects_short_output() -> Result<(), LxmfError> {
        let mut full_message = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
        write_full_message(PAYLOAD4, &mut full_message);
        let message = decode_lxmf_message(&full_message)?;
        let mut output = [0; 1];

        assert_eq!(
            write_lxmf_signature_input(message, &mut output),
            Err(LxmfError::OutputTooSmall {
                needed: SIGNATURE_INPUT_LEN,
                available: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn message_id_and_signature_input_reject_malformed_signing_payload() {
        let message = LxmfMessageRef::from_unchecked_parts_for_test(
            LxmfDestinationHash::from_bytes(DESTINATION_HASH),
            LxmfSourceHash::from_bytes(SOURCE_HASH),
            LxmfSignature::from_bytes(SIGNATURE),
            &[0x95],
            LxmfPayloadRef {
                timestamp_secs: 1.5,
                title: b"title",
                content: b"hello",
                fields: LxmfRawMapRef { bytes: &[0x80] },
                stamp: None,
            },
        );
        let mut output = [0; 128];

        assert_eq!(lxmf_message_id(message), Err(LxmfError::MsgpackTruncated));
        assert_eq!(
            lxmf_signature_input_len(message),
            Err(LxmfError::MsgpackTruncated)
        );
        assert_eq!(
            write_lxmf_signature_input(message, &mut output),
            Err(LxmfError::MsgpackTruncated)
        );
    }

    fn write_full_message(payload: &[u8], output: &mut [u8]) {
        output[..16].copy_from_slice(&DESTINATION_HASH);
        output[16..32].copy_from_slice(&SOURCE_HASH);
        output[32..96].copy_from_slice(&SIGNATURE);
        output[96..96 + payload.len()].copy_from_slice(payload);
    }
}
