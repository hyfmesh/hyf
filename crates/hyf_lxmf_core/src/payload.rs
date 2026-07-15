use crate::{
    LXMF_CONTENT_MAX_LEN, LXMF_FIELDS_MAX_LEN, LXMF_PAYLOAD_MAX_LEN, LXMF_STAMP_MAX_LEN,
    LXMF_TITLE_MAX_LEN, LxmfError, LxmfPayloadRef, LxmfRawMapRef, LxmfStampRef,
    msgpack::MsgpackCursor,
};

const LXMF_PAYLOAD_ARRAY_LEN: usize = 4;
const LXMF_PAYLOAD_ARRAY_WITH_STAMP_LEN: usize = 5;

pub fn decode_lxmf_payload(input: &[u8]) -> Result<LxmfPayloadRef<'_>, LxmfError> {
    if input.len() > LXMF_PAYLOAD_MAX_LEN {
        return Err(LxmfError::PayloadTooLarge {
            actual: input.len(),
            maximum: LXMF_PAYLOAD_MAX_LEN,
        });
    }

    let mut cursor = MsgpackCursor::new(input);
    let array_len = cursor.read_array_len()?;
    if array_len != LXMF_PAYLOAD_ARRAY_LEN && array_len != LXMF_PAYLOAD_ARRAY_WITH_STAMP_LEN {
        return Err(LxmfError::InvalidPayloadArrayLen { actual: array_len });
    }

    let timestamp_secs = cursor.read_float64()?;
    if !timestamp_secs.is_finite() {
        return Err(LxmfError::InvalidTimestamp);
    }

    let title = cursor.read_bin_or_str_bytes()?;
    if title.len() > LXMF_TITLE_MAX_LEN {
        return Err(LxmfError::TitleTooLarge {
            actual: title.len(),
            maximum: LXMF_TITLE_MAX_LEN,
        });
    }

    let content = cursor.read_bin_or_str_bytes()?;
    if content.len() > LXMF_CONTENT_MAX_LEN {
        return Err(LxmfError::ContentTooLarge {
            actual: content.len(),
            maximum: LXMF_CONTENT_MAX_LEN,
        });
    }

    let fields = cursor.read_raw_map()?;
    if fields.len() > LXMF_FIELDS_MAX_LEN {
        return Err(LxmfError::FieldsTooLarge {
            actual: fields.len(),
            maximum: LXMF_FIELDS_MAX_LEN,
        });
    }

    let stamp = if array_len == LXMF_PAYLOAD_ARRAY_WITH_STAMP_LEN {
        let bytes = cursor.read_raw_value()?;
        if bytes.len() > LXMF_STAMP_MAX_LEN {
            return Err(LxmfError::StampTooLarge {
                actual: bytes.len(),
                maximum: LXMF_STAMP_MAX_LEN,
            });
        }
        Some(LxmfStampRef { bytes })
    } else {
        None
    };
    cursor.finish()?;

    Ok(LxmfPayloadRef {
        timestamp_secs,
        title,
        content,
        fields: LxmfRawMapRef { bytes: fields },
        stamp,
    })
}

pub fn lxmf_payload_encoded_len(payload: LxmfPayloadRef<'_>) -> Result<usize, LxmfError> {
    validate_payload_for_encode(payload)?;
    let required = 1usize
        .checked_add(9)
        .and_then(|len| len.checked_add(bin_encoded_len(payload.title.len())))
        .and_then(|len| len.checked_add(bin_encoded_len(payload.content.len())))
        .and_then(|len| len.checked_add(payload.fields.bytes.len()))
        .ok_or(LxmfError::PayloadTooLarge {
            actual: payload.fields.bytes.len(),
            maximum: LXMF_PAYLOAD_MAX_LEN,
        })?;
    if required > LXMF_PAYLOAD_MAX_LEN {
        return Err(LxmfError::PayloadTooLarge {
            actual: required,
            maximum: LXMF_PAYLOAD_MAX_LEN,
        });
    }
    Ok(required)
}

pub fn encode_lxmf_payload(
    payload: LxmfPayloadRef<'_>,
    output: &mut [u8],
) -> Result<usize, LxmfError> {
    let required = lxmf_payload_encoded_len(payload)?;
    if output.len() < required {
        return Err(LxmfError::OutputTooSmall {
            needed: required,
            available: output.len(),
        });
    }

    let mut cursor = WriteCursor::new(output);
    cursor.write_u8(0x90 | LXMF_PAYLOAD_ARRAY_LEN as u8);
    cursor.write_u8(0xcb);
    cursor.write_array(&payload.timestamp_secs.to_bits().to_be_bytes());
    write_bin(payload.title, &mut cursor)?;
    write_bin(payload.content, &mut cursor)?;
    cursor.write_array(payload.fields.bytes);
    Ok(required)
}

fn validate_payload_for_encode(payload: LxmfPayloadRef<'_>) -> Result<(), LxmfError> {
    if !payload.timestamp_secs.is_finite() {
        return Err(LxmfError::InvalidTimestamp);
    }
    if payload.title.len() > LXMF_TITLE_MAX_LEN {
        return Err(LxmfError::TitleTooLarge {
            actual: payload.title.len(),
            maximum: LXMF_TITLE_MAX_LEN,
        });
    }
    if payload.content.len() > LXMF_CONTENT_MAX_LEN {
        return Err(LxmfError::ContentTooLarge {
            actual: payload.content.len(),
            maximum: LXMF_CONTENT_MAX_LEN,
        });
    }
    validate_raw_map(payload.fields.bytes)?;
    if payload.fields.bytes.len() > LXMF_FIELDS_MAX_LEN {
        return Err(LxmfError::FieldsTooLarge {
            actual: payload.fields.bytes.len(),
            maximum: LXMF_FIELDS_MAX_LEN,
        });
    }
    if let Some(stamp) = payload.stamp
        && stamp.bytes.len() > LXMF_STAMP_MAX_LEN
    {
        return Err(LxmfError::StampTooLarge {
            actual: stamp.bytes.len(),
            maximum: LXMF_STAMP_MAX_LEN,
        });
    }
    Ok(())
}

pub(crate) fn validate_raw_map(input: &[u8]) -> Result<(), LxmfError> {
    let mut cursor = MsgpackCursor::new(input);
    cursor.read_raw_map()?;
    cursor.finish()
}

const fn bin_encoded_len(len: usize) -> usize {
    if len <= u8::MAX as usize {
        2 + len
    } else {
        3 + len
    }
}

fn write_bin(bytes: &[u8], cursor: &mut WriteCursor<'_>) -> Result<(), LxmfError> {
    if bytes.len() <= u8::MAX as usize {
        cursor.write_u8(0xc4);
        cursor.write_u8(bytes.len() as u8);
    } else if bytes.len() <= u16::MAX as usize {
        cursor.write_u8(0xc5);
        cursor.write_array(&(bytes.len() as u16).to_be_bytes());
    } else {
        return Err(LxmfError::PayloadTooLarge {
            actual: bytes.len(),
            maximum: LXMF_PAYLOAD_MAX_LEN,
        });
    }
    cursor.write_array(bytes);
    Ok(())
}

struct WriteCursor<'a> {
    output: &'a mut [u8],
    index: usize,
}

impl<'a> WriteCursor<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, index: 0 }
    }

    fn write_u8(&mut self, value: u8) {
        self.output[self.index] = value;
        self.index += 1;
    }

    fn write_array(&mut self, value: &[u8]) {
        let end = self.index + value.len();
        self.output[self.index..end].copy_from_slice(value);
        self.index = end;
    }
}

#[cfg(test)]
mod tests {
    use super::decode_lxmf_payload;
    use crate::{
        LXMF_CONTENT_MAX_LEN, LXMF_FIELDS_MAX_LEN, LXMF_PAYLOAD_MAX_LEN, LXMF_STAMP_MAX_LEN,
        LXMF_TITLE_MAX_LEN, LxmfError, LxmfPayloadRef, LxmfRawMapRef, LxmfStampRef,
        encode_lxmf_payload, lxmf_payload_encoded_len,
    };

    const PAYLOAD4: &[u8] = &[
        0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4,
        0x05, b'h', b'e', b'l', b'l', b'o', 0x80,
    ];
    const PAYLOAD5: &[u8] = &[
        0x95, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4,
        0x05, b'h', b'e', b'l', b'l', b'o', 0x80, 0xc4, 0x02, b'x', b'x',
    ];

    #[test]
    fn payload_decode_accepts_array4_source_order() -> Result<(), LxmfError> {
        let payload = decode_lxmf_payload(PAYLOAD4)?;

        assert_eq!(payload.timestamp_secs, 1.5);
        assert_eq!(payload.title, b"title");
        assert_eq!(payload.content, b"hello");
        assert_eq!(payload.fields, LxmfRawMapRef { bytes: &[0x80] });
        assert_eq!(payload.stamp, None);
        Ok(())
    }

    #[test]
    fn payload_decode_accepts_array5_with_stamp() -> Result<(), LxmfError> {
        let payload = decode_lxmf_payload(PAYLOAD5)?;

        assert_eq!(payload.title, b"title");
        assert_eq!(payload.content, b"hello");
        assert_eq!(
            payload.stamp,
            Some(LxmfStampRef {
                bytes: &[0xc4, 0x02, b'x', b'x'],
            })
        );
        Ok(())
    }

    #[test]
    fn payload_source_order_title_content_are_not_swapped() -> Result<(), LxmfError> {
        let readme_order = [
            0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b'h', b'e', b'l', b'l', b'o',
            0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0x80,
        ];
        let payload = decode_lxmf_payload(&readme_order)?;

        assert_ne!(payload.title, b"title");
        assert_ne!(payload.content, b"hello");
        assert_eq!(payload.title, b"hello");
        assert_eq!(payload.content, b"title");
        Ok(())
    }

    #[test]
    fn payload_decode_rejects_array_lengths_outside_profile() {
        assert_eq!(
            decode_lxmf_payload(&[0x93, 0xcb, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(LxmfError::InvalidPayloadArrayLen { actual: 3 })
        );
        assert_eq!(
            decode_lxmf_payload(&[0x96, 0xcb, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(LxmfError::InvalidPayloadArrayLen { actual: 6 })
        );
    }

    #[test]
    fn payload_decode_rejects_f32_timestamp() {
        let payload = [
            0x94, 0xca, 0x3f, 0xc0, 0, 0, 0xc4, 0x01, b'a', 0xc4, 0x01, b'b', 0x80,
        ];

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::UnsupportedMsgpackType { marker: 0xca })
        );
    }

    #[test]
    fn payload_decode_rejects_non_finite_timestamp() {
        let payload = [
            0x94, 0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x01, b'a', 0xc4, 0x01, b'b', 0x80,
        ];

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::InvalidTimestamp)
        );
    }

    #[test]
    fn payload_decode_accepts_title_content_str_as_bytes() -> Result<(), LxmfError> {
        let payload = [
            0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xa5, b't', b'i', b't', b'l', b'e', 0xa5,
            b'h', b'e', b'l', b'l', b'o', 0x80,
        ];
        let decoded = decode_lxmf_payload(&payload)?;

        assert_eq!(decoded.title, b"title");
        assert_eq!(decoded.content, b"hello");
        Ok(())
    }

    #[test]
    fn payload_decode_preserves_nested_fields_raw() -> Result<(), LxmfError> {
        let fields = [0x81, 0xa1, b'a', 0x81, 0xa1, b'b', 0x01];
        let payload = [
            0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x01, b't', 0xc4, 0x01, b'c',
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
        ];
        let decoded = decode_lxmf_payload(&payload)?;

        assert_eq!(decoded.fields.bytes, fields);
        Ok(())
    }

    #[test]
    fn payload_decode_preserves_extension_fields_raw() -> Result<(), LxmfError> {
        let fields = [
            0x82, 0xa1, b'a', 0xd4, 0x01, 0xaa, 0xa1, b'b', 0xc7, 0x02, 0x02, 0xbb, 0xcc,
        ];
        let payload = payload_with_parts(
            &repeated_bin(1, b't'),
            &repeated_bin(1, b'c'),
            &fields,
            None,
        );

        let decoded = decode_lxmf_payload(&payload)?;

        assert_eq!(decoded.fields.bytes, fields);
        Ok(())
    }

    #[test]
    fn payload_decode_rejects_non_map_fields() {
        let payload = [
            0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x01, b't', 0xc4, 0x01, b'c', 0x90,
        ];

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::UnsupportedMsgpackType { marker: 0x90 })
        );
    }

    #[test]
    fn payload_decode_rejects_oversize_payload_input() {
        let too_large = [0; LXMF_PAYLOAD_MAX_LEN + 1];

        assert_eq!(
            decode_lxmf_payload(&too_large),
            Err(LxmfError::PayloadTooLarge {
                actual: LXMF_PAYLOAD_MAX_LEN + 1,
                maximum: LXMF_PAYLOAD_MAX_LEN,
            })
        );
    }

    #[test]
    fn payload_decode_rejects_oversize_title() {
        let payload = payload_with_parts(
            &repeated_bin(LXMF_TITLE_MAX_LEN + 1, b't'),
            &repeated_bin(1, b'c'),
            &[0x80],
            None,
        );

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::TitleTooLarge {
                actual: LXMF_TITLE_MAX_LEN + 1,
                maximum: LXMF_TITLE_MAX_LEN,
            })
        );
    }

    #[test]
    fn payload_decode_rejects_oversize_content() {
        let payload = payload_with_parts(
            &repeated_bin(1, b't'),
            &repeated_bin(LXMF_CONTENT_MAX_LEN + 1, b'c'),
            &[0x80],
            None,
        );

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::ContentTooLarge {
                actual: LXMF_CONTENT_MAX_LEN + 1,
                maximum: LXMF_CONTENT_MAX_LEN,
            })
        );
    }

    #[test]
    fn payload_decode_rejects_oversize_fields() {
        let fields = fields_map_over_limit();
        let payload = payload_with_parts(
            &repeated_bin(1, b't'),
            &repeated_bin(1, b'c'),
            &fields,
            None,
        );

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::FieldsTooLarge {
                actual: fields.len(),
                maximum: LXMF_FIELDS_MAX_LEN,
            })
        );
    }

    #[test]
    fn payload_decode_rejects_oversize_stamp() {
        let stamp = repeated_bin(LXMF_STAMP_MAX_LEN - 1, b's');
        let payload = payload_with_parts(
            &repeated_bin(1, b't'),
            &repeated_bin(1, b'c'),
            &[0x80],
            Some(&stamp),
        );

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::StampTooLarge {
                actual: stamp.len(),
                maximum: LXMF_STAMP_MAX_LEN,
            })
        );
    }

    #[test]
    fn encode_payload_uses_array4_and_bin_fields() -> Result<(), LxmfError> {
        let payload = LxmfPayloadRef {
            timestamp_secs: 1.5,
            title: b"title",
            content: b"hello",
            fields: LxmfRawMapRef { bytes: &[0x80] },
            stamp: None,
        };
        let mut output = [0; 64];

        let len = encode_lxmf_payload(payload, &mut output)?;

        assert_eq!(len, PAYLOAD4.len());
        assert_eq!(&output[..len], PAYLOAD4);
        assert_eq!(lxmf_payload_encoded_len(payload)?, PAYLOAD4.len());
        Ok(())
    }

    #[test]
    fn encode_payload_does_not_generate_optional_stamp() -> Result<(), LxmfError> {
        let payload = LxmfPayloadRef {
            timestamp_secs: 1.5,
            title: b"title",
            content: b"hello",
            fields: LxmfRawMapRef { bytes: &[0x80] },
            stamp: Some(LxmfStampRef {
                bytes: &[0xc4, 0x02, b'x', b'x'],
            }),
        };
        let mut output = [0; 64];

        let len = encode_lxmf_payload(payload, &mut output)?;

        assert_eq!(&output[..len], PAYLOAD4);
        Ok(())
    }

    #[test]
    fn encode_payload_rejects_nan_infinite_and_short_output() {
        let nan = LxmfPayloadRef {
            timestamp_secs: f64::NAN,
            title: b"title",
            content: b"hello",
            fields: LxmfRawMapRef { bytes: &[0x80] },
            stamp: None,
        };
        let infinite = LxmfPayloadRef {
            timestamp_secs: f64::INFINITY,
            ..nan
        };
        let valid = LxmfPayloadRef {
            timestamp_secs: 1.5,
            ..nan
        };
        let mut output = [0; 1];

        assert_eq!(
            encode_lxmf_payload(nan, &mut output),
            Err(LxmfError::InvalidTimestamp)
        );
        assert_eq!(
            encode_lxmf_payload(infinite, &mut output),
            Err(LxmfError::InvalidTimestamp)
        );
        assert_eq!(
            encode_lxmf_payload(valid, &mut output),
            Err(LxmfError::OutputTooSmall {
                needed: PAYLOAD4.len(),
                available: 1,
            })
        );
    }

    #[test]
    fn encode_payload_rejects_malformed_fields() {
        let payload = LxmfPayloadRef {
            timestamp_secs: 1.5,
            title: b"title",
            content: b"hello",
            fields: LxmfRawMapRef { bytes: &[0x90] },
            stamp: None,
        };
        let mut output = [0; 64];

        assert_eq!(
            encode_lxmf_payload(payload, &mut output),
            Err(LxmfError::UnsupportedMsgpackType { marker: 0x90 })
        );
    }

    fn payload_with_parts(
        title: &[u8],
        content: &[u8],
        fields: &[u8],
        stamp: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(if stamp.is_some() { 0x95 } else { 0x94 });
        payload.extend_from_slice(&[0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]);
        payload.extend_from_slice(title);
        payload.extend_from_slice(content);
        payload.extend_from_slice(fields);
        if let Some(stamp) = stamp {
            payload.extend_from_slice(stamp);
        }
        payload
    }

    fn repeated_bin(len: usize, byte: u8) -> Vec<u8> {
        let mut bin = Vec::new();
        if len <= u8::MAX as usize {
            bin.push(0xc4);
            bin.push(len as u8);
        } else {
            bin.push(0xc5);
            bin.extend_from_slice(&(len as u16).to_be_bytes());
        }
        bin.resize(bin.len() + len, byte);
        bin
    }

    fn fields_map_over_limit() -> Vec<u8> {
        let mut fields = vec![0xde, 0x02, 0x00];
        for _ in 0..512 {
            fields.extend_from_slice(&[0x00, 0x00]);
        }
        fields
    }
}
