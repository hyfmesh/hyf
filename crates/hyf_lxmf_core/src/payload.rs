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

#[cfg(test)]
mod tests {
    use super::decode_lxmf_payload;
    use crate::{LxmfError, LxmfRawMapRef, LxmfStampRef};

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
    fn payload_decode_rejects_non_map_fields() {
        let payload = [
            0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x01, b't', 0xc4, 0x01, b'c', 0x90,
        ];

        assert_eq!(
            decode_lxmf_payload(&payload),
            Err(LxmfError::UnsupportedMsgpackType { marker: 0x90 })
        );
    }
}
