use crate::{
    HYF_NOSTR_MAX_ENVELOPE_BYTES, NostrError, decode_lower_hex, encode_lower_hex,
    validate_content_len,
};

pub fn encode_hyf_envelope_content<'out>(
    bytes: &[u8],
    out: &'out mut [u8],
) -> Result<&'out str, NostrError> {
    if bytes.len() > HYF_NOSTR_MAX_ENVELOPE_BYTES {
        return Err(NostrError::EnvelopeTooLarge {
            actual: bytes.len(),
            maximum: HYF_NOSTR_MAX_ENVELOPE_BYTES,
        });
    }
    encode_lower_hex(bytes, out)
}

pub fn decode_hyf_envelope_content(content: &str, out: &mut [u8]) -> Result<usize, NostrError> {
    validate_content_len(content)?;
    decode_lower_hex(content, out)
}

#[cfg(test)]
mod tests {
    use super::{decode_hyf_envelope_content, encode_hyf_envelope_content};
    use crate::{
        HYF_NOSTR_MAX_CONTENT_CHARS, HYF_NOSTR_MAX_ENVELOPE_BYTES, NostrError,
        decode_fixed_lower_hex,
    };

    #[test]
    fn content_codec_roundtrips_bytes() -> Result<(), NostrError> {
        let envelope = [0x00, 0x01, 0x10, 0xab, 0xff];
        let mut content = [0; 10];
        let content = encode_hyf_envelope_content(&envelope, &mut content)?;
        assert_eq!(content, "000110abff");

        let mut decoded = [0; 5];
        let len = decode_hyf_envelope_content(content, &mut decoded)?;
        assert_eq!(len, envelope.len());
        assert_eq!(decoded, envelope);
        Ok(())
    }

    #[test]
    fn content_codec_allows_maximum_envelope_size() -> Result<(), NostrError> {
        let envelope = [0xa5; HYF_NOSTR_MAX_ENVELOPE_BYTES];
        let mut content = [0; HYF_NOSTR_MAX_CONTENT_CHARS];
        let content = encode_hyf_envelope_content(&envelope, &mut content)?;
        assert_eq!(content.len(), HYF_NOSTR_MAX_CONTENT_CHARS);

        let mut decoded = [0; HYF_NOSTR_MAX_ENVELOPE_BYTES];
        let len = decode_hyf_envelope_content(content, &mut decoded)?;
        assert_eq!(len, HYF_NOSTR_MAX_ENVELOPE_BYTES);
        assert_eq!(decoded, envelope);
        Ok(())
    }

    #[test]
    fn content_codec_rejects_oversized_envelope_bytes() {
        let envelope = [0; HYF_NOSTR_MAX_ENVELOPE_BYTES + 1];
        let mut content = [0; HYF_NOSTR_MAX_CONTENT_CHARS + 2];

        assert_eq!(
            encode_hyf_envelope_content(&envelope, &mut content),
            Err(NostrError::EnvelopeTooLarge {
                actual: HYF_NOSTR_MAX_ENVELOPE_BYTES + 1,
                maximum: HYF_NOSTR_MAX_ENVELOPE_BYTES,
            })
        );
    }

    #[test]
    fn content_codec_rejects_oversized_content() {
        let content = "a".repeat(HYF_NOSTR_MAX_CONTENT_CHARS + 1);
        let mut decoded = [0; HYF_NOSTR_MAX_ENVELOPE_BYTES + 1];

        assert_eq!(
            decode_hyf_envelope_content(&content, &mut decoded),
            Err(NostrError::ContentTooLarge {
                actual: HYF_NOSTR_MAX_CONTENT_CHARS + 1,
                maximum: HYF_NOSTR_MAX_CONTENT_CHARS,
            })
        );
    }

    #[test]
    fn content_codec_rejects_non_canonical_content() {
        assert!(matches!(
            decode_hyf_envelope_content("0A", &mut [0; 1]),
            Err(NostrError::NonCanonicalHex {
                index: 1,
                byte: b'A'
            })
        ));
        assert!(matches!(
            decode_hyf_envelope_content("0 ", &mut [0; 1]),
            Err(NostrError::InvalidHexChar {
                index: 1,
                byte: b' '
            })
        ));
        assert_eq!(
            decode_hyf_envelope_content("abc", &mut [0; 2]),
            Err(NostrError::OddHexLength { len: 3 })
        );
        assert!(decode_fixed_lower_hex::<1>("0a").is_ok());
    }

    #[test]
    fn content_codec_reports_short_output_buffers() {
        assert_eq!(
            encode_hyf_envelope_content(&[1, 2], &mut [0; 3]),
            Err(NostrError::OutputTooSmall {
                needed: 4,
                available: 3,
            })
        );
        assert_eq!(
            decode_hyf_envelope_content("0001", &mut [0; 1]),
            Err(NostrError::OutputTooSmall {
                needed: 2,
                available: 1,
            })
        );
    }
}
