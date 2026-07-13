use core::str;

use crate::NostrError;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode_lower_hex<'a>(bytes: &[u8], out: &'a mut [u8]) -> Result<&'a str, NostrError> {
    let needed = bytes
        .len()
        .checked_mul(2)
        .ok_or(NostrError::OutputTooSmall {
            needed: usize::MAX,
            available: out.len(),
        })?;
    if out.len() < needed {
        return Err(NostrError::OutputTooSmall {
            needed,
            available: out.len(),
        });
    }

    for (index, byte) in bytes.iter().copied().enumerate() {
        out[index * 2] = HEX_DIGITS[(byte >> 4) as usize];
        out[(index * 2) + 1] = HEX_DIGITS[(byte & 0x0f) as usize];
    }

    str::from_utf8(&out[..needed]).map_err(|_| NostrError::Utf8)
}

pub fn decode_lower_hex(input: &str, out: &mut [u8]) -> Result<usize, NostrError> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(NostrError::OddHexLength { len: bytes.len() });
    }

    let needed = bytes.len() / 2;
    if out.len() < needed {
        return Err(NostrError::OutputTooSmall {
            needed,
            available: out.len(),
        });
    }

    for index in 0..needed {
        let high = decode_nibble(bytes[index * 2], index * 2)?;
        let low = decode_nibble(bytes[(index * 2) + 1], (index * 2) + 1)?;
        out[index] = (high << 4) | low;
    }

    Ok(needed)
}

pub fn decode_fixed_lower_hex<const N: usize>(input: &str) -> Result<[u8; N], NostrError> {
    let expected = N * 2;
    if input.len() != expected {
        return Err(NostrError::HexLength {
            expected,
            actual: input.len(),
        });
    }

    let mut out = [0; N];
    decode_lower_hex(input, &mut out)?;
    Ok(out)
}

fn decode_nibble(byte: u8, index: usize) -> Result<u8, NostrError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(NostrError::NonCanonicalHex { index, byte }),
        _ => Err(NostrError::InvalidHexChar { index, byte }),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_fixed_lower_hex, decode_lower_hex, encode_lower_hex};
    use crate::NostrError;

    #[test]
    fn lower_hex_roundtrips_without_allocation() -> Result<(), NostrError> {
        let bytes = [0x00, 0x01, 0x0f, 0x10, 0xab, 0xff];
        let mut encoded = [0; 12];
        let encoded = encode_lower_hex(&bytes, &mut encoded)?;
        assert_eq!(encoded, "00010f10abff");

        let mut decoded = [0; 6];
        let len = decode_lower_hex(encoded, &mut decoded)?;
        assert_eq!(len, bytes.len());
        assert_eq!(decoded, bytes);
        Ok(())
    }

    #[test]
    fn lower_hex_rejects_uppercase_whitespace_odd_and_invalid_input() {
        assert!(matches!(
            decode_fixed_lower_hex::<1>("0A"),
            Err(NostrError::NonCanonicalHex {
                index: 1,
                byte: b'A'
            })
        ));
        assert!(matches!(
            decode_fixed_lower_hex::<1>("0 "),
            Err(NostrError::InvalidHexChar {
                index: 1,
                byte: b' '
            })
        ));
        assert!(matches!(
            decode_lower_hex("abc", &mut [0; 2]),
            Err(NostrError::OddHexLength { len: 3 })
        ));
        assert!(matches!(
            decode_fixed_lower_hex::<1>("0z"),
            Err(NostrError::InvalidHexChar {
                index: 1,
                byte: b'z'
            })
        ));
    }

    #[test]
    fn lower_hex_reports_short_output_and_fixed_length_mismatch() {
        assert!(matches!(
            encode_lower_hex(&[1, 2], &mut [0; 3]),
            Err(NostrError::OutputTooSmall {
                needed: 4,
                available: 3
            })
        ));
        assert!(matches!(
            decode_lower_hex("0001", &mut [0; 1]),
            Err(NostrError::OutputTooSmall {
                needed: 2,
                available: 1
            })
        ));
        assert!(matches!(
            decode_fixed_lower_hex::<2>("00"),
            Err(NostrError::HexLength {
                expected: 4,
                actual: 2
            })
        ));
    }
}
