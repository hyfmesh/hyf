use crate::RnsCryptoError;

pub const PKCS7_BLOCK_LEN: usize = 16;

pub fn pkcs7_padded_len(input_len: usize) -> Result<usize, RnsCryptoError> {
    let padding_len = PKCS7_BLOCK_LEN - (input_len % PKCS7_BLOCK_LEN);
    input_len
        .checked_add(padding_len)
        .ok_or(RnsCryptoError::LengthOverflow)
}

pub fn pkcs7_pad(input: &[u8], out: &mut [u8]) -> Result<usize, RnsCryptoError> {
    let padded_len = pkcs7_padded_len(input.len())?;
    if out.len() < padded_len {
        return Err(RnsCryptoError::OutputBufferTooShort {
            actual: out.len(),
            required: padded_len,
        });
    }

    out[..input.len()].copy_from_slice(input);
    let padding_len = padded_len - input.len();
    for byte in &mut out[input.len()..padded_len] {
        *byte = padding_len as u8;
    }

    Ok(padded_len)
}

pub fn pkcs7_unpad(input: &[u8]) -> Result<&[u8], RnsCryptoError> {
    if input.is_empty() || !input.len().is_multiple_of(PKCS7_BLOCK_LEN) {
        return Err(RnsCryptoError::InvalidPadding);
    }

    let padding_len = usize::from(input[input.len() - 1]);
    if padding_len == 0 || padding_len > PKCS7_BLOCK_LEN || padding_len > input.len() {
        return Err(RnsCryptoError::InvalidPadding);
    }

    let padding_start = input.len() - padding_len;
    if input[padding_start..]
        .iter()
        .any(|byte| usize::from(*byte) != padding_len)
    {
        return Err(RnsCryptoError::InvalidPadding);
    }

    Ok(&input[..padding_start])
}

#[cfg(test)]
mod tests {
    use super::{PKCS7_BLOCK_LEN, pkcs7_pad, pkcs7_padded_len, pkcs7_unpad};
    use crate::RnsCryptoError;

    #[test]
    fn pkcs7_pad_adds_full_block_for_aligned_input() -> Result<(), RnsCryptoError> {
        let input = [0x11; PKCS7_BLOCK_LEN];
        let mut output = [0; PKCS7_BLOCK_LEN * 2];
        let len = pkcs7_pad(&input, &mut output)?;

        assert_eq!(len, PKCS7_BLOCK_LEN * 2);
        assert_eq!(&output[..PKCS7_BLOCK_LEN], &input);
        assert_eq!(&output[PKCS7_BLOCK_LEN..len], &[16; PKCS7_BLOCK_LEN]);
        assert_eq!(pkcs7_unpad(&output[..len])?, input);
        Ok(())
    }

    #[test]
    fn pkcs7_pad_rejects_short_output() {
        let mut output = [0; 1];

        assert_eq!(
            pkcs7_pad(b"hello", &mut output),
            Err(RnsCryptoError::OutputBufferTooShort {
                actual: 1,
                required: 16
            })
        );
    }

    #[test]
    fn pkcs7_unpad_rejects_invalid_padding() {
        assert_eq!(pkcs7_unpad(&[]), Err(RnsCryptoError::InvalidPadding));
        assert_eq!(pkcs7_unpad(&[0; 15]), Err(RnsCryptoError::InvalidPadding));

        let mut bad = [0x04; 16];
        bad[15] = 0;
        assert_eq!(pkcs7_unpad(&bad), Err(RnsCryptoError::InvalidPadding));

        let mut mismatched = [0x04; 16];
        mismatched[14] = 0x03;
        assert_eq!(
            pkcs7_unpad(&mismatched),
            Err(RnsCryptoError::InvalidPadding)
        );
    }

    #[test]
    fn pkcs7_padded_len_detects_overflow() {
        assert_eq!(
            pkcs7_padded_len(usize::MAX),
            Err(RnsCryptoError::LengthOverflow)
        );
    }
}
