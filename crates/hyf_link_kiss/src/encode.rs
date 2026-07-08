use crate::{KISS_FEND, KISS_FESC, KISS_TFEND, KISS_TFESC, KissError, constants::KISS_CMD_DATA};

pub fn max_encoded_data_len(payload_len: usize) -> Result<usize, KissError> {
    max_encoded_command_len(payload_len)
}

pub fn max_encoded_command_len(payload_len: usize) -> Result<usize, KissError> {
    payload_len
        .checked_mul(2)
        .and_then(|len| len.checked_add(3))
        .ok_or(KissError::EncodedLengthOverflow)
}

pub fn encode_data_frame(payload: &[u8], out: &mut [u8]) -> Result<usize, KissError> {
    encode_command_frame(KISS_CMD_DATA, payload, out)
}

pub fn encode_command_frame(
    command: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, KissError> {
    let required = encoded_len(payload)?;
    if out.len() < required {
        return Err(KissError::OutputBufferTooShort {
            actual: out.len(),
            required,
        });
    }

    out[0] = KISS_FEND;
    out[1] = command;
    let mut offset = 2;
    for byte in payload {
        match *byte {
            KISS_FEND => {
                out[offset] = KISS_FESC;
                out[offset + 1] = KISS_TFEND;
                offset += 2;
            }
            KISS_FESC => {
                out[offset] = KISS_FESC;
                out[offset + 1] = KISS_TFESC;
                offset += 2;
            }
            byte => {
                out[offset] = byte;
                offset += 1;
            }
        }
    }
    out[offset] = KISS_FEND;
    Ok(offset + 1)
}

fn encoded_len(payload: &[u8]) -> Result<usize, KissError> {
    let mut len = 3usize;
    for byte in payload {
        let increment = if matches!(*byte, KISS_FEND | KISS_FESC) {
            2
        } else {
            1
        };
        len = len
            .checked_add(increment)
            .ok_or(KissError::EncodedLengthOverflow)?;
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::{
        encode_command_frame, encode_data_frame, max_encoded_command_len, max_encoded_data_len,
    };
    use crate::{KISS_CMD_READY, KissError};

    #[test]
    fn max_encoded_lengths_use_worst_case_formula() {
        assert_eq!(max_encoded_data_len(0), Ok(3));
        assert_eq!(max_encoded_data_len(7), Ok(17));
        assert_eq!(max_encoded_command_len(7), Ok(17));
    }

    #[test]
    fn encode_data_frame_without_escaping() -> Result<(), KissError> {
        let mut output = [0; 8];
        let len = encode_data_frame(&[0x01, 0x02, 0x03], &mut output)?;

        assert_eq!(&output[..len], &[0xc0, 0x00, 0x01, 0x02, 0x03, 0xc0]);
        Ok(())
    }

    #[test]
    fn encode_data_frame_escapes_fend_and_fesc() -> Result<(), KissError> {
        let mut output = [0; 8];
        let len = encode_data_frame(&[0xc0, 0xdb, 0x01], &mut output)?;

        assert_eq!(
            &output[..len],
            &[0xc0, 0x00, 0xdb, 0xdc, 0xdb, 0xdd, 0x01, 0xc0]
        );
        Ok(())
    }

    #[test]
    fn encode_command_frame_uses_command_byte() -> Result<(), KissError> {
        let mut output = [0; 3];
        let len = encode_command_frame(KISS_CMD_READY, &[], &mut output)?;

        assert_eq!(&output[..len], &[0xc0, 0x0f, 0xc0]);
        Ok(())
    }

    #[test]
    fn encode_rejects_short_output_without_partial_success() {
        let mut output = [0x55; 4];

        assert_eq!(
            encode_data_frame(&[0xc0], &mut output),
            Err(KissError::OutputBufferTooShort {
                actual: 4,
                required: 5,
            })
        );
        assert_eq!(output, [0x55; 4]);
    }
}
