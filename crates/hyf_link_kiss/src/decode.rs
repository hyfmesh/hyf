use crate::{KISS_FEND, KISS_FESC, KISS_TFEND, KISS_TFESC, KissError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KissFrameRef<'a> {
    command: u8,
    payload: &'a [u8],
}

impl<'a> KissFrameRef<'a> {
    pub const fn new(command: u8, payload: &'a [u8]) -> Self {
        Self { command, payload }
    }

    pub fn command(&self) -> u8 {
        self.command
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KissDecoder<const N: usize> {
    buffer: [u8; N],
    len: usize,
    in_frame: bool,
    escape_pending: bool,
}

impl<const N: usize> KissDecoder<N> {
    pub fn new() -> Self {
        Self {
            buffer: [0; N],
            len: 0,
            in_frame: false,
            escape_pending: false,
        }
    }

    pub fn push_bytes<F>(&mut self, input: &[u8], mut on_frame: F) -> Result<(), KissError>
    where
        F: FnMut(KissFrameRef<'_>) -> Result<(), KissError>,
    {
        for byte in input {
            self.push_byte(*byte, &mut on_frame)?;
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.len = 0;
        self.in_frame = false;
        self.escape_pending = false;
    }

    fn push_byte<F>(&mut self, byte: u8, on_frame: &mut F) -> Result<(), KissError>
    where
        F: FnMut(KissFrameRef<'_>) -> Result<(), KissError>,
    {
        if byte == KISS_FEND {
            if self.in_frame {
                self.finish_frame(on_frame)?;
            }
            self.in_frame = true;
            self.escape_pending = false;
            return Ok(());
        }

        if !self.in_frame {
            return Ok(());
        }

        if self.escape_pending {
            self.escape_pending = false;
            return match byte {
                KISS_TFEND => self.push_decoded_byte(KISS_FEND),
                KISS_TFESC => self.push_decoded_byte(KISS_FESC),
                byte => {
                    self.reset();
                    Err(KissError::MalformedEscape { byte })
                }
            };
        }

        if byte == KISS_FESC {
            self.escape_pending = true;
            return Ok(());
        }

        self.push_decoded_byte(byte)
    }

    fn push_decoded_byte(&mut self, byte: u8) -> Result<(), KissError> {
        if self.len == N {
            let error = KissError::FrameTooLarge {
                actual: self.len + 1,
                maximum: N,
            };
            self.reset();
            return Err(error);
        }

        self.buffer[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    fn finish_frame<F>(&mut self, on_frame: &mut F) -> Result<(), KissError>
    where
        F: FnMut(KissFrameRef<'_>) -> Result<(), KissError>,
    {
        if self.len == 0 {
            return Ok(());
        }

        let frame = KissFrameRef {
            command: self.buffer[0],
            payload: &self.buffer[1..self.len],
        };
        let result = on_frame(frame);
        self.len = 0;
        self.escape_pending = false;
        result
    }
}

impl<const N: usize> Default for KissDecoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::KissDecoder;
    use crate::{KISS_CMD_READY, KissError};

    #[test]
    fn decoder_ignores_bytes_before_first_fend() -> Result<(), KissError> {
        let frames = collect_frames::<16>(&[&[0x01, 0x02, 0xc0, 0x00, 0x03, 0xc0]])?;

        assert_eq!(frames, vec![(0x00, vec![0x03])]);
        Ok(())
    }

    #[test]
    fn decoder_decodes_single_frame() -> Result<(), KissError> {
        let frames = collect_frames::<16>(&[&[0xc0, 0x00, 0x01, 0x02, 0xc0]])?;

        assert_eq!(frames, vec![(0x00, vec![0x01, 0x02])]);
        Ok(())
    }

    #[test]
    fn decoder_decodes_multiple_frames_in_one_chunk() -> Result<(), KissError> {
        let frames = collect_frames::<16>(&[&[0xc0, 0x00, 0x01, 0xc0, 0x0f, 0xc0]])?;

        assert_eq!(frames, vec![(0x00, vec![0x01]), (KISS_CMD_READY, vec![])]);
        Ok(())
    }

    #[test]
    fn decoder_handles_partial_frames_and_escapes() -> Result<(), KissError> {
        let frames = collect_frames::<16>(&[&[0xc0, 0x00, 0xdb], &[0xdc, 0xdb], &[0xdd, 0xc0]])?;

        assert_eq!(frames, vec![(0x00, vec![0xc0, 0xdb])]);
        Ok(())
    }

    #[test]
    fn decoder_preserves_trailing_partial_escape() -> Result<(), KissError> {
        let mut frames = Vec::new();
        let mut decoder = KissDecoder::<16>::new();
        decoder.push_bytes(&[0xc0, 0x00, 0xdb], |frame| {
            frames.push((frame.command(), frame.payload().to_vec()));
            Ok(())
        })?;

        assert!(frames.is_empty());

        decoder.push_bytes(&[0xdc, 0xc0], |frame| {
            frames.push((frame.command(), frame.payload().to_vec()));
            Ok(())
        })?;

        assert_eq!(frames, vec![(0x00, vec![0xc0])]);
        Ok(())
    }

    #[test]
    fn decoder_rejects_malformed_escape_and_resets() -> Result<(), KissError> {
        let mut frames = Vec::new();
        let mut decoder = KissDecoder::<16>::new();

        assert_eq!(
            decoder.push_bytes(&[0xc0, 0x00, 0xdb, 0x00], |frame| {
                frames.push((frame.command(), frame.payload().to_vec()));
                Ok(())
            }),
            Err(KissError::MalformedEscape { byte: 0x00 })
        );
        assert!(frames.is_empty());

        decoder.push_bytes(&[0xc0, 0x00, 0x01, 0xc0], |frame| {
            frames.push((frame.command(), frame.payload().to_vec()));
            Ok(())
        })?;

        assert_eq!(frames, vec![(0x00, vec![0x01])]);
        Ok(())
    }

    #[test]
    fn decoder_rejects_oversized_frame_and_resets() -> Result<(), KissError> {
        let mut frames = Vec::new();
        let mut decoder = KissDecoder::<3>::new();

        assert_eq!(
            decoder.push_bytes(&[0xc0, 0x00, 0x01, 0x02, 0x03], |frame| {
                frames.push((frame.command(), frame.payload().to_vec()));
                Ok(())
            }),
            Err(KissError::FrameTooLarge {
                actual: 4,
                maximum: 3,
            })
        );
        assert!(frames.is_empty());

        decoder.push_bytes(&[0xc0, 0x0f, 0xc0], |frame| {
            frames.push((frame.command(), frame.payload().to_vec()));
            Ok(())
        })?;

        assert_eq!(frames, vec![(KISS_CMD_READY, vec![])]);
        Ok(())
    }

    #[test]
    fn decoder_ignores_empty_frames() -> Result<(), KissError> {
        let frames = collect_frames::<16>(&[&[0xc0, 0xc0, 0xc0]])?;

        assert!(frames.is_empty());
        Ok(())
    }

    fn collect_frames<const N: usize>(chunks: &[&[u8]]) -> Result<Vec<(u8, Vec<u8>)>, KissError> {
        let mut frames = Vec::new();
        let mut decoder = KissDecoder::<N>::new();
        for chunk in chunks {
            decoder.push_bytes(chunk, |frame| {
                frames.push((frame.command(), frame.payload().to_vec()));
                Ok(())
            })?;
        }
        Ok(frames)
    }
}
