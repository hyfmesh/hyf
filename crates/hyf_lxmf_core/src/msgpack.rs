use crate::{LXMF_MSGPACK_MAX_DEPTH, LXMF_PAYLOAD_MAX_LEN, LxmfError};

const MARKER_NIL: u8 = 0xc0;
const MARKER_FALSE: u8 = 0xc2;
const MARKER_TRUE: u8 = 0xc3;
const MARKER_BIN8: u8 = 0xc4;
const MARKER_BIN16: u8 = 0xc5;
const MARKER_BIN32: u8 = 0xc6;
const MARKER_FLOAT32: u8 = 0xca;
const MARKER_FLOAT64: u8 = 0xcb;
const MARKER_UINT8: u8 = 0xcc;
const MARKER_UINT16: u8 = 0xcd;
const MARKER_UINT32: u8 = 0xce;
const MARKER_UINT64: u8 = 0xcf;
const MARKER_INT8: u8 = 0xd0;
const MARKER_INT16: u8 = 0xd1;
const MARKER_INT32: u8 = 0xd2;
const MARKER_INT64: u8 = 0xd3;
const MARKER_STR8: u8 = 0xd9;
const MARKER_STR16: u8 = 0xda;
const MARKER_STR32: u8 = 0xdb;
const MARKER_ARRAY16: u8 = 0xdc;
const MARKER_ARRAY32: u8 = 0xdd;
const MARKER_MAP16: u8 = 0xde;
const MARKER_MAP32: u8 = 0xdf;

pub(crate) struct MsgpackCursor<'a> {
    input: &'a [u8],
    index: usize,
}

impl<'a> MsgpackCursor<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, index: 0 }
    }

    #[cfg(test)]
    pub(crate) const fn position(&self) -> usize {
        self.index
    }

    #[cfg(test)]
    pub(crate) const fn remaining(&self) -> usize {
        self.input.len() - self.index
    }

    pub(crate) fn finish(&self) -> Result<(), LxmfError> {
        if self.index == self.input.len() {
            Ok(())
        } else {
            Err(LxmfError::MsgpackTrailingBytes)
        }
    }

    pub(crate) fn read_array_len(&mut self) -> Result<usize, LxmfError> {
        let marker = self.read_u8()?;
        match marker {
            0x90..=0x9f => Ok((marker & 0x0f) as usize),
            MARKER_ARRAY16 => Ok(self.read_u16()? as usize),
            MARKER_ARRAY32 => self.read_u32_as_usize(),
            _ => Err(LxmfError::UnsupportedMsgpackType { marker }),
        }
    }

    pub(crate) fn read_float64(&mut self) -> Result<f64, LxmfError> {
        let marker = self.read_u8()?;
        if marker != MARKER_FLOAT64 {
            return Err(LxmfError::UnsupportedMsgpackType { marker });
        }
        Ok(f64::from_bits(self.read_u64()?))
    }

    pub(crate) fn read_bin_or_str_bytes(&mut self) -> Result<&'a [u8], LxmfError> {
        let marker = self.read_u8()?;
        let len = match marker {
            0xa0..=0xbf => (marker & 0x1f) as usize,
            MARKER_BIN8 | MARKER_STR8 => self.read_u8()? as usize,
            MARKER_BIN16 | MARKER_STR16 => self.read_u16()? as usize,
            MARKER_BIN32 | MARKER_STR32 => self.read_u32_as_usize()?,
            _ => return Err(LxmfError::UnsupportedMsgpackType { marker }),
        };
        self.read_slice(len)
    }

    pub(crate) fn read_raw_map(&mut self) -> Result<&'a [u8], LxmfError> {
        let start = self.index;
        let marker = self.peek_u8()?;
        if !is_map_marker(marker) {
            return Err(LxmfError::UnsupportedMsgpackType { marker });
        }
        self.skip_value(1)?;
        Ok(&self.input[start..self.index])
    }

    pub(crate) fn read_raw_value(&mut self) -> Result<&'a [u8], LxmfError> {
        let start = self.index;
        self.skip_value(1)?;
        Ok(&self.input[start..self.index])
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), LxmfError> {
        if depth > LXMF_MSGPACK_MAX_DEPTH {
            return Err(LxmfError::MsgpackDepthExceeded {
                maximum: LXMF_MSGPACK_MAX_DEPTH,
            });
        }

        let marker = self.read_u8()?;
        match marker {
            0x00..=0x7f | 0xe0..=0xff | MARKER_NIL | MARKER_FALSE | MARKER_TRUE => Ok(()),
            0x80..=0x8f => self.skip_map((marker & 0x0f) as usize, depth),
            0x90..=0x9f => self.skip_array((marker & 0x0f) as usize, depth),
            0xa0..=0xbf => self.skip_len((marker & 0x1f) as usize),
            MARKER_BIN8 | MARKER_STR8 => {
                let len = self.read_u8()? as usize;
                self.skip_len(len)
            }
            MARKER_BIN16 | MARKER_STR16 => {
                let len = self.read_u16()? as usize;
                self.skip_len(len)
            }
            MARKER_BIN32 | MARKER_STR32 => {
                let len = self.read_u32_as_usize()?;
                self.skip_len(len)
            }
            MARKER_FLOAT32 | MARKER_UINT32 | MARKER_INT32 => self.skip_len(4),
            MARKER_FLOAT64 | MARKER_UINT64 | MARKER_INT64 => self.skip_len(8),
            MARKER_UINT8 | MARKER_INT8 => self.skip_len(1),
            MARKER_UINT16 | MARKER_INT16 => self.skip_len(2),
            MARKER_ARRAY16 => {
                let len = self.read_u16()? as usize;
                self.skip_array(len, depth)
            }
            MARKER_ARRAY32 => {
                let len = self.read_u32_as_usize()?;
                self.skip_array(len, depth)
            }
            MARKER_MAP16 => {
                let len = self.read_u16()? as usize;
                self.skip_map(len, depth)
            }
            MARKER_MAP32 => {
                let len = self.read_u32_as_usize()?;
                self.skip_map(len, depth)
            }
            _ => Err(LxmfError::UnsupportedMsgpackType { marker }),
        }
    }

    fn skip_array(&mut self, len: usize, depth: usize) -> Result<(), LxmfError> {
        for _ in 0..len {
            self.skip_value(depth + 1)?;
        }
        Ok(())
    }

    fn skip_map(&mut self, len: usize, depth: usize) -> Result<(), LxmfError> {
        for _ in 0..len {
            self.skip_value(depth + 1)?;
            self.skip_value(depth + 1)?;
        }
        Ok(())
    }

    fn skip_len(&mut self, len: usize) -> Result<(), LxmfError> {
        self.read_slice(len).map(|_| ())
    }

    fn read_u8(&mut self) -> Result<u8, LxmfError> {
        Ok(self.read_slice(1)?[0])
    }

    fn peek_u8(&self) -> Result<u8, LxmfError> {
        self.input
            .get(self.index)
            .copied()
            .ok_or(LxmfError::MsgpackTruncated)
    }

    fn read_u16(&mut self) -> Result<u16, LxmfError> {
        let bytes = self.read_slice(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, LxmfError> {
        let bytes = self.read_slice(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u32_as_usize(&mut self) -> Result<usize, LxmfError> {
        let value = self.read_u32()? as u64;
        if value > usize::MAX as u64 {
            return Err(LxmfError::PayloadTooLarge {
                actual: usize::MAX,
                maximum: LXMF_PAYLOAD_MAX_LEN,
            });
        }
        Ok(value as usize)
    }

    fn read_u64(&mut self) -> Result<u64, LxmfError> {
        let bytes = self.read_slice(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], LxmfError> {
        let Some(end) = self.index.checked_add(len) else {
            return Err(LxmfError::PayloadTooLarge {
                actual: len,
                maximum: LXMF_PAYLOAD_MAX_LEN,
            });
        };
        if end > self.input.len() {
            return Err(LxmfError::MsgpackTruncated);
        }
        let slice = &self.input[self.index..end];
        self.index = end;
        Ok(slice)
    }
}

const fn is_map_marker(marker: u8) -> bool {
    matches!(marker, 0x80..=0x8f | MARKER_MAP16 | MARKER_MAP32)
}

#[cfg(test)]
mod tests {
    use super::MsgpackCursor;
    use crate::{LXMF_MSGPACK_MAX_DEPTH, LxmfError};

    #[test]
    fn msgpack_reads_array_lengths() -> Result<(), LxmfError> {
        let mut fixed = MsgpackCursor::new(&[0x94]);
        let mut array16 = MsgpackCursor::new(&[0xdc, 0x00, 0x05]);
        let mut array32 = MsgpackCursor::new(&[0xdd, 0x00, 0x00, 0x00, 0x06]);

        assert_eq!(fixed.read_array_len()?, 4);
        assert_eq!(array16.read_array_len()?, 5);
        assert_eq!(array32.read_array_len()?, 6);
        assert_eq!(fixed.remaining(), 0);
        Ok(())
    }

    #[test]
    fn msgpack_reads_float64() -> Result<(), LxmfError> {
        let mut cursor = MsgpackCursor::new(&[0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]);

        assert_eq!(cursor.read_float64()?, 1.5);
        assert_eq!(cursor.finish(), Ok(()));
        Ok(())
    }

    #[test]
    fn msgpack_rejects_non_float64_timestamp_marker() {
        let mut cursor = MsgpackCursor::new(&[0xca, 0x3f, 0xc0, 0, 0]);

        assert_eq!(
            cursor.read_float64(),
            Err(LxmfError::UnsupportedMsgpackType { marker: 0xca })
        );
    }

    #[test]
    fn msgpack_reads_bin_and_str_as_bytes() -> Result<(), LxmfError> {
        let mut fixed_str = MsgpackCursor::new(&[0xa2, b'o', b'k']);
        let mut bin8 = MsgpackCursor::new(&[0xc4, 0x03, b'b', b'i', b'n']);
        let mut str8 = MsgpackCursor::new(&[0xd9, 0x03, b's', b't', b'r']);

        assert_eq!(fixed_str.read_bin_or_str_bytes()?, b"ok");
        assert_eq!(bin8.read_bin_or_str_bytes()?, b"bin");
        assert_eq!(str8.read_bin_or_str_bytes()?, b"str");
        Ok(())
    }

    #[test]
    fn msgpack_preserves_raw_map_bytes() -> Result<(), LxmfError> {
        let input = [0x81, 0xa1, b'a', 0x92, 0xc2, 0x2a];
        let mut cursor = MsgpackCursor::new(&input);

        assert_eq!(cursor.read_raw_map()?, input);
        assert_eq!(cursor.finish(), Ok(()));
        Ok(())
    }

    #[test]
    fn msgpack_preserves_raw_value_bytes() -> Result<(), LxmfError> {
        let input = [0x92, 0xa1, b'a', 0xcc, 0x09];
        let mut cursor = MsgpackCursor::new(&input);

        assert_eq!(cursor.read_raw_value()?, input);
        assert_eq!(cursor.position(), input.len());
        Ok(())
    }

    #[test]
    fn msgpack_rejects_non_map_raw_map() {
        let mut cursor = MsgpackCursor::new(&[0x90]);

        assert_eq!(
            cursor.read_raw_map(),
            Err(LxmfError::UnsupportedMsgpackType { marker: 0x90 })
        );
    }

    #[test]
    fn msgpack_rejects_truncated_input() {
        let mut cursor = MsgpackCursor::new(&[0xc4, 0x02, b'a']);

        assert_eq!(
            cursor.read_bin_or_str_bytes(),
            Err(LxmfError::MsgpackTruncated)
        );
    }

    #[test]
    fn msgpack_rejects_trailing_bytes() -> Result<(), LxmfError> {
        let mut cursor = MsgpackCursor::new(&[0xa1, b'a', 0x00]);

        assert_eq!(cursor.read_bin_or_str_bytes()?, b"a");
        assert_eq!(cursor.finish(), Err(LxmfError::MsgpackTrailingBytes));
        Ok(())
    }

    #[test]
    fn msgpack_rejects_depth_overflow() {
        let mut input = [0; LXMF_MSGPACK_MAX_DEPTH + 1];
        input.fill(0x91);
        let mut cursor = MsgpackCursor::new(&input);

        assert_eq!(
            cursor.read_raw_value(),
            Err(LxmfError::MsgpackDepthExceeded {
                maximum: LXMF_MSGPACK_MAX_DEPTH,
            })
        );
    }
}
