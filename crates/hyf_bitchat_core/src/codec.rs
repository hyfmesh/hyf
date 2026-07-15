use crate::BitchatError;

pub(crate) struct DecodeCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> DecodeCursor<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    pub(crate) fn read_u8(&mut self, field: &'static str) -> Result<u8, BitchatError> {
        let bytes = self.read_slice(field, 1)?;

        Ok(bytes[0])
    }

    pub(crate) fn read_u16(&mut self, field: &'static str) -> Result<u16, BitchatError> {
        let bytes = self.read_slice(field, 2)?;

        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&mut self, field: &'static str) -> Result<u32, BitchatError> {
        let bytes = self.read_slice(field, 4)?;

        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_u64(&mut self, field: &'static str) -> Result<u64, BitchatError> {
        let bytes = self.read_slice(field, 8)?;

        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(crate) fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], BitchatError> {
        let bytes = self.read_slice(field, N)?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);

        Ok(output)
    }

    pub(crate) fn read_slice(
        &mut self,
        field: &'static str,
        len: usize,
    ) -> Result<&'a [u8], BitchatError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(BitchatError::LengthOverflow)?;

        if end > self.input.len() {
            return Err(BitchatError::MissingField {
                field,
                needed: len,
                remaining: self.remaining(),
            });
        }

        let slice = &self.input[self.position..end];
        self.position = end;

        Ok(slice)
    }

    pub(crate) fn finish(self) -> Result<(), BitchatError> {
        let remaining = self.input.len().saturating_sub(self.position);
        if remaining == 0 {
            Ok(())
        } else {
            Err(BitchatError::TrailingBytes { remaining })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DecodeCursor;
    use crate::BitchatError;

    #[test]
    fn cursor_reads_big_endian_values_and_slices() -> Result<(), BitchatError> {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut cursor = DecodeCursor::new(&bytes);

        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.read_u8("version")?, 0x01);
        assert_eq!(cursor.read_u16("u16")?, 0x0203);
        assert_eq!(cursor.read_u32("u32")?, 0x0405_0607);
        assert_eq!(cursor.read_u64("u64")?, 0x0809_0a0b_0c0d_0e0f);
        assert_eq!(cursor.finish(), Ok(()));

        Ok(())
    }

    #[test]
    fn cursor_reads_arrays_and_borrowed_slices() -> Result<(), BitchatError> {
        let bytes = [1, 2, 3, 4, 5, 6];
        let mut cursor = DecodeCursor::new(&bytes);

        assert_eq!(cursor.read_array::<2>("array")?, [1, 2]);
        assert_eq!(cursor.read_slice("slice", 3)?, &[3, 4, 5]);
        assert_eq!(cursor.remaining(), 1);

        Ok(())
    }

    #[test]
    fn cursor_rejects_missing_fields_and_trailing_bytes() -> Result<(), BitchatError> {
        let bytes = [1, 2, 3];
        let mut cursor = DecodeCursor::new(&bytes);

        assert_eq!(cursor.read_u8("first")?, 1);
        assert_eq!(
            cursor.read_slice("payload", 4),
            Err(BitchatError::MissingField {
                field: "payload",
                needed: 4,
                remaining: 2,
            })
        );
        assert_eq!(
            cursor.finish(),
            Err(BitchatError::TrailingBytes { remaining: 2 })
        );

        Ok(())
    }
}
