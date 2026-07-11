use core::cmp::min;
use core::fmt;

#[cfg(feature = "serialport_runtime")]
use std::io::{Read, Write};

use crate::RNodeSerialError;

pub trait SerialIo {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, RNodeSerialError>;
    fn write_all(&mut self, input: &[u8]) -> Result<(), RNodeSerialError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct FakeSerial<const RX_MAX: usize, const TX_MAX: usize> {
    read_buf: [u8; RX_MAX],
    read_len: usize,
    written: [u8; TX_MAX],
    written_len: usize,
    next_read_error: Option<RNodeSerialError>,
    next_write_error: Option<RNodeSerialError>,
}

impl<const RX_MAX: usize, const TX_MAX: usize> fmt::Debug for FakeSerial<RX_MAX, TX_MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeSerial")
            .field("read_buf", &"<redacted>")
            .field("read_len", &self.read_len)
            .field("written", &"<redacted>")
            .field("written_len", &self.written_len)
            .field("next_read_error", &self.next_read_error)
            .field("next_write_error", &self.next_write_error)
            .finish()
    }
}

impl<const RX_MAX: usize, const TX_MAX: usize> FakeSerial<RX_MAX, TX_MAX> {
    pub const fn new() -> Self {
        Self {
            read_buf: [0; RX_MAX],
            read_len: 0,
            written: [0; TX_MAX],
            written_len: 0,
            next_read_error: None,
            next_write_error: None,
        }
    }

    pub fn with_read_bytes(input: &[u8]) -> Result<Self, RNodeSerialError> {
        let mut serial = Self::new();
        serial.push_read_bytes(input)?;
        Ok(serial)
    }

    pub fn push_read_bytes(&mut self, input: &[u8]) -> Result<(), RNodeSerialError> {
        let required =
            self.read_len
                .checked_add(input.len())
                .ok_or(RNodeSerialError::WriteBufferFull {
                    required: usize::MAX,
                    capacity: RX_MAX,
                })?;
        if required > RX_MAX {
            return Err(RNodeSerialError::WriteBufferFull {
                required,
                capacity: RX_MAX,
            });
        }
        self.read_buf[self.read_len..required].copy_from_slice(input);
        self.read_len = required;
        Ok(())
    }

    pub fn written(&self) -> &[u8] {
        &self.written[..self.written_len]
    }

    pub fn clear_written(&mut self) {
        self.written_len = 0;
    }

    pub fn fail_next_read(&mut self) {
        self.next_read_error = Some(RNodeSerialError::InjectedReadFailure);
    }

    pub fn fail_next_write(&mut self) {
        self.next_write_error = Some(RNodeSerialError::InjectedWriteFailure);
    }
}

impl<const RX_MAX: usize, const TX_MAX: usize> Default for FakeSerial<RX_MAX, TX_MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RX_MAX: usize, const TX_MAX: usize> SerialIo for FakeSerial<RX_MAX, TX_MAX> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, RNodeSerialError> {
        if let Some(error) = self.next_read_error.take() {
            return Err(error);
        }
        if self.read_len == 0 {
            return Ok(0);
        }
        if output.is_empty() {
            return Err(RNodeSerialError::ReadBufferTooSmall {
                actual: 0,
                required: 1,
            });
        }

        let count = min(output.len(), self.read_len);
        output[..count].copy_from_slice(&self.read_buf[..count]);
        let remaining = self.read_len - count;
        for index in 0..remaining {
            self.read_buf[index] = self.read_buf[count + index];
        }
        self.read_len = remaining;
        Ok(count)
    }

    fn write_all(&mut self, input: &[u8]) -> Result<(), RNodeSerialError> {
        if let Some(error) = self.next_write_error.take() {
            return Err(error);
        }
        let required =
            self.written_len
                .checked_add(input.len())
                .ok_or(RNodeSerialError::WriteBufferFull {
                    required: usize::MAX,
                    capacity: TX_MAX,
                })?;
        if required > TX_MAX {
            return Err(RNodeSerialError::WriteBufferFull {
                required,
                capacity: TX_MAX,
            });
        }
        self.written[self.written_len..required].copy_from_slice(input);
        self.written_len = required;
        Ok(())
    }
}

#[cfg(feature = "serialport_runtime")]
pub struct SerialPortIo {
    port: std::boxed::Box<dyn serialport::SerialPort>,
}

#[cfg(feature = "serialport_runtime")]
impl fmt::Debug for SerialPortIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialPortIo")
            .field("port", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "serialport_runtime")]
impl SerialPortIo {
    pub fn open(path: &str, baud_rate: u32, timeout_ms: u64) -> Result<Self, RNodeSerialError> {
        let port = serialport::new(path, baud_rate)
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .open()
            .map_err(|_| RNodeSerialError::SerialOpenFailure)?;
        Ok(Self { port })
    }

    pub fn from_port(port: std::boxed::Box<dyn serialport::SerialPort>) -> Self {
        Self { port }
    }
}

#[cfg(feature = "serialport_runtime")]
impl SerialIo for SerialPortIo {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, RNodeSerialError> {
        match self.port.read(output) {
            Ok(read) => Ok(read),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(0)
            }
            Err(_) => Err(RNodeSerialError::SerialReadFailure),
        }
    }

    fn write_all(&mut self, input: &[u8]) -> Result<(), RNodeSerialError> {
        self.port
            .write_all(input)
            .map_err(|_| RNodeSerialError::SerialWriteFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::{FakeSerial, SerialIo};
    use crate::RNodeSerialError;

    #[test]
    fn fake_serial_reads_chunks_and_empty_reads_as_zero() -> Result<(), RNodeSerialError> {
        let mut serial = FakeSerial::<8, 8>::with_read_bytes(b"abcdef")?;
        let mut first = [0; 2];
        let mut second = [0; 8];

        assert_eq!(serial.read(&mut first)?, 2);
        assert_eq!(&first, b"ab");
        assert_eq!(serial.read(&mut second)?, 4);
        assert_eq!(&second[..4], b"cdef");
        assert_eq!(serial.read(&mut second)?, 0);
        Ok(())
    }

    #[test]
    fn fake_serial_captures_writes_and_can_clear_them() -> Result<(), RNodeSerialError> {
        let mut serial = FakeSerial::<1, 8>::new();

        serial.write_all(b"abc")?;
        serial.write_all(b"def")?;
        assert_eq!(serial.written(), b"abcdef");
        serial.clear_written();
        assert_eq!(serial.written(), b"");
        Ok(())
    }

    #[test]
    fn fake_serial_reports_bounds_and_injected_errors() -> Result<(), RNodeSerialError> {
        let mut serial = FakeSerial::<2, 2>::new();
        let mut empty = [];

        serial.push_read_bytes(b"a")?;
        assert_eq!(
            serial.read(&mut empty),
            Err(RNodeSerialError::ReadBufferTooSmall {
                actual: 0,
                required: 1,
            })
        );
        assert_eq!(
            serial.push_read_bytes(b"bc"),
            Err(RNodeSerialError::WriteBufferFull {
                required: 3,
                capacity: 2,
            })
        );
        assert_eq!(
            serial.write_all(b"abc"),
            Err(RNodeSerialError::WriteBufferFull {
                required: 3,
                capacity: 2,
            })
        );

        serial.fail_next_read();
        assert_eq!(
            serial.read(&mut [0; 1]),
            Err(RNodeSerialError::InjectedReadFailure)
        );
        serial.fail_next_write();
        assert_eq!(
            serial.write_all(b"a"),
            Err(RNodeSerialError::InjectedWriteFailure)
        );
        Ok(())
    }

    #[test]
    fn fake_serial_debug_redacts_buffers() -> Result<(), RNodeSerialError> {
        let mut serial = FakeSerial::<8, 8>::with_read_bytes(b"secret")?;
        serial.write_all(b"payload")?;
        let debug = format!("{serial:?}");

        assert!(debug.contains("FakeSerial"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("payload"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }
}
