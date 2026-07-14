use core::fmt;

use crate::{FipsEndpoint, FipsError};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FipsDatagramRecord<const FRAME_MAX: usize> {
    source: FipsEndpoint,
    destination: FipsEndpoint,
    len: usize,
    bytes: [u8; FRAME_MAX],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FipsDatagramRef<'a> {
    pub source: FipsEndpoint,
    pub destination: FipsEndpoint,
    pub bytes: &'a [u8],
}

impl<const FRAME_MAX: usize> FipsDatagramRecord<FRAME_MAX> {
    pub fn new(
        source: FipsEndpoint,
        destination: FipsEndpoint,
        bytes: &[u8],
    ) -> Result<Self, FipsError> {
        source.validate()?;
        destination.validate()?;
        if bytes.len() > FRAME_MAX {
            return Err(FipsError::FrameTooLarge {
                len: bytes.len(),
                mtu: FRAME_MAX,
            });
        }

        let mut stored = [0; FRAME_MAX];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            source,
            destination,
            len: bytes.len(),
            bytes: stored,
        })
    }

    pub const fn source(&self) -> FipsEndpoint {
        self.source
    }

    pub const fn destination(&self) -> FipsEndpoint {
        self.destination
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_ref(&self) -> FipsDatagramRef<'_> {
        FipsDatagramRef {
            source: self.source,
            destination: self.destination,
            bytes: self.bytes(),
        }
    }
}

impl<const FRAME_MAX: usize> fmt::Debug for FipsDatagramRecord<FRAME_MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FipsDatagramRecord")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("bytes", &"<redacted>")
            .field("len", &self.len)
            .finish()
    }
}

impl fmt::Debug for FipsDatagramRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FipsDatagramRef")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::FipsDatagramRecord;
    use crate::{FipsEndpoint, FipsError, FipsPublicKey};

    fn endpoint(seed: u8) -> FipsEndpoint {
        FipsEndpoint::from_public_key(FipsPublicKey::from_bytes([seed; 32]))
    }

    #[test]
    fn datagram_record_owns_payload_bytes() -> Result<(), FipsError> {
        let source = endpoint(1);
        let destination = endpoint(2);
        let input = [b'a', b'b', b'c'];
        let record = FipsDatagramRecord::<8>::new(source, destination, &input)?;

        assert_eq!(record.source(), source);
        assert_eq!(record.destination(), destination);
        assert_eq!(record.len(), 3);
        assert_eq!(record.bytes(), b"abc");
        assert_eq!(record.as_ref().bytes, b"abc");
        Ok(())
    }

    #[test]
    fn datagram_record_rejects_frame_max_overflow() {
        assert_eq!(
            FipsDatagramRecord::<3>::new(endpoint(1), endpoint(2), b"four"),
            Err(FipsError::FrameTooLarge { len: 4, mtu: 3 })
        );
    }

    #[test]
    fn datagram_debug_redacts_payload_bytes() -> Result<(), FipsError> {
        let record = FipsDatagramRecord::<16>::new(endpoint(1), endpoint(2), b"secret")?;
        let debug = format!("{record:?}");

        assert!(debug.contains("FipsDatagramRecord"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115"));
        Ok(())
    }
}
