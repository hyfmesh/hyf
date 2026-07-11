use core::fmt;

use hyf_core::TimestampMs;

use crate::{LinkError, LinkId};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LinkFrameRef<'a> {
    pub link_id: LinkId,
    pub received_at_ms: TimestampMs,
    pub bytes: &'a [u8],
}

impl fmt::Debug for LinkFrameRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinkFrameRef")
            .field("link_id", &self.link_id)
            .field("received_at_ms", &self.received_at_ms)
            .field("bytes", &"<redacted>")
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl<'a> LinkFrameRef<'a> {
    pub const fn new(link_id: LinkId, received_at_ms: TimestampMs, bytes: &'a [u8]) -> Self {
        Self {
            link_id,
            received_at_ms,
            bytes,
        }
    }

    pub fn validate_mtu(&self, mtu: usize) -> Result<(), LinkError> {
        validate_frame_mtu(self.bytes, mtu)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkEvent<'a> {
    Frame(LinkFrameRef<'a>),
    Up { link_id: LinkId },
    Down { link_id: LinkId },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum LinkCommand<'a> {
    Send { link_id: LinkId, bytes: &'a [u8] },
}

impl fmt::Debug for LinkCommand<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send { link_id, bytes } => formatter
                .debug_struct("Send")
                .field("link_id", link_id)
                .field("bytes", &"<redacted>")
                .field("bytes_len", &bytes.len())
                .finish(),
        }
    }
}

impl<'a> LinkCommand<'a> {
    pub const fn send(link_id: LinkId, bytes: &'a [u8]) -> Self {
        Self::Send { link_id, bytes }
    }

    pub fn link_id(&self) -> LinkId {
        match self {
            Self::Send { link_id, .. } => *link_id,
        }
    }

    pub fn bytes(&self) -> &'a [u8] {
        match self {
            Self::Send { bytes, .. } => bytes,
        }
    }

    pub fn validate_mtu(&self, mtu: usize) -> Result<(), LinkError> {
        validate_frame_mtu(self.bytes(), mtu)
    }
}

pub fn validate_frame_mtu(bytes: &[u8], mtu: usize) -> Result<(), LinkError> {
    if bytes.len() > mtu {
        return Err(LinkError::FrameTooLarge {
            actual: bytes.len(),
            mtu,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyf_core::TimestampMs;

    use super::{LinkCommand, LinkEvent, LinkFrameRef, validate_frame_mtu};
    use crate::{LinkError, LinkId};

    #[test]
    fn frame_event_and_command_types_preserve_fields() {
        let link_id = LinkId([3; 16]);
        let frame = LinkFrameRef::new(link_id, TimestampMs(12), b"abc");

        assert_eq!(frame.link_id, link_id);
        assert_eq!(frame.received_at_ms, TimestampMs(12));
        assert_eq!(frame.bytes, b"abc");
        assert_eq!(LinkEvent::Frame(frame), LinkEvent::Frame(frame));

        let command = LinkCommand::send(link_id, b"xyz");
        assert_eq!(command.link_id(), link_id);
        assert_eq!(command.bytes(), b"xyz");
    }

    #[test]
    fn mtu_validation_rejects_oversized_frames() {
        assert_eq!(validate_frame_mtu(b"abcd", 4), Ok(()));
        assert_eq!(
            validate_frame_mtu(b"abcde", 4),
            Err(LinkError::FrameTooLarge { actual: 5, mtu: 4 })
        );
        assert_eq!(
            LinkCommand::send(LinkId([1; 16]), b"abcde").validate_mtu(4),
            Err(LinkError::FrameTooLarge { actual: 5, mtu: 4 })
        );
    }

    #[test]
    fn debug_redacts_frame_and_command_bytes() {
        let frame = LinkFrameRef::new(LinkId([3; 16]), TimestampMs(12), b"secret");
        let command = LinkCommand::send(LinkId([4; 16]), b"secret");
        let frame_debug = format!("{frame:?}");
        let command_debug = format!("{command:?}");

        assert!(frame_debug.contains("<redacted>"));
        assert!(frame_debug.contains("bytes_len"));
        assert!(command_debug.contains("<redacted>"));
        assert!(command_debug.contains("bytes_len"));
        assert!(!frame_debug.contains("secret"));
        assert!(!command_debug.contains("secret"));
        assert!(!frame_debug.contains("115, 101, 99"));
        assert!(!command_debug.contains("115, 101, 99"));
    }
}
