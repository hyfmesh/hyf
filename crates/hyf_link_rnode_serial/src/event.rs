use core::fmt;

use hyf_link::LinkFrameRef;
use hyf_link_rnode::{
    RNodeConfigReport, RNodeEvent, RNodeFirmwareVersion, RNodeHardwareError, RNodeStat,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RNodeSerialEvent<'a> {
    Frame(LinkFrameRef<'a>),
    Ready,
    Error(RNodeHardwareError),
    FirmwareVersion(RNodeFirmwareVersion),
    ConfigReport(RNodeConfigReport),
    Stat(RNodeStat),
    Unknown { command: u8, payload_len: usize },
}

impl fmt::Debug for RNodeSerialEvent<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(frame) => formatter.debug_tuple("Frame").field(frame).finish(),
            Self::Ready => formatter.write_str("Ready"),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
            Self::FirmwareVersion(version) => formatter
                .debug_tuple("FirmwareVersion")
                .field(version)
                .finish(),
            Self::ConfigReport(report) => {
                formatter.debug_tuple("ConfigReport").field(report).finish()
            }
            Self::Stat(stat) => formatter.debug_tuple("Stat").field(stat).finish(),
            Self::Unknown {
                command,
                payload_len,
            } => formatter
                .debug_struct("Unknown")
                .field("command", command)
                .field("payload", &"<redacted>")
                .field("payload_len", payload_len)
                .finish(),
        }
    }
}

impl<'a> RNodeSerialEvent<'a> {
    pub(crate) fn from_rnode(event: RNodeEvent<'_>) -> Self {
        match event {
            RNodeEvent::Data(_) => Self::Unknown {
                command: 0x00,
                payload_len: 0,
            },
            RNodeEvent::Ready => Self::Ready,
            RNodeEvent::Error(error) => Self::Error(error),
            RNodeEvent::FirmwareVersion(version) => Self::FirmwareVersion(version),
            RNodeEvent::ConfigReport(report) => Self::ConfigReport(report),
            RNodeEvent::Stat(stat) => Self::Stat(stat),
            RNodeEvent::Unknown { command, payload } => Self::Unknown {
                command,
                payload_len: payload.len(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use hyf_link::LinkId;

    use super::RNodeSerialEvent;

    #[test]
    fn event_debug_redacts_payload_bytes() {
        let event = RNodeSerialEvent::Frame(hyf_link::LinkFrameRef::new(
            LinkId([1; 16]),
            hyf_core::TimestampMs(0),
            b"secret",
        ));
        let debug = format!("{event:?}");

        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("bytes_len"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));

        let unknown = RNodeSerialEvent::Unknown {
            command: 0xee,
            payload_len: 6,
        };
        let debug = format!("{unknown:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret"));
    }
}
