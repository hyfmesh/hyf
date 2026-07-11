use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{LinkClass, LinkDriver, LinkFrameRef};
use hyf_link_kiss::{
    KISS_CMD_DATA, KISS_FEND, KISS_FESC, KISS_TFEND, KISS_TFESC, KissDecoder, KissFrameRef,
};
use hyf_link_rnode::{RNodeState, parse_command_frame};

use crate::{RNodeSerialConfig, RNodeSerialError, RNodeSerialEvent, SerialIo};

pub struct RNodeSerialLink<Io, const FRAME_MAX: usize> {
    config: RNodeSerialConfig,
    io: Io,
    state: RNodeState,
    decoder: KissDecoder<FRAME_MAX>,
    pending: Option<PendingFrame<FRAME_MAX>>,
}

impl<Io, const FRAME_MAX: usize> fmt::Debug for RNodeSerialLink<Io, FRAME_MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RNodeSerialLink")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("decoder", &self.decoder)
            .field(
                "pending",
                &self.pending.as_ref().map(PendingFrame::redacted),
            )
            .field("frame_max", &FRAME_MAX)
            .finish_non_exhaustive()
    }
}

impl<Io, const FRAME_MAX: usize> RNodeSerialLink<Io, FRAME_MAX>
where
    Io: SerialIo,
{
    pub fn new(config: RNodeSerialConfig, io: Io) -> Result<Self, RNodeSerialError> {
        config.validate()?;
        let required_capacity =
            config
                .mtu
                .checked_add(1)
                .ok_or(RNodeSerialError::InvalidFrameCapacity {
                    mtu: config.mtu,
                    capacity: FRAME_MAX,
                })?;
        if required_capacity > FRAME_MAX {
            return Err(RNodeSerialError::InvalidFrameCapacity {
                mtu: config.mtu,
                capacity: FRAME_MAX,
            });
        }

        Ok(Self {
            config,
            io,
            state: RNodeState::new(config.flow_control),
            decoder: KissDecoder::new(),
            pending: None,
        })
    }

    pub fn config(&self) -> RNodeSerialConfig {
        self.config
    }

    pub fn state(&self) -> RNodeState {
        self.state
    }

    pub fn io(&self) -> &Io {
        &self.io
    }

    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    pub fn send_gateway_bytes(
        &mut self,
        bytes: &[u8],
        _now_ms: TimestampMs,
    ) -> Result<(), RNodeSerialError> {
        if bytes.len() > self.config.mtu {
            return Err(RNodeSerialError::FrameTooLarge {
                actual: bytes.len(),
                mtu: self.config.mtu,
            });
        }
        if !self.state.can_transmit() {
            return Err(RNodeSerialError::FlowControlBlocked);
        }

        write_kiss_frame(&mut self.io, KISS_CMD_DATA, bytes)?;
        self.state.mark_tx_started();
        Ok(())
    }

    pub fn poll_event<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<RNodeSerialEvent<'a>>, RNodeSerialError> {
        if self.pending.is_none() && !self.read_until_pending()? {
            return Ok(None);
        }
        self.drain_pending(output)
    }

    fn read_until_pending(&mut self) -> Result<bool, RNodeSerialError> {
        let mut byte = [0; 1];
        loop {
            let read = self.io.read(&mut byte)?;
            if read == 0 {
                return Ok(false);
            }
            if read > byte.len() {
                return Err(RNodeSerialError::ReadBufferTooSmall {
                    actual: byte.len(),
                    required: read,
                });
            }

            let mut pending = None;
            self.decoder.push_bytes(&byte[..read], |frame| {
                pending = Some(PendingFrame::try_from_kiss_frame(frame)?);
                Ok(())
            })?;
            if let Some(frame) = pending {
                self.pending = Some(frame);
                return Ok(true);
            }
        }
    }

    fn drain_pending<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<RNodeSerialEvent<'a>>, RNodeSerialError> {
        let Some(pending) = self.pending else {
            return Ok(None);
        };

        if pending.command == KISS_CMD_DATA {
            return self
                .drain_pending_frame(output)
                .map(|frame| frame.map(RNodeSerialEvent::Frame));
        }

        self.drain_pending_command()
    }

    fn drain_pending_frame<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, RNodeSerialError> {
        let Some(pending) = self.pending else {
            return Ok(None);
        };
        if pending.command != KISS_CMD_DATA {
            return Ok(None);
        }
        if output.len() < pending.payload_len {
            return Err(RNodeSerialError::ReadBufferTooSmall {
                actual: output.len(),
                required: pending.payload_len,
            });
        }

        output[..pending.payload_len].copy_from_slice(&pending.payload[..pending.payload_len]);
        self.pending = None;
        Ok(Some(LinkFrameRef::new(
            self.config.link_id,
            pending.received_at_ms,
            &output[..pending.payload_len],
        )))
    }

    fn drain_pending_command<'a>(
        &mut self,
    ) -> Result<Option<RNodeSerialEvent<'a>>, RNodeSerialError> {
        let Some(pending) = self.pending else {
            return Ok(None);
        };
        if pending.command == KISS_CMD_DATA {
            return Ok(None);
        }
        let frame = KissFrameRef::new(pending.command, &pending.payload[..pending.payload_len]);
        let rnode_event = parse_command_frame(frame)?;
        self.state.apply_event(&rnode_event);
        let event = RNodeSerialEvent::from_rnode(rnode_event);
        self.pending = None;
        Ok(Some(event))
    }
}

impl<Io, const FRAME_MAX: usize> LinkDriver for RNodeSerialLink<Io, FRAME_MAX>
where
    Io: SerialIo,
{
    type Error = RNodeSerialError;

    fn link_id(&self) -> hyf_link::LinkId {
        self.config.link_id
    }

    fn link_class(&self) -> LinkClass {
        LinkClass::RNodeKiss
    }

    fn mtu(&self) -> usize {
        self.config.mtu
    }

    fn is_up(&self) -> bool {
        self.state.can_transmit()
    }

    fn send_bytes(&mut self, bytes: &[u8], now_ms: TimestampMs) -> Result<(), Self::Error> {
        self.send_gateway_bytes(bytes, now_ms)
    }

    fn poll_frame<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, Self::Error> {
        loop {
            if self.pending.is_none() && !self.read_until_pending()? {
                return Ok(None);
            }
            let Some(pending) = self.pending else {
                return Ok(None);
            };
            if pending.command == KISS_CMD_DATA {
                return self.drain_pending_frame(output);
            }
            self.drain_pending_command()?;
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PendingFrame<const N: usize> {
    command: u8,
    payload: [u8; N],
    payload_len: usize,
    received_at_ms: TimestampMs,
}

impl<const N: usize> PendingFrame<N> {
    fn try_from_kiss_frame(frame: KissFrameRef<'_>) -> Result<Self, hyf_link_kiss::KissError> {
        let mut payload = [0; N];
        let payload_len = frame.payload().len();
        if payload_len > N {
            return Err(hyf_link_kiss::KissError::FrameTooLarge {
                actual: payload_len,
                maximum: N,
            });
        }
        payload[..payload_len].copy_from_slice(frame.payload());
        Ok(Self {
            command: frame.command(),
            payload,
            payload_len,
            received_at_ms: TimestampMs(0),
        })
    }

    const fn redacted(&self) -> RedactedPendingFrame {
        RedactedPendingFrame {
            command: self.command,
            payload_len: self.payload_len,
            received_at_ms: self.received_at_ms,
        }
    }
}

impl<const N: usize> fmt::Debug for PendingFrame<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RedactedPendingFrame {
    command: u8,
    payload_len: usize,
    received_at_ms: TimestampMs,
}

fn write_kiss_frame<Io: SerialIo>(
    io: &mut Io,
    command: u8,
    payload: &[u8],
) -> Result<(), RNodeSerialError> {
    io.write_all(&[KISS_FEND, command])?;
    for byte in payload {
        match *byte {
            KISS_FEND => io.write_all(&[KISS_FESC, KISS_TFEND])?,
            KISS_FESC => io.write_all(&[KISS_FESC, KISS_TFESC])?,
            byte => io.write_all(&[byte])?,
        }
    }
    io.write_all(&[KISS_FEND])
}

#[cfg(test)]
mod tests {
    use hyf_core::TimestampMs;
    use hyf_link::{LinkDriver, LinkId};
    use hyf_link_kiss::{KISS_CMD_DATA, encode_command_frame, encode_data_frame};
    use hyf_link_rnode::{
        RNODE_CMD_BANDWIDTH, RNODE_CMD_ERROR, RNODE_CMD_FW_VERSION, RNODE_CMD_READY,
        RNODE_CMD_STAT_RSSI, RNodeConfigReport, RNodeFirmwareVersion, RNodeHardwareError,
        RNodeStat,
    };

    use super::RNodeSerialLink;
    use crate::{FakeSerial, RNodeDataMode, RNodeSerialConfig, RNodeSerialError, RNodeSerialEvent};

    type TestLink = RNodeSerialLink<FakeSerial<128, 128>, 16>;

    #[test]
    fn link_constructs_with_config_io_and_state() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope);
        let link = TestLink::new(config, FakeSerial::new())?;

        assert_eq!(link.config(), config);
        assert!(!link.state().can_transmit());
        assert_eq!(link.io().written(), b"");
        Ok(())
    }

    #[test]
    fn link_rejects_mtu_larger_than_frame_capacity() {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 16, RNodeDataMode::HyfEnvelope);

        assert_eq!(
            TestLink::new(config, FakeSerial::new()).map(|_| ()),
            Err(RNodeSerialError::InvalidFrameCapacity {
                mtu: 16,
                capacity: 16,
            })
        );
    }

    #[test]
    fn link_debug_redacts_io() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope);
        let mut io = FakeSerial::<128, 128>::new();
        io.push_read_bytes(b"secret")?;
        let link = TestLink::new(config, io)?;
        let debug = format!("{link:?}");

        assert!(debug.contains("RNodeSerialLink"));
        assert!(debug.contains("frame_max"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }

    #[test]
    fn send_gateway_bytes_writes_kiss_data_frame() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope)
            .without_flow_control();
        let mut link = TestLink::new(config, FakeSerial::new())?;

        link.send_gateway_bytes(&[0x01, 0xc0, 0xdb], TimestampMs(7))?;

        assert_eq!(
            link.io().written(),
            &[0xc0, KISS_CMD_DATA, 0x01, 0xdb, 0xdc, 0xdb, 0xdd, 0xc0]
        );
        Ok(())
    }

    #[test]
    fn send_gateway_bytes_enforces_mtu_and_flow_control() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 3, RNodeDataMode::HyfEnvelope);
        let mut link = TestLink::new(config, FakeSerial::new())?;

        assert_eq!(
            link.send_gateway_bytes(b"abcd", TimestampMs(1)),
            Err(RNodeSerialError::FrameTooLarge { actual: 4, mtu: 3 })
        );
        assert_eq!(
            link.send_gateway_bytes(b"abc", TimestampMs(1)),
            Err(RNodeSerialError::FlowControlBlocked)
        );

        feed_command(&mut link, RNODE_CMD_READY, &[])?;
        assert_eq!(link.poll_event(&mut [0; 8])?, Some(RNodeSerialEvent::Ready));
        link.send_gateway_bytes(b"abc", TimestampMs(2))?;
        assert!(!link.state().can_transmit());
        Ok(())
    }

    #[test]
    fn poll_event_decodes_partial_and_multiple_data_frames() -> Result<(), RNodeSerialError> {
        let mut link = no_flow_control_link()?;
        let mut encoded = [0; 64];
        let first_len = encode_data_frame(b"one", &mut encoded)?;
        let second_len = encode_data_frame(b"two", &mut encoded[first_len..])?;
        link.io_mut()
            .push_read_bytes(&encoded[..first_len + second_len])?;

        let mut output = [0; 8];
        let Some(RNodeSerialEvent::Frame(first)) = link.poll_event(&mut output)? else {
            return Err(RNodeSerialError::InjectedReadFailure);
        };
        assert_eq!(first.bytes, b"one");
        let Some(RNodeSerialEvent::Frame(second)) = link.poll_event(&mut output)? else {
            return Err(RNodeSerialError::InjectedReadFailure);
        };
        assert_eq!(second.bytes, b"two");
        assert_eq!(link.poll_event(&mut output)?, None);
        Ok(())
    }

    #[test]
    fn poll_event_keeps_pending_frame_when_output_is_short() -> Result<(), RNodeSerialError> {
        let mut link = no_flow_control_link()?;
        let mut encoded = [0; 16];
        let len = encode_data_frame(b"four", &mut encoded)?;
        link.io_mut().push_read_bytes(&encoded[..len])?;

        assert_eq!(
            link.poll_event(&mut [0; 2]),
            Err(RNodeSerialError::ReadBufferTooSmall {
                actual: 2,
                required: 4,
            })
        );

        let mut output = [0; 4];
        let Some(RNodeSerialEvent::Frame(frame)) = link.poll_event(&mut output)? else {
            return Err(RNodeSerialError::InjectedReadFailure);
        };
        assert_eq!(frame.bytes, b"four");
        Ok(())
    }

    #[test]
    fn poll_event_reports_malformed_and_oversized_kiss_frames() -> Result<(), RNodeSerialError> {
        let mut malformed = no_flow_control_link()?;
        malformed
            .io_mut()
            .push_read_bytes(&[0xc0, KISS_CMD_DATA, 0xdb, 0x00])?;
        assert_eq!(
            malformed.poll_event(&mut [0; 8]),
            Err(RNodeSerialError::Kiss(
                hyf_link_kiss::KissError::MalformedEscape { byte: 0x00 }
            ))
        );

        let config = RNodeSerialConfig::new(LinkId([1; 16]), 3, RNodeDataMode::HyfEnvelope)
            .without_flow_control();
        let mut oversized =
            RNodeSerialLink::<FakeSerial<128, 128>, 4>::new(config, FakeSerial::new())?;
        oversized
            .io_mut()
            .push_read_bytes(&[0xc0, KISS_CMD_DATA, 1, 2, 3, 4])?;
        assert_eq!(
            oversized.poll_event(&mut [0; 8]),
            Err(RNodeSerialError::Kiss(
                hyf_link_kiss::KissError::FrameTooLarge {
                    actual: 5,
                    maximum: 4,
                }
            ))
        );
        Ok(())
    }

    #[test]
    fn poll_event_parses_rnode_command_frames_and_updates_state() -> Result<(), RNodeSerialError> {
        let mut link = TestLink::new(
            RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope),
            FakeSerial::new(),
        )?;

        feed_command(&mut link, RNODE_CMD_READY, &[])?;
        feed_command(&mut link, RNODE_CMD_FW_VERSION, &[1, 52])?;
        feed_command(&mut link, RNODE_CMD_STAT_RSSI, &[160])?;
        feed_command(&mut link, RNODE_CMD_BANDWIDTH, &125_000u32.to_be_bytes())?;
        feed_command(&mut link, RNODE_CMD_ERROR, &[0x04])?;
        feed_command(&mut link, 0xee, &[1, 2, 3])?;

        let mut output = [0; 8];
        assert_eq!(link.poll_event(&mut output)?, Some(RNodeSerialEvent::Ready));
        assert!(link.state().can_transmit());
        assert_eq!(
            link.poll_event(&mut output)?,
            Some(RNodeSerialEvent::FirmwareVersion(RNodeFirmwareVersion {
                major: 1,
                minor: 52,
                supported: true,
            }))
        );
        assert_eq!(
            link.poll_event(&mut output)?,
            Some(RNodeSerialEvent::Stat(RNodeStat::RssiDbm(3)))
        );
        assert_eq!(
            link.poll_event(&mut output)?,
            Some(RNodeSerialEvent::ConfigReport(
                RNodeConfigReport::BandwidthHz(125_000)
            ))
        );
        assert_eq!(
            link.poll_event(&mut output)?,
            Some(RNodeSerialEvent::Error(RNodeHardwareError::QueueFull))
        );
        assert!(!link.state().can_transmit());
        assert_eq!(
            link.poll_event(&mut output)?,
            Some(RNodeSerialEvent::Unknown {
                command: 0xee,
                payload_len: 3,
            })
        );
        Ok(())
    }

    #[test]
    fn link_driver_metadata_send_and_poll_frame_work() -> Result<(), RNodeSerialError> {
        let mut link = no_flow_control_link()?;
        let mut encoded = [0; 16];
        let len = encode_data_frame(b"rx", &mut encoded)?;
        link.io_mut().push_read_bytes(&encoded[..len])?;

        assert_eq!(link.link_id(), LinkId([1; 16]));
        assert_eq!(link.link_class(), hyf_link::LinkClass::RNodeKiss);
        assert_eq!(link.mtu(), 8);
        assert!(link.is_up());

        link.send_bytes(b"tx", TimestampMs(9))?;
        assert_eq!(
            link.io().written(),
            &[0xc0, KISS_CMD_DATA, b't', b'x', 0xc0]
        );

        let mut output = [0; 8];
        let frame = link
            .poll_frame(&mut output)?
            .ok_or(RNodeSerialError::InjectedReadFailure)?;
        assert_eq!(frame.link_id, LinkId([1; 16]));
        assert_eq!(frame.received_at_ms, TimestampMs(0));
        assert_eq!(frame.bytes, b"rx");
        Ok(())
    }

    fn no_flow_control_link() -> Result<TestLink, RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope)
            .without_flow_control();
        TestLink::new(config, FakeSerial::new())
    }

    fn feed_command<const FRAME_MAX: usize>(
        link: &mut RNodeSerialLink<FakeSerial<128, 128>, FRAME_MAX>,
        command: u8,
        payload: &[u8],
    ) -> Result<(), RNodeSerialError> {
        let mut encoded = [0; 16];
        let len = encode_command_frame(command, payload, &mut encoded)?;
        link.io_mut().push_read_bytes(&encoded[..len])
    }
}
