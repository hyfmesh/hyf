use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{LinkClass, LinkDriver, LinkFrameRef};
use hyf_link_kiss::{
    KISS_CMD_DATA, KISS_FEND, KISS_FESC, KISS_TFEND, KISS_TFESC, KissDecoder, KissFrameRef,
};
use hyf_link_rnode::{RNodeState, parse_command_frame};
use hyf_link_rns::{RnsWrapParams, unwrap_rns_packet, validate_rns_packet, wrap_rns_packet};
use hyf_wire::{decode_envelope, encode_envelope};

use crate::{RNodeDataMode, RNodeSerialConfig, RNodeSerialError, RNodeSerialEvent, SerialIo};

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
        let payload = self.payload_for_send(bytes)?;
        if payload.len() > self.config.mtu {
            return Err(RNodeSerialError::FrameTooLarge {
                actual: payload.len(),
                mtu: self.config.mtu,
            });
        }
        if !self.state.can_transmit() {
            return Err(RNodeSerialError::FlowControlBlocked);
        }

        write_kiss_frame(&mut self.io, KISS_CMD_DATA, payload)?;
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

    pub fn poll_gateway_frame<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, RNodeSerialError> {
        if self.config.data_mode == RNodeDataMode::RawRnsPacket {
            return Err(RNodeSerialError::RnsWrapParamsRequired);
        }
        self.poll_hyf_gateway_frame(output)
    }

    pub fn poll_gateway_frame_with_rns_params<'a>(
        &mut self,
        output: &'a mut [u8],
        params: RnsWrapParams,
    ) -> Result<Option<LinkFrameRef<'a>>, RNodeSerialError> {
        if self.config.data_mode == RNodeDataMode::HyfEnvelope {
            return Err(RNodeSerialError::RnsWrapParamsUnexpected);
        }
        self.poll_raw_rns_gateway_frame(output, params)
    }

    fn payload_for_send<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], RNodeSerialError> {
        match self.config.data_mode {
            RNodeDataMode::HyfEnvelope => {
                decode_envelope(bytes)?;
                Ok(bytes)
            }
            RNodeDataMode::RawRnsPacket => {
                let envelope = decode_envelope(bytes)?;
                Ok(unwrap_rns_packet(envelope)?)
            }
        }
    }

    fn poll_hyf_gateway_frame<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, RNodeSerialError> {
        loop {
            if self.pending.is_none() && !self.read_until_pending()? {
                return Ok(None);
            }
            let Some(pending) = self.pending else {
                return Ok(None);
            };
            if pending.command == KISS_CMD_DATA {
                return self.drain_pending_hyf_frame(output);
            }
            self.drain_pending_command()?;
        }
    }

    fn poll_raw_rns_gateway_frame<'a>(
        &mut self,
        output: &'a mut [u8],
        params: RnsWrapParams,
    ) -> Result<Option<LinkFrameRef<'a>>, RNodeSerialError> {
        loop {
            if self.pending.is_none() && !self.read_until_pending()? {
                return Ok(None);
            }
            let Some(pending) = self.pending else {
                return Ok(None);
            };
            if pending.command == KISS_CMD_DATA {
                return self.drain_pending_raw_rns_frame(output, params);
            }
            self.drain_pending_command()?;
        }
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

    fn drain_pending_hyf_frame<'a>(
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
        if let Err(error) = decode_envelope(&pending.payload[..pending.payload_len]) {
            self.pending = None;
            return Err(RNodeSerialError::HyfWire(error));
        }

        output[..pending.payload_len].copy_from_slice(&pending.payload[..pending.payload_len]);
        self.pending = None;
        Ok(Some(LinkFrameRef::new(
            self.config.link_id,
            pending.received_at_ms,
            &output[..pending.payload_len],
        )))
    }

    fn drain_pending_raw_rns_frame<'a>(
        &mut self,
        output: &'a mut [u8],
        params: RnsWrapParams,
    ) -> Result<Option<LinkFrameRef<'a>>, RNodeSerialError> {
        let Some(pending) = self.pending else {
            return Ok(None);
        };
        if pending.command != KISS_CMD_DATA {
            return Ok(None);
        }
        let raw = &pending.payload[..pending.payload_len];
        let packet = match validate_rns_packet(raw) {
            Ok(packet) => packet,
            Err(error) => {
                self.pending = None;
                return Err(RNodeSerialError::Rns(error));
            }
        };
        let envelope = wrap_rns_packet(packet, params)?;
        let len = encode_envelope(envelope, output)?;
        self.pending = None;
        Ok(Some(LinkFrameRef::new(
            self.config.link_id,
            params.created_at_ms,
            &output[..len],
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
                return self.poll_gateway_frame(output);
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
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_link::{LinkDriver, LinkId};
    use hyf_link_kiss::{KISS_CMD_DATA, encode_command_frame, encode_data_frame};
    use hyf_link_rnode::{
        RNODE_CMD_BANDWIDTH, RNODE_CMD_ERROR, RNODE_CMD_FW_VERSION, RNODE_CMD_READY,
        RNODE_CMD_STAT_RSSI, RNodeConfigReport, RNodeFirmwareVersion, RNodeHardwareError,
        RNodeStat,
    };
    use hyf_link_rns::{RnsWrapParams, validate_rns_packet, wrap_rns_packet};
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope,
        encode_envelope,
    };

    use super::RNodeSerialLink;
    use crate::{FakeSerial, RNodeDataMode, RNodeSerialConfig, RNodeSerialError, RNodeSerialEvent};

    type TestLink = RNodeSerialLink<FakeSerial<512, 512>, 256>;

    const HEADER_1_PACKET: &[u8] = &[
        0x00, 0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x00, b'h', b'e', b'a', b'd', b'e', b'r', b'-', b'o', b'n', b'e',
    ];

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
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 256, RNodeDataMode::HyfEnvelope);

        assert_eq!(
            TestLink::new(config, FakeSerial::new()).map(|_| ()),
            Err(RNodeSerialError::InvalidFrameCapacity {
                mtu: 256,
                capacity: 256,
            })
        );
    }

    #[test]
    fn link_debug_redacts_io() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope);
        let mut io = FakeSerial::<512, 512>::new();
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
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 192, RNodeDataMode::HyfEnvelope)
            .without_flow_control();
        let mut link = TestLink::new(config, FakeSerial::new())?;
        let mut envelope_bytes = [0; 192];
        let envelope_len = encode_envelope(
            sample_envelope(PayloadKind::HyfNativeV0, b"native"),
            &mut envelope_bytes,
        )?;
        let mut expected = [0; 384];
        let expected_len = encode_data_frame(&envelope_bytes[..envelope_len], &mut expected)?;

        link.send_gateway_bytes(&envelope_bytes[..envelope_len], TimestampMs(7))?;

        assert_eq!(link.io().written(), &expected[..expected_len]);
        Ok(())
    }

    #[test]
    fn send_gateway_bytes_enforces_mtu_and_flow_control() -> Result<(), RNodeSerialError> {
        let mut envelope_bytes = [0; 192];
        let envelope_len = encode_envelope(
            sample_envelope(PayloadKind::HyfNativeV0, b"native"),
            &mut envelope_bytes,
        )?;
        let small_mtu = RNodeSerialConfig::new(LinkId([1; 16]), 4, RNodeDataMode::HyfEnvelope);
        let mut small_link = TestLink::new(small_mtu, FakeSerial::new())?;

        assert!(matches!(
            small_link.send_gateway_bytes(&envelope_bytes[..envelope_len], TimestampMs(1)),
            Err(RNodeSerialError::FrameTooLarge { mtu: 4, .. })
        ));
        assert!(matches!(
            small_link.send_gateway_bytes(HEADER_1_PACKET, TimestampMs(1)),
            Err(RNodeSerialError::HyfWire(_))
        ));

        let config = RNodeSerialConfig::new(LinkId([1; 16]), 192, RNodeDataMode::HyfEnvelope);
        let mut link = TestLink::new(config, FakeSerial::new())?;
        assert_eq!(
            link.send_gateway_bytes(&envelope_bytes[..envelope_len], TimestampMs(1)),
            Err(RNodeSerialError::FlowControlBlocked)
        );
        feed_command(&mut link, RNODE_CMD_READY, &[])?;
        assert_eq!(link.poll_event(&mut [0; 8])?, Some(RNodeSerialEvent::Ready));
        link.send_gateway_bytes(&envelope_bytes[..envelope_len], TimestampMs(2))?;
        assert!(!link.state().can_transmit());
        Ok(())
    }

    #[test]
    fn raw_rns_send_unwraps_foreign_packet_envelopes_only() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 192, RNodeDataMode::RawRnsPacket)
            .without_flow_control();
        let mut link = TestLink::new(config, FakeSerial::new())?;
        let envelope = wrap_rns_packet(validate_rns_packet(HEADER_1_PACKET)?, rns_params())?;
        let mut envelope_bytes = [0; 192];
        let envelope_len = encode_envelope(envelope, &mut envelope_bytes)?;
        let mut expected = [0; 128];
        let expected_len = encode_data_frame(HEADER_1_PACKET, &mut expected)?;

        link.send_gateway_bytes(&envelope_bytes[..envelope_len], TimestampMs(2))?;
        assert_eq!(link.io().written(), &expected[..expected_len]);

        let native = sample_envelope(PayloadKind::HyfNativeV0, b"native");
        let native_len = encode_envelope(native, &mut envelope_bytes)?;
        assert_eq!(
            link.send_gateway_bytes(&envelope_bytes[..native_len], TimestampMs(3)),
            Err(RNodeSerialError::Rns(
                hyf_link_rns::HyfLinkRnsError::NotForeignRnsPacket
            ))
        );
        Ok(())
    }

    #[test]
    fn gateway_frame_polling_keeps_hyf_and_raw_rns_modes_explicit() -> Result<(), RNodeSerialError>
    {
        let mut hyf_link = no_flow_control_link()?;
        let mut envelope_bytes = [0; 192];
        let envelope_len = encode_envelope(
            sample_envelope(PayloadKind::HyfNativeV0, b"native"),
            &mut envelope_bytes,
        )?;
        let mut encoded = [0; 384];
        let encoded_len = encode_data_frame(&envelope_bytes[..envelope_len], &mut encoded)?;
        hyf_link.io_mut().push_read_bytes(&encoded[..encoded_len])?;

        let mut output = [0; 256];
        let frame = hyf_link
            .poll_gateway_frame(&mut output)?
            .ok_or(RNodeSerialError::InjectedReadFailure)?;
        assert_eq!(
            decode_envelope(frame.bytes)?.payload_kind,
            PayloadKind::HyfNativeV0
        );
        assert_eq!(
            hyf_link.poll_gateway_frame_with_rns_params(&mut output, rns_params()),
            Err(RNodeSerialError::RnsWrapParamsUnexpected)
        );

        let mut raw_link = raw_rns_link()?;
        let raw_encoded_len = encode_data_frame(HEADER_1_PACKET, &mut encoded)?;
        raw_link
            .io_mut()
            .push_read_bytes(&encoded[..raw_encoded_len])?;
        assert_eq!(
            raw_link.poll_gateway_frame(&mut output),
            Err(RNodeSerialError::RnsWrapParamsRequired)
        );
        let frame = raw_link
            .poll_gateway_frame_with_rns_params(&mut output, rns_params())?
            .ok_or(RNodeSerialError::InjectedReadFailure)?;
        let envelope = decode_envelope(frame.bytes)?;
        assert_eq!(envelope.payload_kind, PayloadKind::ForeignRnsPacket);
        assert_eq!(envelope.payload, HEADER_1_PACKET);
        Ok(())
    }

    #[test]
    fn gateway_frame_polling_rejects_wrong_payload_for_mode() -> Result<(), RNodeSerialError> {
        let mut hyf_link = no_flow_control_link()?;
        let mut encoded = [0; 128];
        let encoded_len = encode_data_frame(HEADER_1_PACKET, &mut encoded)?;
        hyf_link.io_mut().push_read_bytes(&encoded[..encoded_len])?;

        assert!(matches!(
            hyf_link.poll_gateway_frame(&mut [0; 256]),
            Err(RNodeSerialError::HyfWire(_))
        ));

        let mut raw_link = raw_rns_link()?;
        let malformed_len = encode_data_frame(b"bad", &mut encoded)?;
        raw_link
            .io_mut()
            .push_read_bytes(&encoded[..malformed_len])?;
        assert!(matches!(
            raw_link.poll_gateway_frame_with_rns_params(&mut [0; 256], rns_params()),
            Err(RNodeSerialError::Rns(_))
        ));
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
        let mut frame_bytes = [0; 192];
        let frame_len = encode_envelope(
            sample_envelope(PayloadKind::HyfNativeV0, b"rx"),
            &mut frame_bytes,
        )?;
        let mut encoded = [0; 384];
        let len = encode_data_frame(&frame_bytes[..frame_len], &mut encoded)?;
        link.io_mut().push_read_bytes(&encoded[..len])?;

        assert_eq!(link.link_id(), LinkId([1; 16]));
        assert_eq!(link.link_class(), hyf_link::LinkClass::RNodeKiss);
        assert_eq!(link.mtu(), 192);
        assert!(link.is_up());

        let tx_len = encode_envelope(
            sample_envelope(PayloadKind::HyfNativeV0, b"tx"),
            &mut frame_bytes,
        )?;
        let mut expected = [0; 384];
        let expected_len = encode_data_frame(&frame_bytes[..tx_len], &mut expected)?;
        link.send_bytes(&frame_bytes[..tx_len], TimestampMs(9))?;
        assert_eq!(link.io().written(), &expected[..expected_len]);

        let mut output = [0; 256];
        let frame = link
            .poll_frame(&mut output)?
            .ok_or(RNodeSerialError::InjectedReadFailure)?;
        assert_eq!(frame.link_id, LinkId([1; 16]));
        assert_eq!(frame.received_at_ms, TimestampMs(0));
        assert_eq!(decode_envelope(frame.bytes)?.payload, b"rx");
        Ok(())
    }

    fn no_flow_control_link() -> Result<TestLink, RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 192, RNodeDataMode::HyfEnvelope)
            .without_flow_control();
        TestLink::new(config, FakeSerial::new())
    }

    fn raw_rns_link() -> Result<TestLink, RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 192, RNodeDataMode::RawRnsPacket)
            .without_flow_control();
        TestLink::new(config, FakeSerial::new())
    }

    fn feed_command<const FRAME_MAX: usize>(
        link: &mut RNodeSerialLink<FakeSerial<512, 512>, FRAME_MAX>,
        command: u8,
        payload: &[u8],
    ) -> Result<(), RNodeSerialError> {
        let mut encoded = [0; 16];
        let len = encode_command_frame(command, payload, &mut encoded)?;
        link.io_mut().push_read_bytes(&encoded[..len])
    }

    fn sample_envelope<'a>(payload_kind: PayloadKind, payload: &'a [u8]) -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id: MessageId([3; 32]),
            source: NodeId([1; 32]),
            destination: HyfDestination::Node(NodeId([2; 32])),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
            payload_kind,
            payload,
        }
    }

    fn rns_params() -> RnsWrapParams {
        RnsWrapParams {
            source_node: NodeId([1; 32]),
            destination: HyfDestination::Node(NodeId([2; 32])),
            created_at_ms: TimestampMs(10),
            expires_at_ms: TimestampMs(20),
            hop_limit: 4,
            message_id: MessageId([3; 32]),
        }
    }
}
