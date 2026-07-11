use std::error::Error;
use std::io;

use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{GATEWAY_FRAME_BUFFER_LEN, GatewayCore, GatewayError, GatewayLinkExecutor};
use hyf_link::{LinkDriverError, LinkFrameRef, LinkId};
use hyf_link_kiss::{KISS_CMD_DATA, KissDecoder, KissError, encode_data_frame};
use hyf_link_rnode_serial::{
    FakeSerial, RNodeDataMode, RNodeSerialConfig, RNodeSerialError, RNodeSerialLink,
};
use hyf_link_rns::{RnsWrapParams, validate_rns_packet, wrap_rns_packet};
use hyf_store::StorePolicy;
use hyf_wire::{
    HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope,
    encode_envelope,
};

type TestCore = GatewayCore<2, 8, 4>;
type TestSerialLink = RNodeSerialLink<FakeSerial<8192, 8192>, 4096>;

const LINK_A: LinkId = LinkId([0xa1; 16]);
const LINK_B: LinkId = LinkId([0xb2; 16]);
const LOCAL: NodeId = NodeId([0x11; 32]);
const REMOTE: NodeId = NodeId([0x22; 32]);
const HEADER_1_PACKET: &[u8] = &[
    0x00, 0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20, 0x00, b'h', b'e', b'a', b'd', b'e', b'r', b'-', b'o', b'n', b'e',
];

#[test]
fn smoke_gateway_outbound_native_hyf_over_fake_rnode_serial() -> Result<(), Box<dyn Error>> {
    let mut core = TestCore::new(valid_config())?;
    let mut executor = SerialExecutor::new(RNodeDataMode::HyfEnvelope)?;
    core.handle_link_event(hyf_link::LinkEvent::Up { link_id: LINK_A }, &mut executor)?;

    core.submit(
        sample_envelope(
            MessageId([1; 32]),
            REMOTE,
            PayloadKind::HyfNativeV0,
            b"outbound",
        ),
        &mut executor,
    )?;

    let mut kiss_payload = [0; GATEWAY_FRAME_BUFFER_LEN];
    let payload = first_kiss_payload(executor.link.io().written(), &mut kiss_payload)?;
    let envelope = decode_envelope(payload)?;
    assert_eq!(envelope.message_id, MessageId([1; 32]));
    assert_eq!(envelope.payload_kind, PayloadKind::HyfNativeV0);
    assert_eq!(envelope.payload, b"outbound");
    assert_eq!(core.metrics().sent, 1);
    assert!(core.metrics().bytes_sent > 0);
    Ok(())
}

#[test]
fn smoke_gateway_inbound_native_hyf_delivery_from_fake_rnode_serial() -> Result<(), Box<dyn Error>>
{
    let mut core = TestCore::new(valid_config())?;
    let mut executor = SerialExecutor::new(RNodeDataMode::HyfEnvelope)?;
    core.handle_link_event(hyf_link::LinkEvent::Up { link_id: LINK_A }, &mut executor)?;
    feed_hyf_frame(
        &mut executor.link,
        sample_envelope(
            MessageId([2; 32]),
            LOCAL,
            PayloadKind::HyfNativeV0,
            b"inbound",
        ),
    )?;

    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let inbound = executor
        .link
        .poll_gateway_frame(&mut frame)?
        .ok_or_else(|| missing_frame("inbound native HYF frame"))?;
    core.ingest_link_frame(inbound, &mut executor)?;

    assert_eq!(core.metrics().received, 1);
    assert_eq!(core.metrics().delivered, 1);
    assert_eq!(core.last_delivered_message_id(), Some(MessageId([2; 32])));
    assert_eq!(core.last_delivered_payload_len(), b"inbound".len());
    Ok(())
}

#[test]
fn smoke_gateway_store_forward_flushes_over_fake_rnode_serial() -> Result<(), Box<dyn Error>> {
    let mut core = TestCore::new(valid_config())?;
    let mut executor = SerialExecutor::new(RNodeDataMode::HyfEnvelope)?;
    core.handle_link_event(hyf_link::LinkEvent::Up { link_id: LINK_A }, &mut executor)?;
    core.handle_link_event(hyf_link::LinkEvent::Down { link_id: LINK_A }, &mut executor)?;

    core.submit(
        sample_envelope(
            MessageId([3; 32]),
            REMOTE,
            PayloadKind::HyfNativeV0,
            b"stored",
        ),
        &mut executor,
    )?;
    assert_eq!(core.stored_len(), 1);
    assert_eq!(executor.link.io().written(), b"");

    core.handle_link_event(hyf_link::LinkEvent::Up { link_id: LINK_A }, &mut executor)?;

    assert_eq!(core.stored_len(), 0);
    assert_eq!(core.metrics().stored, 1);
    assert_eq!(core.metrics().sent, 1);
    let mut kiss_payload = [0; GATEWAY_FRAME_BUFFER_LEN];
    let payload = first_kiss_payload(executor.link.io().written(), &mut kiss_payload)?;
    assert_eq!(decode_envelope(payload)?.message_id, MessageId([3; 32]));
    Ok(())
}

#[test]
fn smoke_gateway_malformed_serial_and_gateway_frames_drop_safely() -> Result<(), Box<dyn Error>> {
    let mut core = TestCore::new(valid_config())?;
    let mut executor = SerialExecutor::new(RNodeDataMode::HyfEnvelope)?;
    core.handle_link_event(hyf_link::LinkEvent::Up { link_id: LINK_A }, &mut executor)?;

    executor
        .link
        .io_mut()
        .push_read_bytes(&[0xc0, KISS_CMD_DATA, 0xdb, 0x00])?;
    assert!(matches!(
        executor
            .link
            .poll_gateway_frame(&mut [0; GATEWAY_FRAME_BUFFER_LEN]),
        Err(RNodeSerialError::Kiss(KissError::MalformedEscape {
            byte: 0x00
        }))
    ));

    core.ingest_link_frame(
        LinkFrameRef::new(LINK_A, TimestampMs(10), b"not-a-hyf-envelope"),
        &mut executor,
    )?;
    assert_eq!(core.metrics().received, 1);
    assert_eq!(core.metrics().dropped, 1);
    Ok(())
}

#[test]
fn smoke_gateway_opaque_rns_carriage_over_fake_rnode_serial() -> Result<(), Box<dyn Error>> {
    let mut inbound_core = TestCore::new(valid_config())?;
    let mut inbound = SerialExecutor::new(RNodeDataMode::RawRnsPacket)?;
    inbound_core.handle_link_event(hyf_link::LinkEvent::Up { link_id: LINK_A }, &mut inbound)?;
    let mut encoded_rns = [0; 128];
    let encoded_len = encode_data_frame(HEADER_1_PACKET, &mut encoded_rns)?;
    inbound
        .link
        .io_mut()
        .push_read_bytes(&encoded_rns[..encoded_len])?;

    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let wrapped = inbound
        .link
        .poll_gateway_frame_with_rns_params(&mut frame, rns_params(LOCAL))?
        .ok_or_else(|| missing_frame("wrapped raw RNS frame"))?;
    let envelope = decode_envelope(wrapped.bytes)?;
    assert_eq!(envelope.payload_kind, PayloadKind::ForeignRnsPacket);
    assert_eq!(envelope.payload, HEADER_1_PACKET);
    inbound_core.ingest_link_frame(wrapped, &mut inbound)?;
    assert_eq!(inbound_core.metrics().delivered, 1);
    assert_eq!(
        inbound_core.last_delivered_payload_len(),
        HEADER_1_PACKET.len()
    );

    let mut outbound_core = TestCore::new(valid_config())?;
    let mut outbound = SerialExecutor::new(RNodeDataMode::RawRnsPacket)?;
    outbound_core.handle_link_event(hyf_link::LinkEvent::Up { link_id: LINK_A }, &mut outbound)?;
    let rns_envelope = wrap_rns_packet(validate_rns_packet(HEADER_1_PACKET)?, rns_params(REMOTE))?;
    outbound_core.submit(rns_envelope, &mut outbound)?;

    let mut kiss_payload = [0; GATEWAY_FRAME_BUFFER_LEN];
    let payload = first_kiss_payload(outbound.link.io().written(), &mut kiss_payload)?;
    assert_eq!(payload, HEADER_1_PACKET);
    Ok(())
}

struct SerialExecutor {
    link: TestSerialLink,
}

impl SerialExecutor {
    fn new(mode: RNodeDataMode) -> Result<Self, RNodeSerialError> {
        let config =
            RNodeSerialConfig::new(LINK_A, GATEWAY_FRAME_BUFFER_LEN, mode).without_flow_control();
        Ok(Self {
            link: TestSerialLink::new(config, FakeSerial::new())?,
        })
    }
}

impl GatewayLinkExecutor for SerialExecutor {
    fn send_link_bytes(
        &mut self,
        link_id: LinkId,
        bytes: &[u8],
        now_ms: TimestampMs,
    ) -> Result<(), GatewayError> {
        if link_id != LINK_A {
            return Err(GatewayError::UnsupportedLink { link_id });
        }
        self.link
            .send_gateway_bytes(bytes, now_ms)
            .map_err(|error| GatewayError::Driver {
                link_id,
                kind: error.driver_error_kind(),
            })
    }
}

fn valid_config() -> GatewayConfig<2> {
    GatewayConfig {
        node_id: LOCAL,
        router: RouterConfig::new(2, 8),
        store: StoreConfig::new(4, StorePolicy::new()),
        links: LinkConfigSet::new([
            Some(LinkConfig::new(LINK_A, GATEWAY_FRAME_BUFFER_LEN)),
            Some(LinkConfig::disabled(LINK_B, GATEWAY_FRAME_BUFFER_LEN)),
        ]),
        policy: GatewayPolicyConfig::new(),
    }
}

fn sample_envelope<'a>(
    message_id: MessageId,
    destination: NodeId,
    payload_kind: PayloadKind,
    payload: &'a [u8],
) -> HyfEnvelopeRef<'a> {
    HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id,
        source: LOCAL,
        destination: HyfDestination::Node(destination),
        created_at_ms: TimestampMs(100),
        expires_at_ms: TimestampMs(300),
        hop_limit: 4,
        payload_kind,
        payload,
    }
}

fn feed_hyf_frame(
    link: &mut TestSerialLink,
    envelope: HyfEnvelopeRef<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let frame_len = encode_envelope(envelope, &mut frame)?;
    let mut encoded = [0; GATEWAY_FRAME_BUFFER_LEN * 2 + 3];
    let encoded_len = encode_data_frame(&frame[..frame_len], &mut encoded)?;
    link.io_mut().push_read_bytes(&encoded[..encoded_len])?;
    Ok(())
}

fn first_kiss_payload<'a>(input: &[u8], output: &'a mut [u8]) -> Result<&'a [u8], Box<dyn Error>> {
    let mut decoder = KissDecoder::<4096>::new();
    let mut payload_len = None;
    decoder.push_bytes(input, |frame| {
        if frame.command() != KISS_CMD_DATA {
            return Ok(());
        }
        if frame.payload().len() > output.len() {
            return Err(KissError::FrameTooLarge {
                actual: frame.payload().len(),
                maximum: output.len(),
            });
        }
        output[..frame.payload().len()].copy_from_slice(frame.payload());
        payload_len = Some(frame.payload().len());
        Ok(())
    })?;
    let len = payload_len.ok_or_else(|| missing_frame("KISS data payload"))?;
    Ok(&output[..len])
}

fn rns_params(destination: NodeId) -> RnsWrapParams {
    RnsWrapParams {
        source_node: LOCAL,
        destination: HyfDestination::Node(destination),
        created_at_ms: TimestampMs(100),
        expires_at_ms: TimestampMs(300),
        hop_limit: 4,
        message_id: MessageId([9; 32]),
    }
}

fn missing_frame(context: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, context)
}
