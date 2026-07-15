use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{ForeignNetworkKind, MessageId, NodeId, TimestampMs};
use hyf_gateway::{GATEWAY_FRAME_BUFFER_LEN, GatewayRuntime};
use hyf_link::{LinkFrameRef, LinkId};
use hyf_link_bitchat::{BitchatWrapParams, unwrap_bitchat_packet, wrap_bitchat_packet};
use hyf_link_loopback::{LOOPBACK_LEFT_ID, LOOPBACK_RIGHT_ID};
use hyf_store::StorePolicy;
use hyf_wire::{HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope, encode_envelope};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type SmokeRuntime = GatewayRuntime<2, 8, 4, 4>;

const LOCAL_NODE: NodeId = NodeId([0x11; 32]);
const BITCHAT_DESTINATION_BYTES: [u8; 16] = [0xbc; 16];
const OUTBOUND_PACKET_ID: MessageId = MessageId([0x51; 32]);
const INBOUND_PACKET_ID: MessageId = MessageId([0x52; 32]);
const STORE_FORWARD_PACKET_ID: MessageId = MessageId([0x53; 32]);
const HOP_EXHAUSTED_PACKET_ID: MessageId = MessageId([0x54; 32]);

#[test]
fn gateway_carries_foreign_bitchat_packet_bytes_over_loopback() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = raw_bitchat_packet();
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let envelope = wrap_bitchat_packet(&raw, params(OUTBOUND_PACKET_ID, 4))?;

    runtime.submit(envelope)?;

    assert_eq!(runtime.metrics().submitted, 1);
    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_RIGHT_ID)?, 1);
    let decoded = receive_bitchat_envelope_from(&mut runtime, LOOPBACK_RIGHT_ID, &mut frame)?;

    assert_bitchat_envelope(decoded, OUTBOUND_PACKET_ID, &raw, 4)
}

#[test]
fn gateway_forwards_inbound_foreign_bitchat_packet_with_decremented_hop() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = raw_bitchat_packet();
    let mut inbound = [0; GATEWAY_FRAME_BUFFER_LEN];
    let inbound_len = encode_bitchat_envelope(&raw, INBOUND_PACKET_ID, 2, &mut inbound)?;
    let mut forwarded = [0; GATEWAY_FRAME_BUFFER_LEN];

    runtime.ingest_link_frame(LinkFrameRef::new(
        LOOPBACK_LEFT_ID,
        TimestampMs(120),
        &inbound[..inbound_len],
    ))?;

    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_LEFT_ID)?, 1);
    let decoded = receive_bitchat_envelope_from(&mut runtime, LOOPBACK_LEFT_ID, &mut forwarded)?;

    assert_bitchat_envelope(decoded, INBOUND_PACKET_ID, &raw, 1)
}

#[test]
fn gateway_store_forwards_inbound_foreign_bitchat_packet_when_links_recover() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = raw_bitchat_packet();
    let mut inbound = [0; GATEWAY_FRAME_BUFFER_LEN];
    let inbound_len = encode_bitchat_envelope(&raw, STORE_FORWARD_PACKET_ID, 3, &mut inbound)?;
    let mut forwarded = [0; GATEWAY_FRAME_BUFFER_LEN];

    runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;
    runtime.ingest_link_frame(LinkFrameRef::new(
        LOOPBACK_LEFT_ID,
        TimestampMs(120),
        &inbound[..inbound_len],
    ))?;

    assert_eq!(runtime.stored_len(), 1);
    assert_eq!(runtime.metrics().stored, 1);
    assert_eq!(runtime.metrics().sent, 0);

    runtime.set_link_up(LOOPBACK_LEFT_ID, true)?;
    assert_eq!(runtime.stored_len(), 1);

    runtime.set_link_up(LOOPBACK_RIGHT_ID, true)?;
    assert_eq!(runtime.stored_len(), 0);
    assert_eq!(runtime.metrics().sent, 1);
    let decoded = receive_bitchat_envelope_from(&mut runtime, LOOPBACK_RIGHT_ID, &mut forwarded)?;

    assert_bitchat_envelope(decoded, STORE_FORWARD_PACKET_ID, &raw, 2)
}

#[test]
fn gateway_drops_inbound_foreign_bitchat_packet_when_hop_limit_is_exhausted() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = raw_bitchat_packet();
    let mut inbound = [0; GATEWAY_FRAME_BUFFER_LEN];
    let inbound_len = encode_bitchat_envelope(&raw, HOP_EXHAUSTED_PACKET_ID, 1, &mut inbound)?;

    runtime.ingest_link_frame(LinkFrameRef::new(
        LOOPBACK_LEFT_ID,
        TimestampMs(120),
        &inbound[..inbound_len],
    ))?;

    assert_eq!(runtime.metrics().dropped, 1);
    assert_eq!(runtime.metrics().sent, 0);
    assert_eq!(runtime.stored_len(), 0);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_LEFT_ID)?, 0);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_RIGHT_ID)?, 0);
    Ok(())
}

fn assert_bitchat_envelope(
    decoded: HyfEnvelopeRef<'_>,
    expected_message_id: MessageId,
    raw: &[u8],
    expected_hop_limit: u8,
) -> TestResult {
    let raw_bitchat = unwrap_bitchat_packet(decoded)?;

    assert_eq!(decoded.message_id, expected_message_id);
    assert_eq!(decoded.source, LOCAL_NODE);
    assert_eq!(decoded.hop_limit, expected_hop_limit);
    assert_eq!(decoded.payload_kind, PayloadKind::ForeignBitChatPacket);
    assert_eq!(decoded.payload, raw);
    assert_eq!(raw_bitchat, raw);
    let HyfDestination::Foreign(endpoint) = decoded.destination else {
        return Err(std::io::Error::other("expected BitChat foreign destination").into());
    };
    assert_eq!(endpoint.network(), ForeignNetworkKind::BitChat);
    assert_eq!(endpoint.as_bytes(), &BITCHAT_DESTINATION_BYTES);
    Ok(())
}

fn receive_bitchat_envelope_from<'a>(
    runtime: &mut SmokeRuntime,
    link_id: LinkId,
    output: &'a mut [u8; GATEWAY_FRAME_BUFFER_LEN],
) -> TestResult<HyfEnvelopeRef<'a>> {
    let frame = runtime
        .receive_loopback_frame(link_id, output)?
        .ok_or_else(|| std::io::Error::other("expected queued BitChat loopback frame"))?;
    Ok(decode_envelope(frame.bytes)?)
}

fn encode_bitchat_envelope(
    raw: &[u8],
    message_id: MessageId,
    hop_limit: u8,
    output: &mut [u8],
) -> TestResult<usize> {
    let envelope = wrap_bitchat_packet(raw, params(message_id, hop_limit))?;
    Ok(encode_envelope(envelope, output)?)
}

fn params(message_id: MessageId, hop_limit: u8) -> BitchatWrapParams {
    BitchatWrapParams {
        message_id,
        source_node: LOCAL_NODE,
        destination: HyfDestination::Foreign(hyf_core::ForeignEndpointId::from_fixed_16(
            ForeignNetworkKind::BitChat,
            BITCHAT_DESTINATION_BYTES,
        )),
        created_at_ms: TimestampMs(1_720_000_000_123),
        expires_at_ms: TimestampMs(1_720_000_100_000),
        hop_limit,
    }
}

fn config(mtu: usize) -> GatewayConfig<2> {
    GatewayConfig {
        node_id: LOCAL_NODE,
        router: RouterConfig::new(2, 8),
        store: StoreConfig::new(4, StorePolicy::new()),
        links: LinkConfigSet::new([
            Some(LinkConfig::new(LOOPBACK_LEFT_ID, mtu)),
            Some(LinkConfig::new(LOOPBACK_RIGHT_ID, mtu)),
        ]),
        policy: GatewayPolicyConfig::new(),
    }
}

fn raw_bitchat_packet() -> [u8; 29] {
    let mut packet = [0; 29];
    packet[0] = 2;
    packet[1] = 0x31;
    packet[2] = 5;
    packet[3..11].copy_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
    packet[11] = 0;
    packet[12..16].copy_from_slice(&(b"hello".len() as u32).to_be_bytes());
    packet[16..24].copy_from_slice(&[0x11; 8]);
    packet[24..29].copy_from_slice(b"hello");
    packet
}
