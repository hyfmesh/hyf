use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{GATEWAY_FRAME_BUFFER_LEN, GatewayRuntime};
use hyf_link::{LinkFrameRef, LinkId};
use hyf_link_loopback::{LOOPBACK_LEFT_ID, LOOPBACK_RIGHT_ID};
use hyf_link_lxmf::{LxmfWrapParams, unwrap_lxmf_message, wrap_lxmf_message};
use hyf_store::StorePolicy;
use hyf_wire::{HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope, encode_envelope};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type SmokeRuntime = GatewayRuntime<2, 8, 4, 4>;

const LXMF_FIXED_HEADER_LEN: usize = 96;
const LOCAL_NODE: NodeId = NodeId([0x11; 32]);
const DESTINATION_HASH: [u8; 16] = [0x01; 16];
const SOURCE_HASH: [u8; 16] = [0x02; 16];
const SIGNATURE: [u8; 64] = [0x03; 64];
const PAYLOAD4_MESSAGE_LEN: usize = LXMF_FIXED_HEADER_LEN + PAYLOAD4.len();
const EXPECTED_MESSAGE_ID: MessageId = MessageId([
    0x18, 0x93, 0xa6, 0xcf, 0x0c, 0xca, 0x60, 0x56, 0x8b, 0x39, 0xf7, 0xa7, 0x00, 0xa1, 0x7a, 0x67,
    0xc0, 0x1c, 0x05, 0xb1, 0xc1, 0xea, 0xbc, 0x6b, 0xa5, 0xf5, 0xd9, 0xf6, 0xfa, 0x17, 0xe3, 0xe3,
]);
const PAYLOAD4: &[u8] = &[
    0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4, 0x05,
    b'h', b'e', b'l', b'l', b'o', 0x80,
];

#[test]
fn gateway_carries_foreign_lxmf_message_bytes_over_loopback() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = payload4_lxmf_message();
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let envelope = wrap_lxmf_message(&raw, params(4))?;

    runtime.submit(envelope)?;

    assert_eq!(runtime.metrics().submitted, 1);
    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_RIGHT_ID)?, 1);
    let decoded = receive_lxmf_envelope_from(&mut runtime, LOOPBACK_RIGHT_ID, &mut frame)?;

    assert_lxmf_envelope(decoded, &raw, 4)
}

#[test]
fn gateway_forwards_inbound_foreign_lxmf_message_with_decremented_hop() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = payload4_lxmf_message();
    let mut inbound = [0; GATEWAY_FRAME_BUFFER_LEN];
    let inbound_len = encode_lxmf_envelope(&raw, 2, &mut inbound)?;
    let mut forwarded = [0; GATEWAY_FRAME_BUFFER_LEN];

    runtime.ingest_link_frame(LinkFrameRef::new(
        LOOPBACK_LEFT_ID,
        TimestampMs(120),
        &inbound[..inbound_len],
    ))?;

    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_LEFT_ID)?, 1);
    let decoded = receive_lxmf_envelope_from(&mut runtime, LOOPBACK_LEFT_ID, &mut forwarded)?;

    assert_lxmf_envelope(decoded, &raw, 1)
}

#[test]
fn gateway_store_forwards_inbound_foreign_lxmf_message_when_links_recover() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = payload4_lxmf_message();
    let mut inbound = [0; GATEWAY_FRAME_BUFFER_LEN];
    let inbound_len = encode_lxmf_envelope(&raw, 3, &mut inbound)?;
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
    let decoded = receive_lxmf_envelope_from(&mut runtime, LOOPBACK_RIGHT_ID, &mut forwarded)?;

    assert_lxmf_envelope(decoded, &raw, 2)
}

#[test]
fn gateway_drops_inbound_foreign_lxmf_message_when_hop_limit_is_exhausted() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let raw = payload4_lxmf_message();
    let mut inbound = [0; GATEWAY_FRAME_BUFFER_LEN];
    let inbound_len = encode_lxmf_envelope(&raw, 1, &mut inbound)?;

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

fn assert_lxmf_envelope(
    decoded: HyfEnvelopeRef<'_>,
    raw: &[u8],
    expected_hop_limit: u8,
) -> TestResult {
    let raw_lxmf = unwrap_lxmf_message(decoded)?;

    assert_eq!(decoded.message_id, EXPECTED_MESSAGE_ID);
    assert_eq!(decoded.source, LOCAL_NODE);
    assert_eq!(decoded.hop_limit, expected_hop_limit);
    assert_eq!(decoded.payload_kind, PayloadKind::ForeignLxmfMessage);
    assert_eq!(decoded.payload, raw);
    assert_eq!(raw_lxmf, raw);
    let HyfDestination::Foreign(endpoint) = decoded.destination else {
        return Err(std::io::Error::other("expected LXMF foreign destination").into());
    };
    assert_eq!(endpoint.network(), hyf_core::ForeignNetworkKind::Lxmf);
    assert_eq!(endpoint.as_bytes(), &DESTINATION_HASH);
    Ok(())
}

fn receive_lxmf_envelope_from<'a>(
    runtime: &mut SmokeRuntime,
    link_id: LinkId,
    output: &'a mut [u8; GATEWAY_FRAME_BUFFER_LEN],
) -> TestResult<HyfEnvelopeRef<'a>> {
    let frame = runtime
        .receive_loopback_frame(link_id, output)?
        .ok_or_else(|| std::io::Error::other("expected queued LXMF loopback frame"))?;
    Ok(decode_envelope(frame.bytes)?)
}

fn encode_lxmf_envelope(raw: &[u8], hop_limit: u8, output: &mut [u8]) -> TestResult<usize> {
    let envelope = wrap_lxmf_message(raw, params(hop_limit))?;
    Ok(encode_envelope(envelope, output)?)
}

fn params(hop_limit: u8) -> LxmfWrapParams {
    LxmfWrapParams {
        source_node: LOCAL_NODE,
        created_at_ms: TimestampMs(1_720_000_000_123),
        expires_at_ms: TimestampMs(1_720_000_100_000),
        hop_limit,
    }
}

fn payload4_lxmf_message() -> [u8; PAYLOAD4_MESSAGE_LEN] {
    let mut raw = [0; PAYLOAD4_MESSAGE_LEN];
    write_lxmf_message(PAYLOAD4, &mut raw);
    raw
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

fn write_lxmf_message(payload: &[u8], output: &mut [u8]) {
    output[..16].copy_from_slice(&DESTINATION_HASH);
    output[16..32].copy_from_slice(&SOURCE_HASH);
    output[32..96].copy_from_slice(&SIGNATURE);
    output[96..96 + payload.len()].copy_from_slice(payload);
}
