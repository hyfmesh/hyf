use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{GATEWAY_FRAME_BUFFER_LEN, GatewayRuntime};
use hyf_link_loopback::{LOOPBACK_LEFT_ID, LOOPBACK_RIGHT_ID};
use hyf_link_lxmf::{LxmfWrapParams, unwrap_lxmf_message, wrap_lxmf_message};
use hyf_store::StorePolicy;
use hyf_wire::{HyfDestination, PayloadKind, decode_envelope};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type SmokeRuntime = GatewayRuntime<2, 8, 4, 4>;

const LXMF_FIXED_HEADER_LEN: usize = 96;
const LOCAL_NODE: NodeId = NodeId([0x11; 32]);
const DESTINATION_HASH: [u8; 16] = [0x01; 16];
const SOURCE_HASH: [u8; 16] = [0x02; 16];
const SIGNATURE: [u8; 64] = [0x03; 64];
const PAYLOAD4: &[u8] = &[
    0x94, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xc4, 0x05, b't', b'i', b't', b'l', b'e', 0xc4, 0x05,
    b'h', b'e', b'l', b'l', b'o', 0x80,
];

#[test]
fn gateway_carries_foreign_lxmf_message_bytes_over_loopback() -> TestResult {
    let mut runtime = SmokeRuntime::new(config(512))?;
    let mut raw = [0; LXMF_FIXED_HEADER_LEN + PAYLOAD4.len()];
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    write_lxmf_message(PAYLOAD4, &mut raw);
    let envelope = wrap_lxmf_message(&raw, params())?;

    runtime.submit(envelope)?;

    assert_eq!(runtime.metrics().submitted, 1);
    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_RIGHT_ID)?, 1);

    let frame = runtime
        .receive_loopback_frame(LOOPBACK_RIGHT_ID, &mut frame)?
        .ok_or_else(|| std::io::Error::other("expected queued LXMF loopback frame"))?;
    let decoded = decode_envelope(frame.bytes)?;
    let raw_lxmf = unwrap_lxmf_message(decoded)?;

    assert_eq!(decoded.message_id, MessageId([0x44; 32]));
    assert_eq!(decoded.source, LOCAL_NODE);
    assert_eq!(decoded.payload_kind, PayloadKind::ForeignLxmfMessage);
    assert_eq!(decoded.payload, &raw);
    assert_eq!(raw_lxmf, &raw);
    let HyfDestination::Foreign(endpoint) = decoded.destination else {
        return Err(std::io::Error::other("expected LXMF foreign destination").into());
    };
    assert_eq!(endpoint.network(), hyf_core::ForeignNetworkKind::Lxmf);
    assert_eq!(endpoint.as_bytes(), &DESTINATION_HASH);
    Ok(())
}

fn params() -> LxmfWrapParams {
    LxmfWrapParams {
        source_node: LOCAL_NODE,
        created_at_ms: TimestampMs(1_720_000_000_123),
        expires_at_ms: TimestampMs(1_720_000_100_000),
        hop_limit: 4,
        message_id: MessageId([0x44; 32]),
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

fn write_lxmf_message(payload: &[u8], output: &mut [u8]) {
    output[..16].copy_from_slice(&DESTINATION_HASH);
    output[16..32].copy_from_slice(&SOURCE_HASH);
    output[32..96].copy_from_slice(&SIGNATURE);
    output[96..96 + payload.len()].copy_from_slice(payload);
}
