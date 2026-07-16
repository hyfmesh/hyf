use hyf_bridge_core::{
    BridgeEndpointKind, BridgeEndpointRef, BridgeMessageRef, BridgePayloadKind, BridgeWrapParams,
    HYF_BRIDGE_MESSAGE_VERSION_0, decode_bridge_message, encode_bridge_message,
    unwrap_bridge_message, wrap_bridge_message,
};
use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, NodeId, TimestampMs};
use hyf_gateway::{GATEWAY_FRAME_BUFFER_LEN, GatewayError, GatewayRuntime};
use hyf_link_loopback::{LOOPBACK_LEFT_ID, LOOPBACK_RIGHT_ID};
use hyf_store::StorePolicy;
use hyf_wire::{HyfDestination, decode_envelope};

type BridgeRuntime = GatewayRuntime<2, 8, 4, 4>;

#[test]
fn bridge_room_submit_delivers_locally_and_fans_out_to_links()
-> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = BridgeRuntime::new(config_for(local()))?;
    let mut raw = [0; 256];
    let bridge_len = encode_bridge_message(sample_bridge_message(), &mut raw)?;
    let envelope = wrap_bridge_message(
        &raw[..bridge_len],
        BridgeWrapParams {
            source_node: local(),
            created_at_ms: TimestampMs(1000),
            expires_at_ms: TimestampMs(2000),
            hop_limit: 4,
        },
    )?;

    runtime.submit(envelope)?;

    assert_eq!(runtime.metrics().delivered, 1);
    assert_eq!(runtime.metrics().sent, 2);
    assert_eq!(runtime.last_delivered_message_id(), Some(message_id()));
    assert_eq!(runtime.last_delivered_payload_len(), bridge_len);
    assert_loopback_bridge_frame(&mut runtime, LOOPBACK_LEFT_ID)?;
    assert_loopback_bridge_frame(&mut runtime, LOOPBACK_RIGHT_ID)?;
    Ok(())
}

fn assert_loopback_bridge_frame(
    runtime: &mut BridgeRuntime,
    link_id: hyf_link::LinkId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let received = runtime.receive_loopback_frame(link_id, &mut frame)?;
    let frame = received.ok_or(GatewayError::UnsupportedLink { link_id })?;
    let envelope = decode_envelope(frame.bytes)?;
    let raw = unwrap_bridge_message(envelope)?;
    let bridge_message = decode_bridge_message(raw)?;

    assert_eq!(envelope.message_id, message_id());
    assert_eq!(envelope.destination, HyfDestination::Community(room_id()));
    assert_eq!(bridge_message.payload, sample_raw_bridge_payload());
    Ok(())
}

fn sample_bridge_message() -> BridgeMessageRef<'static> {
    BridgeMessageRef {
        version: HYF_BRIDGE_MESSAGE_VERSION_0,
        room_id: room_id(),
        message_id: message_id(),
        author: BridgeEndpointRef {
            kind: BridgeEndpointKind::Foreign(ForeignNetworkKind::BitChat),
            id: b"bchat001",
        },
        created_at_ms: TimestampMs(1000),
        payload_kind: BridgePayloadKind::TextUtf8,
        payload: sample_raw_bridge_payload(),
    }
}

fn config_for(node_id: NodeId) -> GatewayConfig<2> {
    let mut local_communities = [None; hyf_router::ROUTER_LOCAL_COMMUNITY_CAPACITY];
    local_communities[0] = Some(room_id());
    GatewayConfig {
        node_id,
        router: RouterConfig::new(2, 8),
        store: StoreConfig::new(4, StorePolicy::new()),
        links: LinkConfigSet::new([
            Some(LinkConfig::new(LOOPBACK_LEFT_ID, 512)),
            Some(LinkConfig::new(LOOPBACK_RIGHT_ID, 512)),
        ]),
        policy: GatewayPolicyConfig::with_local_communities(local_communities),
    }
}

const fn local() -> NodeId {
    NodeId([0x11; 32])
}

const fn room_id() -> CommunityId {
    CommunityId([0x44; 16])
}

const fn message_id() -> MessageId {
    MessageId([0x55; 32])
}

const fn sample_raw_bridge_payload() -> &'static [u8] {
    b"bridge-room hello"
}
