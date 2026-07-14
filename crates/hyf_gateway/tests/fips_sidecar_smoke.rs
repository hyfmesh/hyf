use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{FipsGatewayExecutor, GATEWAY_FRAME_BUFFER_LEN, GatewayCore, GatewayError};
use hyf_link::{LinkDriverErrorKind, LinkEvent, LinkId};
use hyf_link_fips::{FakeFipsSidecar, FipsEndpoint, FipsError, FipsPublicKey};
use hyf_store::StorePolicy;
use hyf_wire::{
    HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope,
    encode_envelope,
};

type SmokeCore = GatewayCore<1, 8, 4>;

const LOCAL_NODE: NodeId = NodeId([0x11; 32]);
const REMOTE_NODE: NodeId = NodeId([0x22; 32]);
const FIPS_LINK: LinkId = LinkId([0xf1; 16]);
const PAYLOAD: &[u8] = b"secret-outbound";

#[test]
fn smoke_gateway_outbound_hyf_envelope_enqueues_fake_fips_datagram() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config(2048))?;
    let mut executor = fips_executor::<2, 2, GATEWAY_FRAME_BUFFER_LEN>(2048, true)?;
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];

    executor.set_up(true);
    core.handle_link_event(LinkEvent::Up { link_id: FIPS_LINK }, &mut executor)?;
    core.submit(sample_envelope(), &mut executor)?;

    assert_eq!(core.metrics().sent, 1);
    assert_eq!(executor.sidecar().outbound_len(), 1);
    assert_no_payload_leak(&format!("{core:?}"));
    assert_no_payload_leak(&format!("{executor:?}"));
    assert_no_payload_leak(&format!("{:?}", executor.sidecar()));

    let datagram = executor
        .sidecar_mut()
        .poll_outbound(&mut frame)
        .map_err(map_fips_error)?
        .ok_or_else(protocol_error)?;
    assert_eq!(datagram.source, local_endpoint());
    assert_eq!(datagram.destination, remote_endpoint());

    let decoded = decode_envelope(datagram.bytes)?;
    assert_eq!(decoded.message_id, MessageId([0x44; 32]));
    assert_eq!(decoded.source, LOCAL_NODE);
    assert_eq!(decoded.destination, HyfDestination::Node(REMOTE_NODE));
    assert_eq!(decoded.payload, PAYLOAD);
    Ok(())
}

#[test]
fn smoke_gateway_inbound_fake_fips_datagram_delivers_to_core() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config(2048))?;
    let mut executor = fips_executor::<2, 2, GATEWAY_FRAME_BUFFER_LEN>(2048, true)?;
    let mut encoded = [0; GATEWAY_FRAME_BUFFER_LEN];
    let len = encode_envelope(inbound_envelope(), &mut encoded)?;
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];

    executor.set_up(true);
    executor
        .sidecar_mut()
        .inject_from(remote_endpoint(), &encoded[..len])
        .map_err(map_fips_error)?;
    let frame = executor
        .poll_sidecar_frame(TimestampMs(1_720_000_010_000), &mut frame)?
        .ok_or_else(protocol_error)?;
    core.ingest_link_frame(frame, &mut executor)?;

    assert_eq!(core.metrics().received, 1);
    assert_eq!(core.metrics().delivered, 1);
    assert_eq!(
        core.last_delivered_message_id(),
        Some(MessageId([0x66; 32]))
    );
    assert_eq!(core.last_delivered_payload_len(), b"inbound-secret".len());
    assert_no_payload_leak(&format!("{core:?}"));
    Ok(())
}

#[test]
fn smoke_gateway_store_forward_flushes_over_fake_fips_sidecar() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config(2048))?;
    let mut executor = fips_executor::<2, 2, GATEWAY_FRAME_BUFFER_LEN>(2048, true)?;

    core.submit(sample_envelope(), &mut executor)?;
    assert_eq!(core.stored_len(), 1);
    assert_eq!(executor.sidecar().outbound_len(), 0);

    executor.set_up(true);
    core.handle_link_event(LinkEvent::Up { link_id: FIPS_LINK }, &mut executor)?;

    assert_eq!(core.stored_len(), 0);
    assert_eq!(core.metrics().sent, 1);
    assert_eq!(executor.sidecar().outbound_len(), 1);
    Ok(())
}

#[test]
fn smoke_gateway_store_forward_keeps_pending_on_recoverable_fips_link_down()
-> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config(2048))?;
    let mut executor = fips_executor::<2, 2, GATEWAY_FRAME_BUFFER_LEN>(2048, true)?;

    core.submit(sample_envelope(), &mut executor)?;
    assert_eq!(core.stored_len(), 1);

    core.handle_link_event(LinkEvent::Up { link_id: FIPS_LINK }, &mut executor)?;

    assert_eq!(core.stored_len(), 1);
    assert_eq!(core.metrics().link_errors, 1);
    assert_eq!(executor.sidecar().outbound_len(), 0);
    Ok(())
}

#[test]
fn smoke_gateway_store_forward_keeps_pending_on_fips_queue_full() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config(2048))?;
    let mut executor = fips_executor::<1, 1, GATEWAY_FRAME_BUFFER_LEN>(2048, true)?;

    core.submit(sample_envelope(), &mut executor)?;
    executor.set_up(true);
    executor
        .sidecar_mut()
        .send_to(remote_endpoint(), b"full")
        .map_err(map_fips_error)?;

    core.handle_link_event(LinkEvent::Up { link_id: FIPS_LINK }, &mut executor)?;

    assert_eq!(core.stored_len(), 1);
    assert_eq!(core.metrics().link_errors, 1);
    assert_eq!(executor.sidecar().outbound_len(), 1);
    Ok(())
}

#[test]
fn smoke_gateway_missing_fips_peer_fails_validation() -> Result<(), GatewayError> {
    assert_eq!(
        fips_executor::<0, 2, GATEWAY_FRAME_BUFFER_LEN>(2048, false).err(),
        Some(GatewayError::Driver {
            link_id: FIPS_LINK,
            kind: LinkDriverErrorKind::Protocol,
        })
    );
    Ok(())
}

#[test]
fn smoke_gateway_oversize_frame_failure_is_non_recoverable() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config(2048))?;
    let mut executor = fips_executor::<2, 2, GATEWAY_FRAME_BUFFER_LEN>(64, true)?;

    executor.set_up(true);
    core.handle_link_event(LinkEvent::Up { link_id: FIPS_LINK }, &mut executor)?;

    assert_eq!(
        core.submit(sample_envelope(), &mut executor),
        Err(GatewayError::Driver {
            link_id: FIPS_LINK,
            kind: LinkDriverErrorKind::FrameTooLarge,
        })
    );
    assert_eq!(core.stored_len(), 0);
    assert_eq!(core.metrics().link_errors, 1);
    assert_eq!(executor.sidecar().outbound_len(), 0);
    Ok(())
}

#[test]
fn smoke_gateway_short_output_retries_pending_fips_frame() -> Result<(), GatewayError> {
    let mut executor = fips_executor::<2, 2, GATEWAY_FRAME_BUFFER_LEN>(2048, true)?;
    let mut encoded = [0; GATEWAY_FRAME_BUFFER_LEN];
    let len = encode_envelope(inbound_envelope(), &mut encoded)?;
    let mut short = [0; 1];
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];

    executor.set_up(true);
    executor
        .sidecar_mut()
        .inject_from(remote_endpoint(), &encoded[..len])
        .map_err(map_fips_error)?;

    assert_eq!(
        executor.poll_sidecar_frame(TimestampMs(1), &mut short),
        Err(GatewayError::Driver {
            link_id: FIPS_LINK,
            kind: LinkDriverErrorKind::OutputTooSmall,
        })
    );
    assert_eq!(executor.sidecar().inbound_len(), 1);
    assert!(
        executor
            .poll_sidecar_frame(TimestampMs(2), &mut frame)?
            .is_some()
    );
    assert_eq!(executor.sidecar().inbound_len(), 0);
    Ok(())
}

#[test]
fn smoke_gateway_fips_debug_surfaces_do_not_leak_payloads() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config(2048))?;
    let mut executor = fips_executor::<2, 2, GATEWAY_FRAME_BUFFER_LEN>(2048, true)?;

    executor.set_up(true);
    core.handle_link_event(LinkEvent::Up { link_id: FIPS_LINK }, &mut executor)?;
    core.submit(sample_envelope(), &mut executor)?;

    assert_no_payload_leak(&format!("{:?}", core.metrics()));
    assert_no_payload_leak(&format!("{core:?}"));
    assert_no_payload_leak(&format!("{executor:?}"));
    assert_no_payload_leak(&format!("{:?}", executor.sidecar()));
    Ok(())
}

fn config(mtu: usize) -> GatewayConfig<1> {
    GatewayConfig {
        node_id: LOCAL_NODE,
        router: RouterConfig::new(1, 8),
        store: StoreConfig::new(4, StorePolicy::new()),
        links: LinkConfigSet::new([Some(LinkConfig::new(FIPS_LINK, mtu))]),
        policy: GatewayPolicyConfig::new(),
    }
}

fn sample_envelope<'a>() -> HyfEnvelopeRef<'a> {
    HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id: MessageId([0x44; 32]),
        source: LOCAL_NODE,
        destination: HyfDestination::Node(REMOTE_NODE),
        created_at_ms: TimestampMs(1_720_000_000_123),
        expires_at_ms: TimestampMs(1_720_000_100_000),
        hop_limit: 4,
        payload_kind: PayloadKind::HyfNativeV0,
        payload: PAYLOAD,
    }
}

fn inbound_envelope<'a>() -> HyfEnvelopeRef<'a> {
    HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id: MessageId([0x66; 32]),
        source: REMOTE_NODE,
        destination: HyfDestination::Node(LOCAL_NODE),
        created_at_ms: TimestampMs(1_720_000_010_000),
        expires_at_ms: TimestampMs(1_720_000_100_000),
        hop_limit: 4,
        payload_kind: PayloadKind::HyfNativeV0,
        payload: b"inbound-secret",
    }
}

fn fips_executor<const PEERS: usize, const QUEUE: usize, const FRAME_MAX: usize>(
    mtu: usize,
    register_remote: bool,
) -> Result<FipsGatewayExecutor<FakeFipsSidecar<PEERS, QUEUE, FRAME_MAX>>, GatewayError> {
    let mut sidecar = FakeFipsSidecar::new(local_endpoint(), mtu).map_err(map_fips_error)?;
    if register_remote {
        sidecar
            .register_peer(remote_endpoint())
            .map_err(map_fips_error)?;
    }
    FipsGatewayExecutor::new(FIPS_LINK, local_endpoint(), remote_endpoint(), sidecar, mtu)
}

fn local_endpoint() -> FipsEndpoint {
    FipsEndpoint::from_public_key(FipsPublicKey::from_bytes([1; 32]))
}

fn remote_endpoint() -> FipsEndpoint {
    FipsEndpoint::from_public_key(FipsPublicKey::from_bytes([2; 32]))
}

fn map_fips_error(_error: FipsError) -> GatewayError {
    protocol_error()
}

fn protocol_error() -> GatewayError {
    GatewayError::Driver {
        link_id: FIPS_LINK,
        kind: LinkDriverErrorKind::Protocol,
    }
}

fn assert_no_payload_leak(debug: &str) {
    assert!(!debug.contains("secret-outbound"));
    assert!(!debug.contains("inbound-secret"));
    assert!(!debug.contains("115, 101, 99"));
}
