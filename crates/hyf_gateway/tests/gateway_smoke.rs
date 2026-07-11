use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{GATEWAY_FRAME_BUFFER_LEN, GatewayError, GatewayRuntime};
use hyf_link_loopback::{LOOPBACK_LEFT_ID, LOOPBACK_RIGHT_ID, LoopbackError};
use hyf_store::{StoreError, StorePolicy};
use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope};

type SmokeRuntime<'a> = GatewayRuntime<'a, 2, 8, 4, 4>;
type QueueLimitedRuntime<'a> = GatewayRuntime<'a, 2, 8, 4, 1>;
type StoreLimitedRuntime<'a> = GatewayRuntime<'a, 2, 8, 1, 4>;

#[test]
fn smoke_local_submit_and_loopback_delivery() -> Result<(), GatewayError> {
    let mut runtime = SmokeRuntime::new(config_for(local(), 512))?;
    let mut peer = SmokeRuntime::new(config_for(remote(), 512))?;
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];

    runtime.submit(sample_envelope(
        MessageId([1; 32]),
        local(),
        100,
        300,
        4,
        b"local",
    ))?;
    assert_eq!(
        runtime.last_delivered().map(|envelope| envelope.message_id),
        Some(MessageId([1; 32]))
    );
    assert_eq!(runtime.metrics().delivered, 1);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_RIGHT_ID)?, 0);

    runtime.submit(sample_envelope(
        MessageId([2; 32]),
        remote(),
        110,
        300,
        4,
        b"remote",
    ))?;
    assert_eq!(runtime.metrics().submitted, 2);
    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(runtime.loopback_queued_len(LOOPBACK_RIGHT_ID)?, 1);
    let received = runtime.receive_loopback_frame(LOOPBACK_RIGHT_ID, &mut frame)?;
    let frame = received.ok_or(GatewayError::UnsupportedLink {
        link_id: LOOPBACK_RIGHT_ID,
    })?;
    peer.process_link_frame(frame)?;

    assert_eq!(
        peer.last_delivered().map(|envelope| envelope.message_id),
        Some(MessageId([2; 32]))
    );
    assert_eq!(peer.metrics().delivered, 1);
    Ok(())
}

#[test]
fn smoke_link_outage_and_store_forward_after_recovery() -> Result<(), GatewayError> {
    let mut runtime = SmokeRuntime::new(config_for(local(), 512))?;
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];

    runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;
    runtime.submit(sample_envelope(
        MessageId([3; 32]),
        remote(),
        100,
        300,
        4,
        b"stored",
    ))?;

    assert_eq!(runtime.stored_len(), 1);
    assert_eq!(runtime.metrics().stored, 1);
    assert_eq!(runtime.metrics().sent, 0);

    runtime.set_link_up(LOOPBACK_LEFT_ID, true)?;
    assert_eq!(runtime.stored_len(), 1);

    runtime.set_link_up(LOOPBACK_RIGHT_ID, true)?;
    assert_eq!(runtime.stored_len(), 0);
    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(
        receive_message_id(&mut runtime, &mut frame)?,
        Some(MessageId([3; 32]))
    );
    Ok(())
}

#[test]
fn smoke_expired_store_record_is_not_forwarded_on_recovery() -> Result<(), GatewayError> {
    let mut runtime = SmokeRuntime::new(config_for(local(), 512))?;
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];

    runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;
    runtime.submit(sample_envelope(
        MessageId([8; 32]),
        remote(),
        100,
        150,
        4,
        b"expired while offline",
    ))?;

    assert_eq!(runtime.stored_len(), 1);
    runtime.tick(TimestampMs(200))?;
    assert_eq!(runtime.stored_len(), 0);
    assert_eq!(runtime.metrics().expired, 1);

    runtime.set_link_up(LOOPBACK_LEFT_ID, true)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, true)?;

    assert_eq!(runtime.metrics().sent, 0);
    assert_eq!(receive_message_id(&mut runtime, &mut frame)?, None);
    Ok(())
}

#[test]
fn smoke_duplicate_expiry_ttl_and_mtu_rejection() -> Result<(), GatewayError> {
    let mut runtime = SmokeRuntime::new(config_for(local(), 512))?;
    let duplicate = sample_envelope(MessageId([4; 32]), remote(), 100, 300, 4, b"duplicate");

    runtime.submit(duplicate)?;
    runtime.submit(duplicate)?;
    assert_eq!(runtime.metrics().sent, 1);
    assert_eq!(runtime.metrics().dropped, 1);

    runtime.submit(sample_envelope(
        MessageId([5; 32]),
        remote(),
        100,
        300,
        0,
        b"ttl",
    ))?;
    runtime.tick(TimestampMs(400))?;
    runtime.submit(sample_envelope(
        MessageId([6; 32]),
        remote(),
        100,
        300,
        4,
        b"expired",
    ))?;
    assert_eq!(runtime.metrics().dropped, 3);

    let mut mtu_runtime = SmokeRuntime::new(config_for(local(), 100))?;
    let oversized = sample_envelope(MessageId([7; 32]), remote(), 100, 300, 4, b"mtu");
    assert_eq!(
        mtu_runtime.submit(oversized),
        Err(GatewayError::Loopback(LoopbackError::FrameTooLarge {
            actual: 121,
            mtu: 100,
        }))
    );
    assert_eq!(
        mtu_runtime.submit(oversized),
        Err(GatewayError::Loopback(LoopbackError::FrameTooLarge {
            actual: 121,
            mtu: 100,
        }))
    );
    assert_eq!(mtu_runtime.metrics().link_errors, 2);
    assert_eq!(mtu_runtime.metrics().dropped, 0);
    assert_eq!(mtu_runtime.metrics().sent, 0);
    Ok(())
}

#[test]
fn smoke_failed_send_does_not_poison_retry() -> Result<(), GatewayError> {
    let mut runtime = QueueLimitedRuntime::new(config_for(local(), 512))?;
    let mut first_frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let mut second_frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let first = sample_envelope(MessageId([10; 32]), remote(), 100, 300, 4, b"first");
    let second = sample_envelope(MessageId([11; 32]), remote(), 100, 300, 4, b"second");

    runtime.submit(first)?;
    assert_eq!(
        runtime.submit(second),
        Err(GatewayError::Loopback(LoopbackError::QueueFull {
            link_id: LOOPBACK_RIGHT_ID,
            capacity: 1,
        }))
    );
    assert_eq!(runtime.metrics().link_errors, 1);
    assert_eq!(runtime.metrics().sent, 1);

    assert_eq!(
        receive_message_id(&mut runtime, &mut first_frame)?,
        Some(MessageId([10; 32]))
    );
    runtime.submit(second)?;
    assert_eq!(
        receive_message_id(&mut runtime, &mut second_frame)?,
        Some(MessageId([11; 32]))
    );
    assert_eq!(runtime.metrics().sent, 2);

    runtime.submit(second)?;
    assert_eq!(runtime.metrics().dropped, 1);
    assert_eq!(runtime.metrics().sent, 2);
    Ok(())
}

#[test]
fn smoke_failed_store_does_not_poison_retry() -> Result<(), GatewayError> {
    let mut config = config_for(local(), 512);
    config.store = StoreConfig::new(1, StorePolicy::new());
    let mut runtime = StoreLimitedRuntime::new(config)?;
    let mut frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let first = sample_envelope(MessageId([12; 32]), remote(), 100, 300, 4, b"stored first");
    let second = sample_envelope(MessageId([13; 32]), remote(), 100, 300, 4, b"stored second");

    runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;
    runtime.submit(first)?;
    assert_eq!(runtime.stored_len(), 1);
    assert_eq!(
        runtime.submit(second),
        Err(GatewayError::Store(StoreError::Full))
    );

    runtime.set_link_up(LOOPBACK_LEFT_ID, true)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, true)?;
    assert_eq!(
        receive_message_id(&mut runtime, &mut frame)?,
        Some(MessageId([12; 32]))
    );

    runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;
    runtime.submit(second)?;

    assert_eq!(runtime.stored_len(), 1);
    assert_eq!(runtime.metrics().stored, 2);
    Ok(())
}

#[test]
fn smoke_store_forward_order_is_deterministic() -> Result<(), GatewayError> {
    let mut runtime = SmokeRuntime::new(config_for(local(), 512))?;
    let mut first_frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let mut second_frame = [0; GATEWAY_FRAME_BUFFER_LEN];
    let mut third_frame = [0; GATEWAY_FRAME_BUFFER_LEN];

    runtime.set_link_up(LOOPBACK_LEFT_ID, false)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, false)?;
    runtime.submit(sample_envelope(
        MessageId([9; 32]),
        remote(),
        100,
        500,
        4,
        b"late",
    ))?;
    runtime.submit(sample_envelope(
        MessageId([1; 32]),
        remote(),
        100,
        300,
        4,
        b"early",
    ))?;

    runtime.set_link_up(LOOPBACK_LEFT_ID, true)?;
    runtime.set_link_up(LOOPBACK_RIGHT_ID, true)?;

    assert_eq!(
        receive_message_id(&mut runtime, &mut first_frame)?,
        Some(MessageId([1; 32]))
    );
    assert_eq!(
        receive_message_id(&mut runtime, &mut second_frame)?,
        Some(MessageId([9; 32]))
    );
    assert_eq!(receive_message_id(&mut runtime, &mut third_frame)?, None);
    Ok(())
}

fn receive_message_id<const STORE_CAPACITY: usize, const LOOPBACK_QUEUE: usize>(
    runtime: &mut GatewayRuntime<'_, 2, 8, STORE_CAPACITY, LOOPBACK_QUEUE>,
    output: &mut [u8],
) -> Result<Option<MessageId>, GatewayError> {
    let Some(frame) = runtime.receive_loopback_frame(LOOPBACK_RIGHT_ID, output)? else {
        return Ok(None);
    };
    Ok(Some(decode_envelope(frame.bytes)?.message_id))
}

fn config_for(node_id: NodeId, mtu: usize) -> GatewayConfig<2> {
    GatewayConfig {
        node_id,
        router: RouterConfig::new(2, 8),
        store: StoreConfig::new(4, StorePolicy::new()),
        links: LinkConfigSet::new([
            Some(LinkConfig::new(LOOPBACK_LEFT_ID, mtu)),
            Some(LinkConfig::new(LOOPBACK_RIGHT_ID, mtu)),
        ]),
        policy: GatewayPolicyConfig::new(),
    }
}

fn sample_envelope<'a>(
    message_id: MessageId,
    destination: NodeId,
    created_at_ms: u64,
    expires_at_ms: u64,
    hop_limit: u8,
    payload: &'a [u8],
) -> HyfEnvelopeRef<'a> {
    HyfEnvelopeRef {
        version: HYF_WIRE_VERSION_0,
        message_id,
        source: local(),
        destination: HyfDestination::Node(destination),
        created_at_ms: TimestampMs(created_at_ms),
        expires_at_ms: TimestampMs(expires_at_ms),
        hop_limit,
        payload_kind: PayloadKind::HyfNativeV0,
        payload,
    }
}

const fn local() -> NodeId {
    NodeId([0x11; 32])
}

const fn remote() -> NodeId {
    NodeId([0x22; 32])
}
