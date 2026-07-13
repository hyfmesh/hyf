use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{GatewayCore, GatewayError, GatewayLinkExecutor, NostrGatewayExecutor};
use hyf_link::{LinkDriverErrorKind, LinkEvent, LinkId};
use hyf_link_nostr::{
    FakeNostrRelay, FakeNostrRelayOutput, HYF_NOSTR_ENVELOPE_KIND, HYF_NOSTR_MAX_CONTENT_CHARS,
    HyfNostrEventBuffers, NostrError, NostrEvent, NostrFilter, NostrPublicKey, NostrSecretKey,
    NostrSignature, NostrTagRef, sign_hyf_nostr_event,
};
use hyf_store::StorePolicy;
use hyf_wire::{
    HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope,
    encode_envelope,
};

type SmokeCore = GatewayCore<1, 8, 4>;
type SmokeRelay = FakeNostrRelay<'static, 4, 2, 8>;
type FullRelay = FakeNostrRelay<'static, 0, 0, 1>;

const LOCAL_NODE: NodeId = NodeId([0x11; 32]);
const REMOTE_NODE: NodeId = NodeId([0x22; 32]);
const NOSTR_LINK: LinkId = LinkId([0x55; 16]);
const RECIPIENT: NostrPublicKey = NostrPublicKey::from_bytes([0x77; 32]);
const PAYLOAD: &[u8] = b"secret-outbound";

#[test]
fn smoke_gateway_outbound_hyf_envelope_publishes_to_fake_nostr_relay() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config())?;
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        SmokeRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );

    executor.set_up(true);
    core.handle_link_event(
        LinkEvent::Up {
            link_id: NOSTR_LINK,
        },
        &mut executor,
    )?;
    core.submit(sample_envelope(), &mut executor)?;

    assert_eq!(core.metrics().sent, 1);
    assert_eq!(executor.relay().stored_event_count(), 1);
    assert_no_payload_leak(&format!("{:?}", core.metrics()));
    assert_no_payload_leak(&format!("{executor:?}"));
    assert_no_payload_leak(&format!("{:?}", executor.relay().metrics()));

    let kinds = [HYF_NOSTR_ENVELOPE_KIND];
    let filters = [NostrFilter {
        kinds: &kinds,
        ..NostrFilter::empty()
    }];
    if executor.relay_mut().subscribe("smoke", &filters).is_err() {
        return Err(protocol_error());
    }

    let mut frame = [0; 256];
    let frame = match executor.poll_relay_frame(&mut frame)? {
        Some(frame) => frame,
        None => return Err(protocol_error()),
    };
    let decoded = decode_envelope(frame.bytes)?;

    assert_eq!(frame.link_id, NOSTR_LINK);
    assert_eq!(decoded.message_id, MessageId([0x44; 32]));
    assert_eq!(decoded.source, LOCAL_NODE);
    assert_eq!(decoded.destination, HyfDestination::Node(REMOTE_NODE));
    assert_eq!(decoded.payload, PAYLOAD);
    Ok(())
}

#[test]
fn smoke_gateway_inbound_fake_nostr_event_delivers_to_core() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config())?;
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        SmokeRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );
    let mut encoded = [0; 256];
    let len = encode_envelope(inbound_envelope(), &mut encoded)?;
    let kinds = [HYF_NOSTR_ENVELOPE_KIND];
    let filters = [NostrFilter {
        kinds: &kinds,
        ..NostrFilter::empty()
    }];
    let mut frame = [0; 256];

    executor.set_up(true);
    executor.send_link_bytes(NOSTR_LINK, &encoded[..len], TimestampMs(1_720_000_010_000))?;
    if executor.relay_mut().subscribe("inbound", &filters).is_err() {
        return Err(protocol_error());
    }
    let frame = match executor.poll_relay_frame(&mut frame)? {
        Some(frame) => frame,
        None => return Err(protocol_error()),
    };
    core.ingest_link_frame(frame, &mut executor)?;

    assert_eq!(core.metrics().received, 1);
    assert_eq!(core.metrics().delivered, 1);
    assert_eq!(
        core.last_delivered_message_id(),
        Some(MessageId([0x66; 32]))
    );
    assert_eq!(core.last_delivered_payload_len(), b"inbound-secret".len());
    Ok(())
}

#[test]
fn smoke_gateway_rejects_malformed_nostr_before_core_ingest() -> Result<(), GatewayError> {
    let core = SmokeCore::new(config())?;
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        SmokeRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );
    let mut encoded = [0; 256];
    let len = encode_envelope(inbound_envelope(), &mut encoded)?;
    let bad_event = tampered_event(&encoded[..len])?;
    let mut frame = [0; 256];

    executor.set_up(true);
    executor
        .relay_mut()
        .enqueue_output(FakeNostrRelayOutput::Event {
            subscription_id: "bad",
            event: bad_event,
        })
        .map_err(map_nostr_error)?;

    assert_eq!(
        executor.poll_relay_frame(&mut frame),
        Err(GatewayError::Driver {
            link_id: NOSTR_LINK,
            kind: LinkDriverErrorKind::Protocol,
        })
    );
    assert_eq!(core.metrics().received, 0);
    assert_eq!(core.last_delivered_message_id(), None);
    Ok(())
}

#[test]
fn smoke_gateway_store_forward_flushes_over_fake_nostr_relay() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config())?;
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        SmokeRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );

    core.submit(sample_envelope(), &mut executor)?;
    assert_eq!(core.stored_len(), 1);
    assert_eq!(executor.relay().stored_event_count(), 0);

    executor.set_up(true);
    core.handle_link_event(
        LinkEvent::Up {
            link_id: NOSTR_LINK,
        },
        &mut executor,
    )?;

    assert_eq!(core.stored_len(), 0);
    assert_eq!(core.metrics().sent, 1);
    assert_eq!(executor.relay().stored_event_count(), 1);
    Ok(())
}

#[test]
fn smoke_gateway_store_forward_keeps_pending_on_recoverable_nostr_failure()
-> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config())?;
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        FullRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );

    core.submit(sample_envelope(), &mut executor)?;
    assert_eq!(core.stored_len(), 1);

    executor.set_up(true);
    core.handle_link_event(
        LinkEvent::Up {
            link_id: NOSTR_LINK,
        },
        &mut executor,
    )?;

    assert_eq!(core.stored_len(), 1);
    assert_eq!(core.metrics().link_errors, 1);
    assert_eq!(executor.relay().stored_event_count(), 0);
    Ok(())
}

fn config() -> GatewayConfig<1> {
    GatewayConfig {
        node_id: LOCAL_NODE,
        router: RouterConfig::new(1, 8),
        store: StoreConfig::new(4, StorePolicy::new()),
        links: LinkConfigSet::new([Some(LinkConfig::new(NOSTR_LINK, 2048))]),
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

fn fixture_secret() -> NostrSecretKey {
    let mut secret_key = [0; 32];
    secret_key[31] = 3;
    NostrSecretKey::from_bytes(secret_key)
}

fn tampered_event(encoded: &[u8]) -> Result<NostrEvent<'static>, GatewayError> {
    let event = sign_hyf_nostr_event(
        encoded,
        &fixture_secret(),
        RECIPIENT,
        1_720_000_010,
        leaked_event_buffers()?,
    )
    .map_err(map_nostr_error)?;
    let mut signature = *event.sig.as_bytes();
    signature[0] ^= 0x01;
    Ok(NostrEvent {
        sig: NostrSignature::from_bytes(signature),
        ..event
    })
}

fn leaked_event_buffers() -> Result<HyfNostrEventBuffers<'static>, GatewayError> {
    let dummy_values = Box::leak(Box::new(["_"]));
    let dummy = NostrTagRef::new(dummy_values).map_err(map_nostr_error)?;
    Ok(HyfNostrEventBuffers {
        content: Box::leak(Box::new([0; HYF_NOSTR_MAX_CONTENT_CHARS])),
        recipient_hex: Box::leak(Box::new([0; 64])),
        p_tag_values: Box::leak(Box::new(["", ""])),
        t_tag_values: Box::leak(Box::new(["", ""])),
        alt_tag_values: Box::leak(Box::new(["", ""])),
        tags: Box::leak(Box::new([dummy; 3])),
    })
}

fn map_nostr_error(_error: NostrError) -> GatewayError {
    protocol_error()
}

fn protocol_error() -> GatewayError {
    GatewayError::Driver {
        link_id: NOSTR_LINK,
        kind: LinkDriverErrorKind::Protocol,
    }
}

fn assert_no_payload_leak(debug: &str) {
    assert!(!debug.contains("secret-outbound"));
    assert!(!debug.contains("payload"));
}
