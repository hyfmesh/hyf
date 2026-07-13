use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{GatewayCore, GatewayError, NostrGatewayExecutor};
use hyf_link::{LinkDriverErrorKind, LinkEvent, LinkId};
use hyf_link_nostr::{
    FakeNostrRelay, HYF_NOSTR_ENVELOPE_KIND, NostrFilter, NostrPublicKey, NostrSecretKey,
};
use hyf_store::StorePolicy;
use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, decode_envelope};

type SmokeCore = GatewayCore<1, 8, 4>;
type SmokeRelay = FakeNostrRelay<'static, 4, 2, 8>;

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

fn fixture_secret() -> NostrSecretKey {
    let mut secret_key = [0; 32];
    secret_key[31] = 3;
    NostrSecretKey::from_bytes(secret_key)
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
