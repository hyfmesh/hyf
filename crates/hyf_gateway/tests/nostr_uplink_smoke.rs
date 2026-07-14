use hyf_config::{
    GatewayConfig, GatewayPolicyConfig, LinkConfig, LinkConfigSet, RouterConfig, StoreConfig,
};
use hyf_core::{MessageId, NodeId, TimestampMs};
use hyf_gateway::{
    GatewayCore, GatewayError, GatewayLinkExecutor, NostrGatewayControlText, NostrGatewayExecutor,
    NostrGatewayRelayOutput, NostrGatewayRelayStatus, NostrGatewaySubscriptionId,
};
use hyf_link::{LinkDriverErrorKind, LinkEvent, LinkId};
use hyf_link_nostr::{
    FakeNostrRelay, HYF_NOSTR_ENVELOPE_KIND, HyfNostrEventScratch, NostrError, NostrFilter,
    NostrPublicKey, NostrRelayStatus, NostrRelayStatusPrefix, NostrSecretKey, NostrSignature,
    with_signed_hyf_nostr_event,
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
    assert_no_payload_leak(&format!("{core:?}"));
    assert_no_payload_leak(&format!("{executor:?}"));
    assert_no_payload_leak(&format!("{:?}", executor.relay()));
    assert_no_payload_leak(&format!("{:?}", executor.relay().metrics()));

    let mut frame = [0; 256];
    assert!(matches!(
        executor.poll_relay_output(&mut frame)?,
        Some(NostrGatewayRelayOutput::Ok { accepted: true, .. })
    ));

    let kinds = [HYF_NOSTR_ENVELOPE_KIND];
    let filters = [NostrFilter {
        kinds: &kinds,
        ..NostrFilter::empty()
    }];
    if executor.relay_mut().subscribe("smoke", &filters).is_err() {
        return Err(protocol_error());
    }

    let frame = match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Frame(frame)) => frame,
        None => return Err(protocol_error()),
        _ => return Err(protocol_error()),
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
    assert!(matches!(
        executor.poll_relay_output(&mut frame)?,
        Some(NostrGatewayRelayOutput::Ok { accepted: true, .. })
    ));
    if executor.relay_mut().subscribe("inbound", &filters).is_err() {
        return Err(protocol_error());
    }
    let frame = match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Frame(frame)) => frame,
        None => return Err(protocol_error()),
        _ => return Err(protocol_error()),
    };
    core.ingest_link_frame(frame, &mut executor)?;

    assert_eq!(core.metrics().received, 1);
    assert_eq!(core.metrics().delivered, 1);
    assert_eq!(
        core.last_delivered_message_id(),
        Some(MessageId([0x66; 32]))
    );
    assert_eq!(core.last_delivered_payload_len(), b"inbound-secret".len());
    assert!(!format!("{core:?}").contains("inbound-secret"));
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
    let mut frame = [0; 256];

    executor.set_up(true);
    enqueue_tampered_event(&mut executor, &encoded[..len])?;

    assert_eq!(
        executor.poll_relay_output(&mut frame),
        Err(GatewayError::Driver {
            link_id: NOSTR_LINK,
            kind: LinkDriverErrorKind::Protocol,
        })
    );
    assert_eq!(core.metrics().received, 0);
    assert_eq!(core.last_delivered_message_id(), None);
    assert_eq!(executor.poll_relay_output(&mut frame)?, None);
    Ok(())
}

#[test]
fn smoke_gateway_typed_relay_controls_surface_in_order() -> Result<(), GatewayError> {
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        SmokeRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );
    let mut encoded = [0; 256];
    let len = encode_envelope(sample_envelope(), &mut encoded)?;
    let closed_status = auth_required_status();
    let mut frame = [0; 256];

    executor.set_up(true);
    executor.send_link_bytes(NOSTR_LINK, &encoded[..len], sample_envelope().created_at_ms)?;
    executor.send_link_bytes(NOSTR_LINK, &encoded[..len], sample_envelope().created_at_ms)?;
    {
        let subscription_id = String::from("controls");
        let raw_prefix = String::from("auth-required");
        let detail = String::from("challenge first");
        let notice = String::from("relay notice");
        let challenge = String::from("challenge-token");
        let injected_status = NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::AuthRequired,
            raw_prefix: &raw_prefix,
            detail: &detail,
        };

        executor
            .relay_mut()
            .inject_eose(&subscription_id)
            .map_err(map_nostr_error)?;
        executor
            .relay_mut()
            .inject_closed(&subscription_id, injected_status)
            .map_err(map_nostr_error)?;
        executor
            .relay_mut()
            .enqueue_notice(&notice)
            .map_err(map_nostr_error)?;
        executor
            .relay_mut()
            .inject_auth_challenge(&challenge)
            .map_err(map_nostr_error)?;
    }

    assert!(matches!(
        executor.poll_relay_output(&mut frame)?,
        Some(NostrGatewayRelayOutput::Ok { accepted: true, .. })
    ));
    match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Ok {
            accepted: true,
            status,
            ..
        }) => assert_eq!(
            status.as_status().map_err(map_nostr_error)?.prefix,
            NostrRelayStatusPrefix::Duplicate
        ),
        _ => return Err(protocol_error()),
    }
    match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Eose { subscription_id }) => {
            assert_subscription_id_eq(subscription_id, "controls")?;
        }
        _ => return Err(protocol_error()),
    }
    match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Closed {
            subscription_id,
            status,
        }) => {
            assert_subscription_id_eq(subscription_id, "controls")?;
            assert_gateway_status_eq(status, closed_status)?;
        }
        _ => return Err(protocol_error()),
    }
    match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Notice { message }) => {
            assert_control_text_eq(message, "relay notice")?;
        }
        _ => return Err(protocol_error()),
    }
    match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Auth { challenge }) => {
            assert_control_text_eq(challenge, "challenge-token")?;
        }
        _ => return Err(protocol_error()),
    }
    assert_eq!(executor.poll_relay_output(&mut frame)?, None);
    Ok(())
}

#[test]
fn smoke_gateway_short_output_buffer_retries_pending_event() -> Result<(), GatewayError> {
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
    let mut short_frame = [0; 1];
    let mut frame = [0; 256];

    executor.set_up(true);
    executor.send_link_bytes(NOSTR_LINK, &encoded[..len], TimestampMs(1_720_000_010_000))?;
    assert!(matches!(
        executor.poll_relay_output(&mut frame)?,
        Some(NostrGatewayRelayOutput::Ok { accepted: true, .. })
    ));
    if executor.relay_mut().subscribe("short", &filters).is_err() {
        return Err(protocol_error());
    }

    assert_eq!(
        executor.poll_relay_output(&mut short_frame),
        Err(GatewayError::Driver {
            link_id: NOSTR_LINK,
            kind: LinkDriverErrorKind::OutputTooSmall,
        })
    );

    let frame = match executor.poll_relay_output(&mut frame)? {
        Some(NostrGatewayRelayOutput::Frame(frame)) => frame,
        _ => return Err(protocol_error()),
    };
    assert_eq!(frame.bytes, &encoded[..len]);
    match executor.poll_relay_output(&mut [0; 1])? {
        Some(NostrGatewayRelayOutput::Eose { subscription_id }) => {
            assert_subscription_id_eq(subscription_id, "short")?;
        }
        _ => return Err(protocol_error()),
    }
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

#[test]
fn smoke_gateway_duplicate_ok_does_not_poison_store_forward_retry() -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config())?;
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        SmokeRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );
    let mut encoded = [0; 256];
    let len = encode_envelope(sample_envelope(), &mut encoded)?;

    core.submit(sample_envelope(), &mut executor)?;
    assert_eq!(core.stored_len(), 1);

    executor.set_up(true);
    executor.send_link_bytes(NOSTR_LINK, &encoded[..len], sample_envelope().created_at_ms)?;
    assert_eq!(executor.relay().stored_event_count(), 1);

    core.handle_link_event(
        LinkEvent::Up {
            link_id: NOSTR_LINK,
        },
        &mut executor,
    )?;

    assert_eq!(core.stored_len(), 0);
    assert_eq!(executor.relay().stored_event_count(), 1);
    Ok(())
}

#[test]
fn smoke_gateway_relay_rejections_are_typed_and_store_safe() -> Result<(), GatewayError> {
    assert_rejection_keeps_pending(
        rate_limited_status(),
        LinkDriverErrorKind::Backpressure,
        true,
    )?;
    assert_rejection_keeps_pending(auth_required_status(), LinkDriverErrorKind::LinkDown, true)?;
    assert_rejection_keeps_pending(invalid_status(), LinkDriverErrorKind::Protocol, false)
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

fn enqueue_tampered_event(
    executor: &mut NostrGatewayExecutor<SmokeRelay>,
    encoded: &[u8],
) -> Result<(), GatewayError> {
    let mut scratch = HyfNostrEventScratch::new();
    with_signed_hyf_nostr_event(
        encoded,
        &fixture_secret(),
        RECIPIENT,
        1_720_000_010,
        &mut scratch,
        |event| {
            let mut signature = *event.sig.as_bytes();
            signature[0] ^= 0x01;
            executor.relay_mut().enqueue_event_output(
                "bad",
                hyf_link_nostr::NostrEvent {
                    sig: NostrSignature::from_bytes(signature),
                    ..event
                },
            )
        },
    )
    .map_err(map_nostr_error)?
    .map_err(map_nostr_error)
}

fn map_nostr_error(_error: NostrError) -> GatewayError {
    protocol_error()
}

fn assert_gateway_status_eq(
    status: NostrGatewayRelayStatus,
    expected: NostrRelayStatus<'_>,
) -> Result<(), GatewayError> {
    assert_eq!(status.as_status().map_err(map_nostr_error)?, expected);
    Ok(())
}

fn assert_control_text_eq(
    text: NostrGatewayControlText,
    expected: &str,
) -> Result<(), GatewayError> {
    assert_eq!(text.as_str().map_err(map_nostr_error)?, expected);
    Ok(())
}

fn assert_subscription_id_eq(
    subscription_id: NostrGatewaySubscriptionId,
    expected: &str,
) -> Result<(), GatewayError> {
    assert_eq!(subscription_id.as_str().map_err(map_nostr_error)?, expected);
    Ok(())
}

fn assert_rejection_keeps_pending(
    status: NostrRelayStatus<'static>,
    kind: LinkDriverErrorKind,
    recoverable: bool,
) -> Result<(), GatewayError> {
    let mut core = SmokeCore::new(config())?;
    let mut executor = NostrGatewayExecutor::new(
        NOSTR_LINK,
        2048,
        SmokeRelay::new(),
        fixture_secret(),
        RECIPIENT,
    );

    core.submit(sample_envelope(), &mut executor)?;
    executor.set_up(true);
    executor
        .relay_mut()
        .reject_next_publish(status)
        .map_err(map_nostr_error)?;

    let result = core.handle_link_event(
        LinkEvent::Up {
            link_id: NOSTR_LINK,
        },
        &mut executor,
    );
    let expected = Err(GatewayError::Driver {
        link_id: NOSTR_LINK,
        kind,
    });
    if recoverable {
        assert_eq!(result, Ok(()));
    } else {
        assert_eq!(result, expected);
    }
    assert_eq!(core.stored_len(), 1);
    assert_eq!(core.metrics().link_errors, 1);
    assert_eq!(executor.relay().stored_event_count(), 0);
    Ok(())
}

const fn rate_limited_status() -> NostrRelayStatus<'static> {
    NostrRelayStatus {
        prefix: NostrRelayStatusPrefix::RateLimited,
        raw_prefix: "rate-limited",
        detail: "slow down",
    }
}

const fn auth_required_status() -> NostrRelayStatus<'static> {
    NostrRelayStatus {
        prefix: NostrRelayStatusPrefix::AuthRequired,
        raw_prefix: "auth-required",
        detail: "challenge first",
    }
}

const fn invalid_status() -> NostrRelayStatus<'static> {
    NostrRelayStatus {
        prefix: NostrRelayStatusPrefix::Invalid,
        raw_prefix: "invalid",
        detail: "bad event",
    }
}

fn protocol_error() -> GatewayError {
    GatewayError::Driver {
        link_id: NOSTR_LINK,
        kind: LinkDriverErrorKind::Protocol,
    }
}

fn assert_no_payload_leak(debug: &str) {
    assert!(!debug.contains("secret-outbound"));
    assert!(!debug.contains("inbound-secret"));
    assert!(!debug.contains("115, 101, 99"));
}
