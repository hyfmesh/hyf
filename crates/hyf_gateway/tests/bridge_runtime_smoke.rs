use hyf_bitchat_core::{
    BitchatFlags, BitchatPacketRef, BitchatPayloadRef, BitchatPeerId, BitchatVersion,
    decode_bitchat_packet, encode_bitchat_packet_v2,
};
use hyf_bridge_bitchat::{BitchatBridgeEgressParams, BitchatBridgeIngressParams};
use hyf_bridge_core::{
    BridgeEndpointKind, BridgeEndpointRef, BridgeMessageKey, BridgeMessageRef, BridgePayloadKind,
    BridgeProtocol, BridgeWrapParams, HYF_BRIDGE_MESSAGE_VERSION_0, decode_bridge_message,
    encode_bridge_message,
};
use hyf_bridge_lxmf::{LxmfBridgeEgressParams, LxmfBridgeIngressParams};
use hyf_bridge_nostr::{NostrBridgeEventScratch, bridge_message_to_nostr_event};
use hyf_bridge_runtime::{
    BridgeOrchestrator, BridgeRoutePolicy, BridgeRuntimeCommand, BridgeRuntimeDispatchParams,
    BridgeRuntimeEgressParams, BridgeRuntimeScratch,
};
use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, NodeId, TimestampMs};
use hyf_link_nostr::{NostrSecretKey, derive_nostr_public_key};
use hyf_lxmf_core::{
    LxmfDestinationHash, LxmfPayloadRef, LxmfRawMapRef, LxmfSignature, LxmfSourceHash,
    decode_lxmf_message, encode_lxmf_message,
};
use hyf_wire::HyfDestination;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ROOM: CommunityId = CommunityId([0x71; 16]);
const MESSAGE: MessageId = MessageId([0x72; 32]);
const SOURCE_NODE: NodeId = NodeId([0x73; 32]);
const BITCHAT_SENDER: BitchatPeerId = BitchatPeerId::from_bytes([0x74; 8]);
const LXMF_DESTINATION: LxmfDestinationHash = LxmfDestinationHash::from_bytes([0x75; 16]);
const LXMF_SOURCE: LxmfSourceHash = LxmfSourceHash::from_bytes([0x76; 16]);
const LXMF_SIGNATURE: LxmfSignature = LxmfSignature::from_bytes([0x77; 64]);

#[test]
fn bridge_runtime_moves_bitchat_ingress_to_lxmf_fixture() -> TestResult {
    let mut raw = [0; 128];
    let raw_len = write_bitchat_packet(b"hello", 1000, &mut raw)?;
    let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
        Some(BridgeProtocol::BitChat),
        Some(BridgeProtocol::Lxmf),
    ]));
    let mut scratch = BridgeRuntimeScratch::new();
    let mut commands = empty_commands::<2>();

    let count = runtime.ingest_bitchat(
        &raw[..raw_len],
        BitchatBridgeIngressParams::new(ROOM, MESSAGE),
        dispatch_params(BridgeRuntimeEgressParams::with_lxmf(lxmf_egress())),
        &mut scratch,
        &mut commands,
    )?;

    assert_eq!(count, 2);
    assert_bridge_envelope(commands[0])?;
    let BridgeRuntimeCommand::EmitLxmfMessage(raw_lxmf) = commands[1] else {
        return Err(std::io::Error::other("expected LXMF egress").into());
    };
    assert_eq!(decode_lxmf_message(raw_lxmf)?.payload().content, b"hello");
    Ok(())
}

#[test]
fn bridge_runtime_moves_lxmf_ingress_to_bitchat_fixture() -> TestResult {
    let mut raw = [0; 256];
    let raw_len = write_lxmf_message(b"hello", 1.5, &mut raw)?;
    let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
        Some(BridgeProtocol::Lxmf),
        Some(BridgeProtocol::BitChat),
    ]));
    let mut scratch = BridgeRuntimeScratch::new();
    let mut commands = empty_commands::<2>();

    let count = runtime.ingest_lxmf(
        &raw[..raw_len],
        LxmfBridgeIngressParams::new(ROOM, MESSAGE),
        dispatch_params(BridgeRuntimeEgressParams::with_bitchat(bitchat_egress())),
        &mut scratch,
        &mut commands,
    )?;

    assert_eq!(count, 2);
    assert_bridge_envelope(commands[0])?;
    let BridgeRuntimeCommand::EmitBitChatPacket(raw_bitchat) = commands[1] else {
        return Err(std::io::Error::other("expected BitChat egress").into());
    };
    let packet = decode_bitchat_packet(raw_bitchat)?;
    assert_eq!(packet.sender_id, BITCHAT_SENDER);
    assert_eq!(packet.payload, BitchatPayloadRef::Plain(b"hello"));
    Ok(())
}

#[test]
fn bridge_runtime_moves_nostr_ingress_to_bitchat_fixture() -> TestResult {
    let secret = nostr_secret();
    let pubkey = derive_nostr_public_key(&secret)?;
    let mut raw_bridge = [0; 256];
    let raw_len = encode_bridge_message(
        bridge_message(
            BridgeEndpointKind::Foreign(ForeignNetworkKind::Nostr),
            pubkey.as_bytes(),
            b"hello",
        ),
        &mut raw_bridge,
    )?;
    let mut nostr_scratch = NostrBridgeEventScratch::new();
    let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
        Some(BridgeProtocol::Nostr),
        Some(BridgeProtocol::BitChat),
    ]));
    let mut scratch = BridgeRuntimeScratch::new();
    let mut commands = empty_commands::<2>();

    let count = bridge_message_to_nostr_event(
        &raw_bridge[..raw_len],
        &secret,
        1_720_000_000,
        &mut nostr_scratch,
        |event| {
            runtime.ingest_nostr(
                &event,
                dispatch_params(BridgeRuntimeEgressParams::with_bitchat(bitchat_egress())),
                &mut scratch,
                &mut commands,
            )
        },
    )??;

    assert_eq!(count, 2);
    assert_bridge_envelope(commands[0])?;
    assert!(matches!(
        commands[1],
        BridgeRuntimeCommand::EmitBitChatPacket(_)
    ));
    Ok(())
}

fn assert_bridge_envelope(command: BridgeRuntimeCommand<'_>) -> TestResult {
    let BridgeRuntimeCommand::EmitHyfEnvelope(envelope) = command else {
        return Err(std::io::Error::other("expected HYF bridge envelope").into());
    };
    let bridge = decode_bridge_message(envelope.payload)?;

    assert_eq!(envelope.message_id, MESSAGE);
    assert_eq!(envelope.destination, HyfDestination::Community(ROOM));
    assert_eq!(bridge.room_id, ROOM);
    assert_eq!(bridge.message_id, MESSAGE);
    Ok(())
}

fn dispatch_params(egress: BridgeRuntimeEgressParams) -> BridgeRuntimeDispatchParams {
    BridgeRuntimeDispatchParams::new(
        BridgeWrapParams {
            source_node: SOURCE_NODE,
            created_at_ms: TimestampMs(1_000),
            expires_at_ms: TimestampMs(2_000),
            hop_limit: 7,
        },
        egress,
    )
}

fn write_bitchat_packet(payload: &[u8], timestamp: u64, output: &mut [u8]) -> TestResult<usize> {
    let packet = BitchatPacketRef {
        version: BitchatVersion::V2,
        packet_type: hyf_bridge_bitchat::BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE,
        ttl: 7,
        timestamp,
        flags: BitchatFlags::empty(),
        sender_id: BitchatPeerId::from_bytes([0x44; 8]),
        recipient_id: None,
        route: None,
        payload: BitchatPayloadRef::Plain(payload),
        signature: None,
    };
    Ok(encode_bitchat_packet_v2(packet, output)?)
}

fn write_lxmf_message(payload: &[u8], timestamp_secs: f64, output: &mut [u8]) -> TestResult<usize> {
    Ok(encode_lxmf_message(
        LXMF_DESTINATION,
        LXMF_SOURCE,
        LXMF_SIGNATURE,
        LxmfPayloadRef {
            timestamp_secs,
            title: b"",
            content: payload,
            fields: LxmfRawMapRef { bytes: &[0x80] },
            stamp: None,
        },
        output,
    )?)
}

fn bridge_message<'a>(
    author_kind: BridgeEndpointKind,
    author_id: &'a [u8],
    payload: &'a [u8],
) -> BridgeMessageRef<'a> {
    BridgeMessageRef {
        version: HYF_BRIDGE_MESSAGE_VERSION_0,
        room_id: ROOM,
        message_id: MESSAGE,
        author: BridgeEndpointRef {
            kind: author_kind,
            id: author_id,
        },
        created_at_ms: TimestampMs(1_000),
        payload_kind: BridgePayloadKind::TextUtf8,
        payload,
    }
}

fn bitchat_egress() -> BitchatBridgeEgressParams {
    BitchatBridgeEgressParams::new(BITCHAT_SENDER)
}

fn lxmf_egress() -> LxmfBridgeEgressParams {
    LxmfBridgeEgressParams::new(LXMF_DESTINATION, LXMF_SOURCE, LXMF_SIGNATURE)
}

fn nostr_secret() -> NostrSecretKey {
    let mut secret = [0; 32];
    secret[31] = 3;
    NostrSecretKey::from_bytes(secret)
}

fn empty_commands<'a, const N: usize>() -> [BridgeRuntimeCommand<'a>; N] {
    [BridgeRuntimeCommand::Drop {
        key: BridgeMessageKey {
            room_id: CommunityId([0xff; 16]),
            message_id: MessageId([0xff; 32]),
        },
        reason: hyf_bridge_runtime::BridgeDropReason::MalformedInput,
    }; N]
}
