use core::fmt;

use hyf_bitchat_core::BITCHAT_CORE_PACKET_MAX_LEN;
use hyf_bridge_bitchat::{
    BitchatBridgeEgressParams, BitchatBridgeIngressParams, decode_bitchat_bridge_ingress,
    encode_bridge_message_to_bitchat_packet,
};
use hyf_bridge_core::{
    BridgeMessageKey, BridgeProtocol, BridgeWrapParams, HYF_BRIDGE_MESSAGE_MAX_LEN,
    decode_bridge_message, encode_bridge_message, validate_bridge_message, wrap_bridge_message,
};
use hyf_bridge_lxmf::{
    LxmfBridgeEgressParams, LxmfBridgeIngressParams, decode_lxmf_bridge_ingress,
    encode_bridge_message_to_lxmf_message,
};
use hyf_bridge_nostr::verify_and_decode_bridge_nostr_event;
use hyf_core::ForeignNetworkKind;
use hyf_link_nostr::NostrEvent;
use hyf_lxmf_core::LXMF_MESSAGE_MAX_LEN;

use crate::{
    BridgeDedupeSet, BridgeDropReason, BridgeOrigin, BridgeRoutePolicy, BridgeRuntimeCommand,
    BridgeRuntimeError,
};

pub struct BridgeRuntimeScratch {
    bridge_message: [u8; HYF_BRIDGE_MESSAGE_MAX_LEN],
    bitchat_packet: [u8; BITCHAT_CORE_PACKET_MAX_LEN],
    lxmf_message: [u8; LXMF_MESSAGE_MAX_LEN],
}

struct EgressOutputs<'a> {
    bitchat_packet: &'a mut [u8],
    lxmf_message: &'a mut [u8],
}

#[derive(Clone, Copy)]
enum EgressPlan {
    BitChat { len: usize },
    Lxmf { len: usize },
    UnsupportedProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeRuntimeEgressParams {
    pub bitchat: Option<BitchatBridgeEgressParams>,
    pub lxmf: Option<LxmfBridgeEgressParams>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeRuntimeDispatchParams {
    pub wrap: BridgeWrapParams,
    pub egress: BridgeRuntimeEgressParams,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeOrchestrator<const DEDUPE_CAPACITY: usize, const MAX_EGRESS: usize> {
    dedupe: BridgeDedupeSet<DEDUPE_CAPACITY>,
    route_policy: BridgeRoutePolicy<MAX_EGRESS>,
}

impl BridgeRuntimeScratch {
    pub const fn new() -> Self {
        Self {
            bridge_message: [0; HYF_BRIDGE_MESSAGE_MAX_LEN],
            bitchat_packet: [0; BITCHAT_CORE_PACKET_MAX_LEN],
            lxmf_message: [0; LXMF_MESSAGE_MAX_LEN],
        }
    }

    pub const fn bridge_message_capacity(&self) -> usize {
        self.bridge_message.len()
    }

    pub const fn bitchat_packet_capacity(&self) -> usize {
        self.bitchat_packet.len()
    }

    pub const fn lxmf_message_capacity(&self) -> usize {
        self.lxmf_message.len()
    }
}

impl Default for BridgeRuntimeScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BridgeRuntimeScratch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeRuntimeScratch")
            .field("bridge_message_capacity", &self.bridge_message.len())
            .field("bitchat_packet_capacity", &self.bitchat_packet.len())
            .field("lxmf_message_capacity", &self.lxmf_message.len())
            .finish()
    }
}

impl BridgeRuntimeEgressParams {
    pub const fn new(
        bitchat: Option<BitchatBridgeEgressParams>,
        lxmf: Option<LxmfBridgeEgressParams>,
    ) -> Self {
        Self { bitchat, lxmf }
    }

    pub const fn none() -> Self {
        Self {
            bitchat: None,
            lxmf: None,
        }
    }

    pub const fn with_bitchat(bitchat: BitchatBridgeEgressParams) -> Self {
        Self {
            bitchat: Some(bitchat),
            lxmf: None,
        }
    }

    pub const fn with_lxmf(lxmf: LxmfBridgeEgressParams) -> Self {
        Self {
            bitchat: None,
            lxmf: Some(lxmf),
        }
    }
}

impl BridgeRuntimeDispatchParams {
    pub const fn new(wrap: BridgeWrapParams, egress: BridgeRuntimeEgressParams) -> Self {
        Self { wrap, egress }
    }
}

impl<const DEDUPE_CAPACITY: usize, const MAX_EGRESS: usize>
    BridgeOrchestrator<DEDUPE_CAPACITY, MAX_EGRESS>
{
    pub const fn new(route_policy: BridgeRoutePolicy<MAX_EGRESS>) -> Self {
        Self {
            dedupe: BridgeDedupeSet::new(),
            route_policy,
        }
    }

    pub const fn dedupe(&self) -> &BridgeDedupeSet<DEDUPE_CAPACITY> {
        &self.dedupe
    }

    pub const fn route_policy(&self) -> &BridgeRoutePolicy<MAX_EGRESS> {
        &self.route_policy
    }

    pub fn ingest_bitchat<'a>(
        &mut self,
        raw: &[u8],
        ingress_params: BitchatBridgeIngressParams,
        params: BridgeRuntimeDispatchParams,
        scratch: &'a mut BridgeRuntimeScratch,
        commands: &mut [BridgeRuntimeCommand<'a>],
    ) -> Result<usize, BridgeRuntimeError> {
        let ingress = decode_bitchat_bridge_ingress(raw, ingress_params)?;
        let bridge_len =
            encode_bridge_message(ingress.bridge_message(), &mut scratch.bridge_message)?;
        let raw_bridge = &scratch.bridge_message[..bridge_len];
        Self::emit_bridge_message(
            &mut self.dedupe,
            self.route_policy,
            BridgeProtocol::BitChat,
            raw_bridge,
            params,
            EgressOutputs {
                bitchat_packet: &mut scratch.bitchat_packet,
                lxmf_message: &mut scratch.lxmf_message,
            },
            commands,
        )
    }

    pub fn ingest_lxmf<'a>(
        &mut self,
        raw: &[u8],
        ingress_params: LxmfBridgeIngressParams,
        params: BridgeRuntimeDispatchParams,
        scratch: &'a mut BridgeRuntimeScratch,
        commands: &mut [BridgeRuntimeCommand<'a>],
    ) -> Result<usize, BridgeRuntimeError> {
        let ingress = decode_lxmf_bridge_ingress(raw, ingress_params)?;
        let bridge_len =
            encode_bridge_message(ingress.bridge_message(), &mut scratch.bridge_message)?;
        let raw_bridge = &scratch.bridge_message[..bridge_len];
        Self::emit_bridge_message(
            &mut self.dedupe,
            self.route_policy,
            BridgeProtocol::Lxmf,
            raw_bridge,
            params,
            EgressOutputs {
                bitchat_packet: &mut scratch.bitchat_packet,
                lxmf_message: &mut scratch.lxmf_message,
            },
            commands,
        )
    }

    pub fn ingest_nostr<'a>(
        &mut self,
        event: &NostrEvent<'_>,
        params: BridgeRuntimeDispatchParams,
        scratch: &'a mut BridgeRuntimeScratch,
        commands: &mut [BridgeRuntimeCommand<'a>],
    ) -> Result<usize, BridgeRuntimeError> {
        let bridge_len = {
            let ingress = verify_and_decode_bridge_nostr_event(event, &mut scratch.bridge_message)?;
            ingress.raw_bridge_message.len()
        };
        let raw_bridge = &scratch.bridge_message[..bridge_len];
        Self::emit_bridge_message(
            &mut self.dedupe,
            self.route_policy,
            BridgeProtocol::Nostr,
            raw_bridge,
            params,
            EgressOutputs {
                bitchat_packet: &mut scratch.bitchat_packet,
                lxmf_message: &mut scratch.lxmf_message,
            },
            commands,
        )
    }

    fn emit_bridge_message<'a>(
        dedupe: &mut BridgeDedupeSet<DEDUPE_CAPACITY>,
        route_policy: BridgeRoutePolicy<MAX_EGRESS>,
        origin_protocol: BridgeProtocol,
        raw_bridge: &'a [u8],
        params: BridgeRuntimeDispatchParams,
        outputs: EgressOutputs<'a>,
        commands: &mut [BridgeRuntimeCommand<'a>],
    ) -> Result<usize, BridgeRuntimeError> {
        let message = validate_bridge_message(raw_bridge)?;
        let key = BridgeMessageKey {
            room_id: message.room_id,
            message_id: message.message_id,
        };

        if dedupe.contains(key) {
            ensure_command_capacity(commands, 1)?;
            commands[0] = BridgeRuntimeCommand::Drop {
                key,
                reason: BridgeDropReason::Duplicate,
            };
            return Ok(1);
        }

        let origin = BridgeOrigin::new(origin_protocol, endpoint_hash(origin_protocol, message));
        let selected_count = route_policy.selected_egress_count(origin);
        let required_commands = 1 + selected_count;
        ensure_command_capacity(commands, required_commands)?;
        dedupe.insert(key)?;

        commands[0] =
            BridgeRuntimeCommand::EmitHyfEnvelope(wrap_bridge_message(raw_bridge, params.wrap)?);

        let mut selected = [BridgeProtocol::Hyf; MAX_EGRESS];
        let selected_count = route_policy.select_egress(origin, &mut selected)?;
        let mut plans = [EgressPlan::UnsupportedProfile; MAX_EGRESS];
        for (index, protocol) in selected[..selected_count].iter().enumerate() {
            plans[index] = match protocol {
                BridgeProtocol::BitChat => match params.egress.bitchat {
                    Some(egress) => {
                        let len = encode_bridge_message_to_bitchat_packet(
                            decode_bridge_message(raw_bridge)?,
                            egress,
                            &mut *outputs.bitchat_packet,
                        )?;
                        EgressPlan::BitChat { len }
                    }
                    None => EgressPlan::UnsupportedProfile,
                },
                BridgeProtocol::Lxmf => match params.egress.lxmf {
                    Some(egress) => {
                        let len = encode_bridge_message_to_lxmf_message(
                            decode_bridge_message(raw_bridge)?,
                            egress,
                            &mut *outputs.lxmf_message,
                        )?;
                        EgressPlan::Lxmf { len }
                    }
                    None => EgressPlan::UnsupportedProfile,
                },
                BridgeProtocol::Hyf | BridgeProtocol::Nostr => EgressPlan::UnsupportedProfile,
            };
        }

        let mut command_count = 1;
        for plan in &plans[..selected_count] {
            commands[command_count] = match *plan {
                EgressPlan::BitChat { len } => {
                    BridgeRuntimeCommand::EmitBitChatPacket(&outputs.bitchat_packet[..len])
                }
                EgressPlan::Lxmf { len } => {
                    BridgeRuntimeCommand::EmitLxmfMessage(&outputs.lxmf_message[..len])
                }
                EgressPlan::UnsupportedProfile => unsupported_profile_drop(key),
            };
            command_count += 1;
        }

        Ok(command_count)
    }
}

impl<const DEDUPE_CAPACITY: usize, const MAX_EGRESS: usize> Default
    for BridgeOrchestrator<DEDUPE_CAPACITY, MAX_EGRESS>
{
    fn default() -> Self {
        Self::new(BridgeRoutePolicy::default())
    }
}

fn ensure_command_capacity(
    commands: &[BridgeRuntimeCommand<'_>],
    required: usize,
) -> Result<(), BridgeRuntimeError> {
    if commands.len() < required {
        return Err(BridgeRuntimeError::OutputTooSmall {
            actual: commands.len(),
            required,
        });
    }
    Ok(())
}

fn unsupported_profile_drop(key: BridgeMessageKey) -> BridgeRuntimeCommand<'static> {
    BridgeRuntimeCommand::Drop {
        key,
        reason: BridgeDropReason::UnsupportedProfile,
    }
}

fn endpoint_hash(
    origin_protocol: BridgeProtocol,
    message: hyf_bridge_core::BridgeMessageRef<'_>,
) -> [u8; 32] {
    let expected_network = match origin_protocol {
        BridgeProtocol::BitChat => Some(ForeignNetworkKind::BitChat),
        BridgeProtocol::Lxmf => Some(ForeignNetworkKind::Lxmf),
        BridgeProtocol::Nostr => Some(ForeignNetworkKind::Nostr),
        BridgeProtocol::Hyf => None,
    };
    let mut endpoint_hash = [0; 32];
    if let Some(network) = expected_network
        && message.author.kind == hyf_bridge_core::BridgeEndpointKind::Foreign(network)
    {
        let len = message.author.id.len().min(endpoint_hash.len());
        endpoint_hash[..len].copy_from_slice(&message.author.id[..len]);
    }
    endpoint_hash
}

#[cfg(test)]
mod tests {
    use hyf_bitchat_core::{
        BitchatFlags, BitchatPacketRef, BitchatPayloadRef, BitchatPeerId, BitchatVersion,
        decode_bitchat_packet, encode_bitchat_packet_v2,
    };
    use hyf_bridge_bitchat::{
        BitchatBridgeEgressParams, BitchatBridgeError, BitchatBridgeIngressParams,
    };
    use hyf_bridge_core::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeMessageRef, BridgePayloadKind, BridgeProtocol,
        BridgeWrapParams, HYF_BRIDGE_MESSAGE_VERSION_0, decode_bridge_message,
        encode_bridge_message,
    };
    use hyf_bridge_lxmf::{LxmfBridgeEgressParams, LxmfBridgeError, LxmfBridgeIngressParams};
    use hyf_bridge_nostr::{NostrBridgeEventScratch, with_signed_bridge_nostr_event};
    use hyf_core::{CommunityId, ForeignNetworkKind, MessageId, NodeId, TimestampMs};
    use hyf_link_nostr::{NostrSecretKey, derive_nostr_public_key};
    use hyf_lxmf_core::{
        LxmfDestinationHash, LxmfPayloadRef, LxmfRawMapRef, LxmfSignature, LxmfSourceHash,
        decode_lxmf_message, encode_lxmf_message,
    };
    use hyf_wire::HyfDestination;

    use super::{
        BridgeOrchestrator, BridgeRuntimeDispatchParams, BridgeRuntimeEgressParams,
        BridgeRuntimeScratch,
    };
    use crate::{BridgeDropReason, BridgeRoutePolicy, BridgeRuntimeCommand, BridgeRuntimeError};

    const ROOM: CommunityId = CommunityId([0x61; 16]);
    const MESSAGE: MessageId = MessageId([0x62; 32]);
    const OTHER_ROOM: CommunityId = CommunityId([0x63; 16]);
    const SOURCE_NODE: NodeId = NodeId([0x64; 32]);
    const BITCHAT_SENDER: BitchatPeerId = BitchatPeerId::from_bytes([0x65; 8]);
    const LXMF_DESTINATION: LxmfDestinationHash = LxmfDestinationHash::from_bytes([0x66; 16]);
    const LXMF_SOURCE: LxmfSourceHash = LxmfSourceHash::from_bytes([0x67; 16]);
    const LXMF_SIGNATURE: LxmfSignature = LxmfSignature::from_bytes([0x68; 64]);

    #[test]
    fn bitchat_ingress_emits_hyf_and_lxmf_without_echo() -> Result<(), BridgeRuntimeError> {
        let mut raw_storage = [0; 128];
        let raw_len = write_bitchat_packet(b"hello", 1000, &mut raw_storage)?;
        let raw = &raw_storage[..raw_len];
        let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
            Some(BridgeProtocol::BitChat),
            Some(BridgeProtocol::Lxmf),
        ]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut commands = empty_commands::<2>();

        let count = runtime.ingest_bitchat(
            raw,
            BitchatBridgeIngressParams::new(ROOM, MESSAGE),
            dispatch_params(BridgeRuntimeEgressParams::with_lxmf(lxmf_egress())),
            &mut scratch,
            &mut commands,
        )?;

        assert_eq!(count, 2);
        assert_hyf_command(commands[0], ROOM, MESSAGE)?;
        let BridgeRuntimeCommand::EmitLxmfMessage(raw_lxmf) = commands[1] else {
            return Err(BridgeRuntimeError::OutputTooSmall {
                actual: 0,
                required: 1,
            });
        };
        let lxmf = decode_lxmf_message(raw_lxmf).map_err(LxmfBridgeError::from)?;
        assert_eq!(lxmf.destination_hash(), &LXMF_DESTINATION);
        assert_eq!(lxmf.payload().content, b"hello");
        Ok(())
    }

    #[test]
    fn lxmf_ingress_emits_hyf_and_bitchat_without_echo() -> Result<(), BridgeRuntimeError> {
        let mut raw_storage = [0; 256];
        let raw_len = write_lxmf_message(b"hello", 1.5, &mut raw_storage)?;
        let raw = &raw_storage[..raw_len];
        let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
            Some(BridgeProtocol::Lxmf),
            Some(BridgeProtocol::BitChat),
        ]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut commands = empty_commands::<2>();

        let count = runtime.ingest_lxmf(
            raw,
            LxmfBridgeIngressParams::new(ROOM, MESSAGE),
            dispatch_params(BridgeRuntimeEgressParams::with_bitchat(bitchat_egress())),
            &mut scratch,
            &mut commands,
        )?;

        assert_eq!(count, 2);
        assert_hyf_command(commands[0], ROOM, MESSAGE)?;
        let BridgeRuntimeCommand::EmitBitChatPacket(raw_bitchat) = commands[1] else {
            return Err(BridgeRuntimeError::OutputTooSmall {
                actual: 0,
                required: 1,
            });
        };
        let packet = decode_bitchat_packet(raw_bitchat).map_err(BitchatBridgeError::from)?;
        assert_eq!(packet.sender_id, BITCHAT_SENDER);
        assert_eq!(packet.payload, BitchatPayloadRef::Plain(b"hello"));
        Ok(())
    }

    #[test]
    fn nostr_ingress_emits_hyf_and_bitchat_without_echo() -> Result<(), BridgeRuntimeError> {
        let secret = nostr_secret();
        let pubkey =
            derive_nostr_public_key(&secret).map_err(hyf_bridge_nostr::NostrBridgeError::from)?;
        let mut raw = [0; 256];
        let raw_len = encode_bridge_message(
            bridge_message(
                ROOM,
                MESSAGE,
                BridgeEndpointKind::Foreign(ForeignNetworkKind::Nostr),
                pubkey.as_bytes(),
                b"hello",
            ),
            &mut raw,
        )?;
        let mut nostr_scratch = NostrBridgeEventScratch::new();
        let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
            Some(BridgeProtocol::Nostr),
            Some(BridgeProtocol::BitChat),
        ]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut commands = empty_commands::<2>();

        with_signed_bridge_nostr_event(
            &raw[..raw_len],
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

        assert_hyf_command(commands[0], ROOM, MESSAGE)?;
        assert!(matches!(
            commands[1],
            BridgeRuntimeCommand::EmitBitChatPacket(_)
        ));
        Ok(())
    }

    #[test]
    fn duplicate_ingress_emits_duplicate_drop() -> Result<(), BridgeRuntimeError> {
        let mut raw_storage = [0; 128];
        let raw_len = write_bitchat_packet(b"hello", 1000, &mut raw_storage)?;
        let raw = &raw_storage[..raw_len];
        let mut runtime = BridgeOrchestrator::<8, 1>::new(BridgeRoutePolicy::no_echo([None]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut first = empty_commands::<1>();
        let mut duplicate = empty_commands::<1>();
        let params = dispatch_params(BridgeRuntimeEgressParams::none());

        assert_eq!(
            runtime.ingest_bitchat(
                raw,
                BitchatBridgeIngressParams::new(ROOM, MESSAGE),
                params,
                &mut scratch,
                &mut first,
            )?,
            1
        );
        assert_eq!(
            runtime.ingest_bitchat(
                raw,
                BitchatBridgeIngressParams::new(ROOM, MESSAGE),
                params,
                &mut scratch,
                &mut duplicate,
            )?,
            1
        );

        assert_eq!(
            duplicate[0],
            BridgeRuntimeCommand::Drop {
                key: hyf_bridge_core::BridgeMessageKey {
                    room_id: ROOM,
                    message_id: MESSAGE,
                },
                reason: BridgeDropReason::Duplicate,
            }
        );
        Ok(())
    }

    #[test]
    fn output_too_small_does_not_insert_dedupe_key() -> Result<(), BridgeRuntimeError> {
        let mut raw_storage = [0; 128];
        let raw_len = write_bitchat_packet(b"hello", 1000, &mut raw_storage)?;
        let raw = &raw_storage[..raw_len];
        let mut runtime = BridgeOrchestrator::<8, 1>::new(BridgeRoutePolicy::no_echo([Some(
            BridgeProtocol::Lxmf,
        )]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut short = empty_commands::<1>();
        let mut commands = empty_commands::<2>();
        let params = dispatch_params(BridgeRuntimeEgressParams::with_lxmf(lxmf_egress()));

        assert_eq!(
            runtime.ingest_bitchat(
                raw,
                BitchatBridgeIngressParams::new(ROOM, MESSAGE),
                params,
                &mut scratch,
                &mut short,
            ),
            Err(BridgeRuntimeError::OutputTooSmall {
                actual: 1,
                required: 2,
            })
        );
        assert_eq!(
            runtime.ingest_bitchat(
                raw,
                BitchatBridgeIngressParams::new(ROOM, MESSAGE),
                params,
                &mut scratch,
                &mut commands,
            )?,
            2
        );
        Ok(())
    }

    #[test]
    fn same_message_id_in_different_rooms_is_not_duplicate() -> Result<(), BridgeRuntimeError> {
        let mut raw_storage = [0; 128];
        let raw_len = write_bitchat_packet(b"hello", 1000, &mut raw_storage)?;
        let raw = &raw_storage[..raw_len];
        let mut runtime = BridgeOrchestrator::<8, 1>::new(BridgeRoutePolicy::no_echo([None]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut first = empty_commands::<1>();
        let mut second = empty_commands::<1>();
        let params = dispatch_params(BridgeRuntimeEgressParams::none());

        assert_eq!(
            runtime.ingest_bitchat(
                raw,
                BitchatBridgeIngressParams::new(ROOM, MESSAGE),
                params,
                &mut scratch,
                &mut first,
            )?,
            1
        );
        assert_eq!(
            runtime.ingest_bitchat(
                raw,
                BitchatBridgeIngressParams::new(OTHER_ROOM, MESSAGE),
                params,
                &mut scratch,
                &mut second,
            )?,
            1
        );
        assert!(matches!(
            second[0],
            BridgeRuntimeCommand::EmitHyfEnvelope(_)
        ));
        Ok(())
    }

    fn assert_hyf_command(
        command: BridgeRuntimeCommand<'_>,
        room_id: CommunityId,
        message_id: MessageId,
    ) -> Result<(), BridgeRuntimeError> {
        let BridgeRuntimeCommand::EmitHyfEnvelope(envelope) = command else {
            return Err(BridgeRuntimeError::OutputTooSmall {
                actual: 0,
                required: 1,
            });
        };
        let bridge = decode_bridge_message(envelope.payload)?;

        assert_eq!(envelope.message_id, message_id);
        assert_eq!(envelope.destination, HyfDestination::Community(room_id));
        assert_eq!(bridge.room_id, room_id);
        assert_eq!(bridge.message_id, message_id);
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

    fn write_bitchat_packet(
        payload: &[u8],
        timestamp: u64,
        output: &mut [u8],
    ) -> Result<usize, BridgeRuntimeError> {
        let packet_ref = BitchatPacketRef {
            version: BitchatVersion::V2,
            packet_type: hyf_bridge_bitchat::BITCHAT_BRIDGE_PACKET_TYPE_PUBLIC_MESSAGE,
            ttl: 7,
            timestamp,
            flags: BitchatFlags::empty(),
            sender_id: BitchatPeerId::from_bytes([0x41; 8]),
            recipient_id: None,
            route: None,
            payload: BitchatPayloadRef::Plain(payload),
            signature: None,
        };
        Ok(encode_bitchat_packet_v2(packet_ref, output).map_err(BitchatBridgeError::from)?)
    }

    fn write_lxmf_message(
        payload: &[u8],
        timestamp_secs: f64,
        output: &mut [u8],
    ) -> Result<usize, BridgeRuntimeError> {
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
        )
        .map_err(LxmfBridgeError::from)?)
    }

    fn bridge_message<'a>(
        room_id: CommunityId,
        message_id: MessageId,
        author_kind: BridgeEndpointKind,
        author_id: &'a [u8],
        payload: &'a [u8],
    ) -> BridgeMessageRef<'a> {
        BridgeMessageRef {
            version: HYF_BRIDGE_MESSAGE_VERSION_0,
            room_id,
            message_id,
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
            key: hyf_bridge_core::BridgeMessageKey {
                room_id: CommunityId([0xff; 16]),
                message_id: MessageId([0xff; 32]),
            },
            reason: BridgeDropReason::MalformedInput,
        }; N]
    }
}
