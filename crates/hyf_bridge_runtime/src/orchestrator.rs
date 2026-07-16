use core::fmt;

use hyf_bridge_bitchat::{
    BITCHAT_BRIDGE_PACKET_MAX_LEN, BitchatBridgeEgressParams, BitchatBridgeIngressParams,
    bitchat_packet_to_bridge_message, bridge_message_to_bitchat_packet_v2,
};
use hyf_bridge_core::{
    BridgeMessageKey, BridgeProtocol, BridgeWrapParams, HYF_BRIDGE_MESSAGE_MAX_LEN,
    decode_bridge_message, encode_bridge_message, validate_bridge_message, wrap_bridge_message,
};
use hyf_bridge_lxmf::{
    LXMF_BRIDGE_MESSAGE_MAX_LEN, LxmfBridgeEgressParams, LxmfBridgeIngressParams,
    bridge_message_to_lxmf_message_fixture, lxmf_message_to_bridge_message,
};
use hyf_bridge_nostr::{
    HYF_NOSTR_BRIDGE_EVENT_JSON_MAX_LEN, NostrBridgeEventScratch, NostrEvent,
    bridge_message_to_nostr_event_json, nostr_event_to_bridge_message,
};
use hyf_core::ForeignNetworkKind;

use crate::{
    BridgeDedupeSet, BridgeDropReason, BridgeOrigin, BridgeRoutePolicy, BridgeRuntimeCommand,
    BridgeRuntimeError,
};

pub use hyf_bridge_nostr::NostrBridgeEgressParams as BridgeRuntimeNostrEgressParams;

pub struct BridgeRuntimeScratch {
    bridge_message: [u8; HYF_BRIDGE_MESSAGE_MAX_LEN],
    bitchat_packet: [u8; BITCHAT_BRIDGE_PACKET_MAX_LEN],
    lxmf_message: [u8; LXMF_BRIDGE_MESSAGE_MAX_LEN],
    nostr_event: NostrBridgeEventScratch,
    nostr_event_json: [u8; HYF_NOSTR_BRIDGE_EVENT_JSON_MAX_LEN],
}

struct EgressOutputs<'a> {
    bitchat_packet: &'a mut [u8],
    lxmf_message: &'a mut [u8],
    nostr_event: &'a mut NostrBridgeEventScratch,
    nostr_event_json: &'a mut [u8],
}

#[derive(Clone, Copy)]
enum EgressPlan {
    BitChat { len: usize },
    Lxmf { len: usize },
    Nostr { len: usize },
    UnsupportedProfile,
}

#[derive(Clone, Copy, Debug)]
pub struct BridgeRuntimeEgressParams<'a> {
    pub bitchat: Option<BitchatBridgeEgressParams>,
    pub lxmf: Option<LxmfBridgeEgressParams>,
    pub nostr: Option<BridgeRuntimeNostrEgressParams<'a>>,
}

#[derive(Clone, Copy, Debug)]
pub struct BridgeRuntimeDispatchParams<'a> {
    pub wrap: BridgeWrapParams,
    pub egress: BridgeRuntimeEgressParams<'a>,
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
            bitchat_packet: [0; BITCHAT_BRIDGE_PACKET_MAX_LEN],
            lxmf_message: [0; LXMF_BRIDGE_MESSAGE_MAX_LEN],
            nostr_event: NostrBridgeEventScratch::new(),
            nostr_event_json: [0; HYF_NOSTR_BRIDGE_EVENT_JSON_MAX_LEN],
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

    pub const fn nostr_event_json_capacity(&self) -> usize {
        self.nostr_event_json.len()
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
            .field("nostr_event_json_capacity", &self.nostr_event_json.len())
            .finish()
    }
}

impl<'a> BridgeRuntimeEgressParams<'a> {
    pub const fn new(
        bitchat: Option<BitchatBridgeEgressParams>,
        lxmf: Option<LxmfBridgeEgressParams>,
        nostr: Option<BridgeRuntimeNostrEgressParams<'a>>,
    ) -> Self {
        Self {
            bitchat,
            lxmf,
            nostr,
        }
    }

    pub const fn none() -> Self {
        Self {
            bitchat: None,
            lxmf: None,
            nostr: None,
        }
    }

    pub const fn with_bitchat(bitchat: BitchatBridgeEgressParams) -> Self {
        Self {
            bitchat: Some(bitchat),
            lxmf: None,
            nostr: None,
        }
    }

    pub const fn with_lxmf(lxmf: LxmfBridgeEgressParams) -> Self {
        Self {
            bitchat: None,
            lxmf: Some(lxmf),
            nostr: None,
        }
    }

    pub const fn with_nostr(nostr: BridgeRuntimeNostrEgressParams<'a>) -> Self {
        Self {
            bitchat: None,
            lxmf: None,
            nostr: Some(nostr),
        }
    }
}

impl<'a> BridgeRuntimeDispatchParams<'a> {
    pub const fn new(wrap: BridgeWrapParams, egress: BridgeRuntimeEgressParams<'a>) -> Self {
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
        params: BridgeRuntimeDispatchParams<'_>,
        scratch: &'a mut BridgeRuntimeScratch,
        commands: &mut [BridgeRuntimeCommand<'a>],
    ) -> Result<usize, BridgeRuntimeError> {
        let ingress = bitchat_packet_to_bridge_message(raw, ingress_params)?;
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
                nostr_event: &mut scratch.nostr_event,
                nostr_event_json: &mut scratch.nostr_event_json,
            },
            commands,
        )
    }

    pub fn ingest_lxmf<'a>(
        &mut self,
        raw: &[u8],
        ingress_params: LxmfBridgeIngressParams,
        params: BridgeRuntimeDispatchParams<'_>,
        scratch: &'a mut BridgeRuntimeScratch,
        commands: &mut [BridgeRuntimeCommand<'a>],
    ) -> Result<usize, BridgeRuntimeError> {
        let ingress = lxmf_message_to_bridge_message(raw, ingress_params)?;
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
                nostr_event: &mut scratch.nostr_event,
                nostr_event_json: &mut scratch.nostr_event_json,
            },
            commands,
        )
    }

    pub fn ingest_nostr<'a>(
        &mut self,
        event: &NostrEvent<'_>,
        params: BridgeRuntimeDispatchParams<'_>,
        scratch: &'a mut BridgeRuntimeScratch,
        commands: &mut [BridgeRuntimeCommand<'a>],
    ) -> Result<usize, BridgeRuntimeError> {
        let bridge_len = {
            let ingress = nostr_event_to_bridge_message(event, &mut scratch.bridge_message)?;
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
                nostr_event: &mut scratch.nostr_event,
                nostr_event_json: &mut scratch.nostr_event_json,
            },
            commands,
        )
    }

    fn emit_bridge_message<'a>(
        dedupe: &mut BridgeDedupeSet<DEDUPE_CAPACITY>,
        route_policy: BridgeRoutePolicy<MAX_EGRESS>,
        origin_protocol: BridgeProtocol,
        raw_bridge: &'a [u8],
        params: BridgeRuntimeDispatchParams<'_>,
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
        let hyf_envelope = wrap_bridge_message(raw_bridge, params.wrap)?;

        let mut selected = [BridgeProtocol::Hyf; MAX_EGRESS];
        let selected_count = route_policy.select_egress(origin, &mut selected)?;
        let mut plans = [EgressPlan::UnsupportedProfile; MAX_EGRESS];
        for (index, protocol) in selected[..selected_count].iter().enumerate() {
            plans[index] = match protocol {
                BridgeProtocol::BitChat => match params.egress.bitchat {
                    Some(egress) => {
                        let len = bridge_message_to_bitchat_packet_v2(
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
                        let len = bridge_message_to_lxmf_message_fixture(
                            decode_bridge_message(raw_bridge)?,
                            egress,
                            &mut *outputs.lxmf_message,
                        )?;
                        EgressPlan::Lxmf { len }
                    }
                    None => EgressPlan::UnsupportedProfile,
                },
                BridgeProtocol::Nostr => match params.egress.nostr {
                    Some(egress) => {
                        let len = bridge_message_to_nostr_event_json(
                            raw_bridge,
                            egress,
                            outputs.nostr_event,
                            outputs.nostr_event_json,
                        )?;
                        EgressPlan::Nostr { len }
                    }
                    None => EgressPlan::UnsupportedProfile,
                },
                BridgeProtocol::Hyf => EgressPlan::UnsupportedProfile,
            };
        }

        dedupe.insert(key)?;
        commands[0] = BridgeRuntimeCommand::EmitHyfEnvelope(hyf_envelope);

        let mut command_count = 1;
        for plan in &plans[..selected_count] {
            commands[command_count] = match *plan {
                EgressPlan::BitChat { len } => {
                    BridgeRuntimeCommand::EmitBitChatPacket(&outputs.bitchat_packet[..len])
                }
                EgressPlan::Lxmf { len } => {
                    BridgeRuntimeCommand::EmitLxmfMessage(&outputs.lxmf_message[..len])
                }
                EgressPlan::Nostr { len } => {
                    BridgeRuntimeCommand::EmitNostrEvent(&outputs.nostr_event_json[..len])
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
    use hyf_bridge_bitchat::{BITCHAT_BRIDGE_PACKET_MAX_LEN, BitchatBridgeIngressParams};
    use hyf_bridge_core::{
        BridgeEndpointKind, BridgeEndpointRef, BridgeMessageRef, BridgePayloadKind, BridgeProtocol,
        BridgeWrapParams, HYF_BRIDGE_MESSAGE_VERSION_0, decode_bridge_message,
        encode_bridge_message,
    };
    use hyf_bridge_lxmf::LXMF_BRIDGE_MESSAGE_MAX_LEN;
    use hyf_bridge_nostr::{
        HYF_NOSTR_BRIDGE_EVENT_JSON_MAX_LEN, NostrBridgeEventScratch, NostrEvent, NostrSecretKey,
        bridge_message_to_nostr_event,
    };
    use hyf_core::{CommunityId, MessageId, NodeId, TimestampMs};
    use hyf_wire::HyfDestination;

    use super::{
        BridgeOrchestrator, BridgeRuntimeDispatchParams, BridgeRuntimeEgressParams,
        BridgeRuntimeNostrEgressParams, BridgeRuntimeScratch,
    };
    use crate::{BridgeDropReason, BridgeRoutePolicy, BridgeRuntimeCommand, BridgeRuntimeError};

    const ROOM: CommunityId = CommunityId([0x61; 16]);
    const MESSAGE: MessageId = MessageId([0x62; 32]);
    const OTHER_ROOM: CommunityId = CommunityId([0x63; 16]);
    const SOURCE_NODE: NodeId = NodeId([0x64; 32]);

    #[test]
    fn scratch_capacities_are_adapter_owned() {
        let scratch = BridgeRuntimeScratch::new();

        assert_eq!(
            scratch.bitchat_packet_capacity(),
            BITCHAT_BRIDGE_PACKET_MAX_LEN
        );
        assert_eq!(scratch.lxmf_message_capacity(), LXMF_BRIDGE_MESSAGE_MAX_LEN);
        assert_eq!(
            scratch.nostr_event_json_capacity(),
            HYF_NOSTR_BRIDGE_EVENT_JSON_MAX_LEN
        );
    }

    #[test]
    fn nostr_ingress_emits_hyf_and_unsupported_drop_without_lower_protocol_dependencies()
    -> Result<(), BridgeRuntimeError> {
        let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
            Some(BridgeProtocol::Nostr),
            Some(BridgeProtocol::BitChat),
        ]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut commands = empty_commands::<2>();

        let count = with_signed_bridge_event(ROOM, MESSAGE, |event| {
            runtime.ingest_nostr(
                &event,
                dispatch_params(BridgeRuntimeEgressParams::none()),
                &mut scratch,
                &mut commands,
            )
        })?;

        assert_eq!(count, 2);
        assert_hyf_command(commands[0], ROOM, MESSAGE)?;
        assert_eq!(
            commands[1],
            BridgeRuntimeCommand::Drop {
                key: hyf_bridge_core::BridgeMessageKey {
                    room_id: ROOM,
                    message_id: MESSAGE,
                },
                reason: BridgeDropReason::UnsupportedProfile,
            }
        );
        Ok(())
    }

    #[test]
    fn bitchat_ingress_emits_hyf_and_nostr_event_without_echo() -> Result<(), BridgeRuntimeError> {
        let secret = nostr_secret();
        let mut runtime = BridgeOrchestrator::<8, 2>::new(BridgeRoutePolicy::no_echo([
            Some(BridgeProtocol::BitChat),
            Some(BridgeProtocol::Nostr),
        ]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut commands = empty_commands::<2>();

        let count = runtime.ingest_bitchat(
            strict_bitchat_public_packet(),
            BitchatBridgeIngressParams::new(ROOM, MESSAGE),
            dispatch_params(BridgeRuntimeEgressParams::with_nostr(nostr_egress(&secret))),
            &mut scratch,
            &mut commands,
        )?;

        assert_eq!(count, 2);
        assert_hyf_command(commands[0], ROOM, MESSAGE)?;
        assert_nostr_event_command(commands[1])?;
        Ok(())
    }

    #[test]
    fn duplicate_ingress_emits_duplicate_drop() -> Result<(), BridgeRuntimeError> {
        let mut runtime = BridgeOrchestrator::<8, 1>::new(BridgeRoutePolicy::no_echo([None]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut first = empty_commands::<1>();
        let mut duplicate = empty_commands::<1>();
        let params = dispatch_params(BridgeRuntimeEgressParams::none());

        assert_eq!(
            with_signed_bridge_event(ROOM, MESSAGE, |event| {
                runtime.ingest_nostr(&event, params, &mut scratch, &mut first)
            })?,
            1
        );
        assert_eq!(
            with_signed_bridge_event(ROOM, MESSAGE, |event| {
                runtime.ingest_nostr(&event, params, &mut scratch, &mut duplicate)
            })?,
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
        let mut runtime = BridgeOrchestrator::<8, 1>::new(BridgeRoutePolicy::no_echo([Some(
            BridgeProtocol::BitChat,
        )]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut short = empty_commands::<1>();
        let mut commands = empty_commands::<2>();
        let params = dispatch_params(BridgeRuntimeEgressParams::none());

        assert_eq!(
            with_signed_bridge_event(ROOM, MESSAGE, |event| {
                runtime.ingest_nostr(&event, params, &mut scratch, &mut short)
            }),
            Err(BridgeRuntimeError::OutputTooSmall {
                actual: 1,
                required: 2,
            })
        );
        assert_eq!(
            with_signed_bridge_event(ROOM, MESSAGE, |event| {
                runtime.ingest_nostr(&event, params, &mut scratch, &mut commands)
            })?,
            2
        );
        Ok(())
    }

    #[test]
    fn same_message_id_in_different_rooms_is_not_duplicate() -> Result<(), BridgeRuntimeError> {
        let mut runtime = BridgeOrchestrator::<8, 1>::new(BridgeRoutePolicy::no_echo([None]));
        let mut scratch = BridgeRuntimeScratch::new();
        let mut first = empty_commands::<1>();
        let mut second = empty_commands::<1>();
        let params = dispatch_params(BridgeRuntimeEgressParams::none());

        assert_eq!(
            with_signed_bridge_event(ROOM, MESSAGE, |event| {
                runtime.ingest_nostr(&event, params, &mut scratch, &mut first)
            })?,
            1
        );
        assert_eq!(
            with_signed_bridge_event(OTHER_ROOM, MESSAGE, |event| {
                runtime.ingest_nostr(&event, params, &mut scratch, &mut second)
            })?,
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

    fn assert_nostr_event_command(
        command: BridgeRuntimeCommand<'_>,
    ) -> Result<(), BridgeRuntimeError> {
        let BridgeRuntimeCommand::EmitNostrEvent(event) = command else {
            return Err(BridgeRuntimeError::OutputTooSmall {
                actual: 0,
                required: 1,
            });
        };
        let event =
            core::str::from_utf8(event).map_err(|_| BridgeRuntimeError::OutputTooSmall {
                actual: 0,
                required: 1,
            })?;

        assert!(event.contains(r#""kind":9109"#));
        assert!(event.contains(r#"["hyf","bridge","v0"]"#));
        assert!(event.contains(r#"["community","61616161616161616161616161616161"]"#));
        assert!(event.contains(r#""sig":"#));
        Ok(())
    }

    fn dispatch_params<'a>(
        egress: BridgeRuntimeEgressParams<'a>,
    ) -> BridgeRuntimeDispatchParams<'a> {
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

    fn with_signed_bridge_event<T>(
        room_id: CommunityId,
        message_id: MessageId,
        f: impl for<'event> FnOnce(NostrEvent<'event>) -> Result<T, BridgeRuntimeError>,
    ) -> Result<T, BridgeRuntimeError> {
        let secret = nostr_secret();
        let mut raw = [0; 256];
        let raw_len = encode_bridge_message(
            bridge_message(
                room_id,
                message_id,
                BridgeEndpointKind::HyfNode,
                &SOURCE_NODE.0,
                b"hello",
            ),
            &mut raw,
        )?;
        let mut scratch = NostrBridgeEventScratch::new();

        bridge_message_to_nostr_event(&raw[..raw_len], &secret, 1_720_000_000, &mut scratch, f)?
    }

    fn strict_bitchat_public_packet() -> &'static [u8] {
        &[
            0x02, 0x02, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00,
            0x00, 0x05, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x68, 0x65, 0x6c, 0x6c,
            0x6f,
        ]
    }

    fn nostr_egress(secret: &NostrSecretKey) -> BridgeRuntimeNostrEgressParams<'_> {
        BridgeRuntimeNostrEgressParams::new(secret, 1_720_000_000)
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
