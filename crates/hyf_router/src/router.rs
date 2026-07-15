use hyf_core::{CommunityId, MessageId, TimestampMs};
use hyf_link::{LinkEvent, LinkFrameRef, LinkId};
use hyf_wire::{HyfDestination, HyfEnvelopeRef, decode_envelope, validate_envelope};

use crate::{
    DropReason, RouterCommand, RouterError, RouterEvent, RouterPolicy, RouterStoreCommand,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinkState {
    link_id: LinkId,
    up: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeenDestination {
    MessageOnly,
    Community(CommunityId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RouterSeenKey {
    destination: SeenDestination,
    message_id: MessageId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Router<const MAX_LINKS: usize, const MAX_SEEN: usize> {
    policy: RouterPolicy,
    now_ms: TimestampMs,
    links: [Option<LinkState>; MAX_LINKS],
    seen: [Option<RouterSeenKey>; MAX_SEEN],
    next_seen: usize,
}

impl<const MAX_LINKS: usize, const MAX_SEEN: usize> Router<MAX_LINKS, MAX_SEEN> {
    pub const fn new(policy: RouterPolicy) -> Self {
        Self {
            policy,
            now_ms: TimestampMs(0),
            links: [None; MAX_LINKS],
            seen: [None; MAX_SEEN],
            next_seen: 0,
        }
    }

    pub fn policy(&self) -> RouterPolicy {
        self.policy
    }

    pub fn now_ms(&self) -> TimestampMs {
        self.now_ms
    }

    pub fn commit_seen(&mut self, envelope: HyfEnvelopeRef<'_>) {
        let key = seen_key_for(envelope);
        if !self.has_seen(key) {
            self.mark_seen(key);
        }
    }

    pub fn handle_event<'a>(
        &mut self,
        event: RouterEvent<'a>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<usize, RouterError> {
        match event {
            RouterEvent::Link(LinkEvent::Up { link_id }) => {
                self.set_link_state(link_id, true)?;
                Ok(0)
            }
            RouterEvent::Link(LinkEvent::Down { link_id }) => {
                self.set_link_state(link_id, false)?;
                Ok(0)
            }
            RouterEvent::Link(LinkEvent::Frame(frame)) => self.handle_frame(frame, out),
            RouterEvent::LocalSubmit(envelope) => self.handle_envelope(envelope, None, out),
            RouterEvent::Tick { now_ms } => {
                self.now_ms = now_ms;
                emit(
                    out,
                    RouterCommand::Store(RouterStoreCommand::ExpireBefore(now_ms)),
                )
            }
        }
    }

    pub fn forward_stored<'a>(
        &mut self,
        envelope: HyfEnvelopeRef<'a>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<usize, RouterError> {
        if let Some(count) = self.reject_terminal_envelope(envelope, out)? {
            return Ok(count);
        }
        if self.is_local_destination(envelope.destination) {
            return emit(out, RouterCommand::DeliverLocal(envelope));
        }
        if let Some(link_id) = self.first_up_link_except(None) {
            return emit(out, RouterCommand::Send { link_id, envelope });
        }

        Ok(0)
    }

    fn handle_frame<'a>(
        &mut self,
        frame: LinkFrameRef<'a>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<usize, RouterError> {
        match decode_envelope(frame.bytes) {
            Ok(envelope) => self.handle_envelope(envelope, Some(frame.link_id), out),
            Err(_) => emit(
                out,
                RouterCommand::DropFrame {
                    link_id: frame.link_id,
                    reason: DropReason::MalformedFrame,
                },
            ),
        }
    }

    fn handle_envelope<'a>(
        &mut self,
        envelope: HyfEnvelopeRef<'a>,
        ingress: Option<LinkId>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<usize, RouterError> {
        if let Some(count) = self.reject_invalid_or_expired(envelope, out)? {
            return Ok(count);
        }
        if self.has_seen(seen_key_for(envelope)) {
            return emit(
                out,
                RouterCommand::Drop {
                    message_id: envelope.message_id,
                    reason: DropReason::Duplicate,
                },
            );
        }

        if let HyfDestination::Community(community_id) = envelope.destination {
            return self.handle_community_envelope(envelope, community_id, ingress, out);
        }

        if self.is_local_destination(envelope.destination) {
            return emit(out, RouterCommand::DeliverLocal(envelope));
        }
        let outbound = match envelope_for_next_hop(envelope, ingress) {
            Ok(outbound) => outbound,
            Err(reason) => {
                return emit(
                    out,
                    RouterCommand::Drop {
                        message_id: envelope.message_id,
                        reason,
                    },
                );
            }
        };
        if let Some(link_id) = self.first_up_link_except(ingress) {
            return emit(
                out,
                RouterCommand::Send {
                    link_id,
                    envelope: outbound,
                },
            );
        }

        emit(out, RouterCommand::Store(RouterStoreCommand::Put(outbound)))
    }

    fn reject_terminal_envelope<'a>(
        &self,
        envelope: HyfEnvelopeRef<'a>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<Option<usize>, RouterError> {
        if let Err(error) = validate_envelope(envelope) {
            return match invalid_envelope_drop_reason(error) {
                Some(reason) => emit(
                    out,
                    RouterCommand::Drop {
                        message_id: envelope.message_id,
                        reason,
                    },
                )
                .map(Some),
                None => Err(RouterError::InvalidEnvelope(error)),
            };
        }

        if envelope.expires_at_ms.0 <= self.now_ms.0 {
            return emit(
                out,
                RouterCommand::Drop {
                    message_id: envelope.message_id,
                    reason: DropReason::Expired,
                },
            )
            .map(Some);
        }
        if envelope.hop_limit == 0 {
            return emit(
                out,
                RouterCommand::Drop {
                    message_id: envelope.message_id,
                    reason: DropReason::HopLimitExhausted,
                },
            )
            .map(Some);
        }

        Ok(None)
    }

    fn reject_invalid_or_expired<'a>(
        &self,
        envelope: HyfEnvelopeRef<'a>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<Option<usize>, RouterError> {
        if let Err(error) = validate_envelope(envelope) {
            return match invalid_envelope_drop_reason(error) {
                Some(reason) => emit(
                    out,
                    RouterCommand::Drop {
                        message_id: envelope.message_id,
                        reason,
                    },
                )
                .map(Some),
                None => Err(RouterError::InvalidEnvelope(error)),
            };
        }

        if envelope.expires_at_ms.0 <= self.now_ms.0 {
            return emit(
                out,
                RouterCommand::Drop {
                    message_id: envelope.message_id,
                    reason: DropReason::Expired,
                },
            )
            .map(Some);
        }

        Ok(None)
    }

    fn set_link_state(&mut self, link_id: LinkId, up: bool) -> Result<(), RouterError> {
        if let Some(index) = self.find_link_index(link_id) {
            self.links[index] = Some(LinkState { link_id, up });
            return Ok(());
        }
        if !up {
            return Ok(());
        }
        let Some(index) = self.links.iter().position(Option::is_none) else {
            return Err(RouterError::TooManyLinks { maximum: MAX_LINKS });
        };
        self.links[index] = Some(LinkState { link_id, up });
        Ok(())
    }

    fn find_link_index(&self, link_id: LinkId) -> Option<usize> {
        for (index, link) in self.links.iter().enumerate() {
            if let Some(existing) = link
                && existing.link_id == link_id
            {
                return Some(index);
            }
        }
        None
    }

    fn handle_community_envelope<'a>(
        &self,
        envelope: HyfEnvelopeRef<'a>,
        community_id: CommunityId,
        ingress: Option<LinkId>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<usize, RouterError> {
        if ingress.is_some() && envelope.hop_limit <= 1 {
            return emit(
                out,
                RouterCommand::Drop {
                    message_id: envelope.message_id,
                    reason: DropReason::HopLimitExhausted,
                },
            );
        }

        let local_delivery = self.policy.is_local_community(community_id);
        let send_count = self.up_link_count_except(ingress);
        let required = usize::from(local_delivery) + send_count;
        if required == 0 {
            return self.emit_community_fallback(envelope, ingress, out);
        }
        if out.len() < required {
            return Err(RouterError::OutputTooSmall {
                actual: out.len(),
                required,
            });
        }

        let mut count = 0;
        if local_delivery {
            out[count] = RouterCommand::DeliverLocal(envelope);
            count += 1;
        }
        let outbound = match ingress {
            Some(_) => HyfEnvelopeRef {
                hop_limit: envelope.hop_limit - 1,
                ..envelope
            },
            None => envelope,
        };
        for link in self.links.iter().flatten() {
            if link.up && Some(link.link_id) != ingress {
                out[count] = RouterCommand::Send {
                    link_id: link.link_id,
                    envelope: outbound,
                };
                count += 1;
            }
        }
        Ok(count)
    }

    fn emit_community_fallback<'a>(
        &self,
        envelope: HyfEnvelopeRef<'a>,
        ingress: Option<LinkId>,
        out: &mut [RouterCommand<'a>],
    ) -> Result<usize, RouterError> {
        if ingress.is_none() {
            return emit(out, RouterCommand::Store(RouterStoreCommand::Put(envelope)));
        }
        emit(
            out,
            RouterCommand::Drop {
                message_id: envelope.message_id,
                reason: DropReason::NoRoute,
            },
        )
    }

    fn first_up_link_except(&self, ingress: Option<LinkId>) -> Option<LinkId> {
        for link in self.links.iter().flatten() {
            if link.up && Some(link.link_id) != ingress {
                return Some(link.link_id);
            }
        }
        None
    }

    fn up_link_count_except(&self, ingress: Option<LinkId>) -> usize {
        self.links
            .iter()
            .flatten()
            .filter(|link| link.up && Some(link.link_id) != ingress)
            .count()
    }

    fn has_seen(&self, key: RouterSeenKey) -> bool {
        self.seen
            .iter()
            .any(|seen| seen.is_some_and(|existing| existing == key))
    }

    fn mark_seen(&mut self, key: RouterSeenKey) {
        if MAX_SEEN == 0 {
            return;
        }
        if let Some(index) = self.seen.iter().position(Option::is_none) {
            self.seen[index] = Some(key);
            self.next_seen = (index + 1) % MAX_SEEN;
            return;
        }
        self.seen[self.next_seen] = Some(key);
        self.next_seen = (self.next_seen + 1) % MAX_SEEN;
    }

    fn is_local_destination(&self, destination: HyfDestination) -> bool {
        matches!(destination, HyfDestination::Node(node_id) if node_id == self.policy.local_node_id)
    }
}

fn seen_key_for(envelope: HyfEnvelopeRef<'_>) -> RouterSeenKey {
    let destination = match envelope.destination {
        HyfDestination::Community(community_id) => SeenDestination::Community(community_id),
        HyfDestination::Node(_) | HyfDestination::Foreign(_) => SeenDestination::MessageOnly,
    };
    RouterSeenKey {
        destination,
        message_id: envelope.message_id,
    }
}

fn envelope_for_next_hop(
    envelope: HyfEnvelopeRef<'_>,
    ingress: Option<LinkId>,
) -> Result<HyfEnvelopeRef<'_>, DropReason> {
    let Some(_) = ingress else {
        if envelope.hop_limit == 0 {
            return Err(DropReason::HopLimitExhausted);
        }
        return Ok(envelope);
    };

    if envelope.hop_limit <= 1 {
        return Err(DropReason::HopLimitExhausted);
    }
    Ok(HyfEnvelopeRef {
        hop_limit: envelope.hop_limit - 1,
        ..envelope
    })
}

fn invalid_envelope_drop_reason(error: hyf_wire::HyfWireError) -> Option<DropReason> {
    match error {
        hyf_wire::HyfWireError::InvalidExpiry => Some(DropReason::Expired),
        _ => None,
    }
}

fn emit<'a>(
    out: &mut [RouterCommand<'a>],
    command: RouterCommand<'a>,
) -> Result<usize, RouterError> {
    if out.is_empty() {
        return Err(RouterError::OutputTooSmall {
            actual: 0,
            required: 1,
        });
    }
    out[0] = command;
    Ok(1)
}

#[cfg(test)]
pub(crate) mod tests {
    use hyf_core::{CommunityId, MessageId, NodeId, TimestampMs};
    use hyf_link::{LinkEvent, LinkFrameRef, LinkId};
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind, encode_envelope,
    };

    use super::Router;
    use crate::{
        DropReason, RouterCommand, RouterError, RouterEvent, RouterPolicy, RouterStoreCommand,
    };

    const LOCAL: NodeId = NodeId([0x11; 32]);
    const REMOTE: NodeId = NodeId([0x22; 32]);
    const ROOM_A: CommunityId = CommunityId([0xa1; 16]);
    const ROOM_B: CommunityId = CommunityId([0xb2; 16]);
    const LINK_A: LinkId = LinkId([0xaa; 16]);
    const LINK_B: LinkId = LinkId([0xbb; 16]);

    #[test]
    fn local_submit_sends_on_up_link() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, 1, b"payload");
        let mut out = [drop_command(); 1];

        assert_eq!(
            router.handle_event(
                RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
                &mut out
            )?,
            0
        );
        let count = router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;

        assert_eq!(count, 1);
        assert_eq!(
            out[0],
            RouterCommand::Send {
                link_id: LINK_A,
                envelope,
            }
        );
        Ok(())
    }

    #[test]
    fn local_submit_stores_when_no_link_is_up() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, 1, b"payload");
        let mut out = [drop_command(); 1];

        let count = router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;

        assert_eq!(count, 1);
        assert_eq!(
            out[0],
            RouterCommand::Store(RouterStoreCommand::Put(envelope))
        );
        Ok(())
    }

    #[test]
    fn local_submit_drops_expired_hop_zero_and_duplicate_messages() -> Result<(), RouterError> {
        let mut router = router();
        let mut out = [drop_command(); 1];
        let expired = sample_envelope(MessageId([1; 32]), 100, 200, 1, b"expired");
        let hop_zero = sample_envelope(MessageId([2; 32]), 100, 400, 0, b"hop");
        let duplicate = sample_envelope(MessageId([3; 32]), 100, 400, 1, b"dupe");

        router.handle_event(
            RouterEvent::Tick {
                now_ms: TimestampMs(300),
            },
            &mut out,
        )?;
        router.handle_event(RouterEvent::LocalSubmit(expired), &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: MessageId([1; 32]),
                reason: DropReason::Expired,
            }
        );

        router.handle_event(RouterEvent::LocalSubmit(hop_zero), &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: MessageId([2; 32]),
                reason: DropReason::HopLimitExhausted,
            }
        );

        router.handle_event(RouterEvent::LocalSubmit(duplicate), &mut out)?;
        router.commit_seen(duplicate);
        router.handle_event(RouterEvent::LocalSubmit(duplicate), &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: MessageId([3; 32]),
                reason: DropReason::Duplicate,
            }
        );
        Ok(())
    }

    #[test]
    fn uncommitted_message_can_be_retried_before_duplicate_drop() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = sample_envelope(MessageId([4; 32]), 100, 300, 1, b"retry");
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
            &mut out,
        )?;
        router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Send {
                link_id: LINK_A,
                envelope,
            }
        );

        router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Send {
                link_id: LINK_A,
                envelope,
            }
        );

        router.commit_seen(envelope);
        router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: envelope.message_id,
                reason: DropReason::Duplicate,
            }
        );
        Ok(())
    }

    #[test]
    fn stored_forwarding_uses_router_link_state() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = sample_envelope(MessageId([5; 32]), 100, 300, 1, b"stored");
        let mut out = [drop_command(); 1];

        assert_eq!(router.forward_stored(envelope, &mut out)?, 0);

        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
            &mut out,
        )?;
        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_B }),
            &mut out,
        )?;
        router.handle_event(
            RouterEvent::Link(LinkEvent::Down { link_id: LINK_A }),
            &mut out,
        )?;

        assert_eq!(router.forward_stored(envelope, &mut out)?, 1);
        assert_eq!(
            out[0],
            RouterCommand::Send {
                link_id: LINK_B,
                envelope,
            }
        );
        Ok(())
    }

    #[test]
    fn stored_forwarding_drops_expired_and_hop_zero() -> Result<(), RouterError> {
        let mut router = router();
        let expired = sample_envelope(MessageId([6; 32]), 100, 200, 1, b"expired");
        let hop_zero = sample_envelope(MessageId([7; 32]), 100, 400, 0, b"hop");
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Tick {
                now_ms: TimestampMs(300),
            },
            &mut out,
        )?;

        router.forward_stored(expired, &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: expired.message_id,
                reason: DropReason::Expired,
            }
        );

        router.forward_stored(hop_zero, &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: hop_zero.message_id,
                reason: DropReason::HopLimitExhausted,
            }
        );
        Ok(())
    }

    #[test]
    fn local_destination_is_delivered_locally() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = HyfEnvelopeRef {
            destination: HyfDestination::Node(LOCAL),
            ..sample_envelope(MessageId([1; 32]), 100, 200, 1, b"payload")
        };
        let mut out = [drop_command(); 1];

        router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;

        assert_eq!(out[0], RouterCommand::DeliverLocal(envelope));
        Ok(())
    }

    #[test]
    fn link_frame_decodes_and_routes_without_echoing_ingress() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, 2, b"payload");
        let expected = HyfEnvelopeRef {
            hop_limit: 1,
            ..envelope
        };
        let mut frame = [0; 128];
        let frame_len =
            encode_envelope(envelope, &mut frame).map_err(RouterError::InvalidEnvelope)?;
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
            &mut out,
        )?;
        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_B }),
            &mut out,
        )?;
        router.handle_event(
            RouterEvent::Link(LinkEvent::Frame(LinkFrameRef::new(
                LINK_A,
                TimestampMs(100),
                &frame[..frame_len],
            ))),
            &mut out,
        )?;

        assert_eq!(
            out[0],
            RouterCommand::Send {
                link_id: LINK_B,
                envelope: expected,
            }
        );
        Ok(())
    }

    #[test]
    fn inbound_remote_without_link_stores_decremented_envelope() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = sample_envelope(MessageId([8; 32]), 100, 200, 3, b"store");
        let expected = HyfEnvelopeRef {
            hop_limit: 2,
            ..envelope
        };
        let mut frame = [0; 128];
        let frame_len =
            encode_envelope(envelope, &mut frame).map_err(RouterError::InvalidEnvelope)?;
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Frame(LinkFrameRef::new(
                LINK_A,
                TimestampMs(100),
                &frame[..frame_len],
            ))),
            &mut out,
        )?;

        assert_eq!(
            out[0],
            RouterCommand::Store(RouterStoreCommand::Put(expected))
        );
        Ok(())
    }

    #[test]
    fn inbound_remote_hop_limit_one_drops_as_exhausted() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = sample_envelope(MessageId([9; 32]), 100, 200, 1, b"hop");
        let mut frame = [0; 128];
        let frame_len =
            encode_envelope(envelope, &mut frame).map_err(RouterError::InvalidEnvelope)?;
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Frame(LinkFrameRef::new(
                LINK_A,
                TimestampMs(100),
                &frame[..frame_len],
            ))),
            &mut out,
        )?;

        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: envelope.message_id,
                reason: DropReason::HopLimitExhausted,
            }
        );
        Ok(())
    }

    #[test]
    fn inbound_local_delivery_does_not_decrement_or_require_hop() -> Result<(), RouterError> {
        let mut router = router();
        let envelope = HyfEnvelopeRef {
            destination: HyfDestination::Node(LOCAL),
            hop_limit: 0,
            ..sample_envelope(MessageId([10; 32]), 100, 200, 1, b"local")
        };
        let mut frame = [0; 128];
        let frame_len =
            encode_envelope(envelope, &mut frame).map_err(RouterError::InvalidEnvelope)?;
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Frame(LinkFrameRef::new(
                LINK_A,
                TimestampMs(100),
                &frame[..frame_len],
            ))),
            &mut out,
        )?;

        assert_eq!(out[0], RouterCommand::DeliverLocal(envelope));
        Ok(())
    }

    #[test]
    fn link_frame_malformed_input_emits_frame_drop() -> Result<(), RouterError> {
        let mut router = router();
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Frame(LinkFrameRef::new(
                LINK_A,
                TimestampMs(100),
                b"bad",
            ))),
            &mut out,
        )?;

        assert_eq!(
            out[0],
            RouterCommand::DropFrame {
                link_id: LINK_A,
                reason: DropReason::MalformedFrame,
            }
        );
        Ok(())
    }

    #[test]
    fn tick_updates_time_and_emits_store_expiry() -> Result<(), RouterError> {
        let mut router = router();
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Tick {
                now_ms: TimestampMs(500),
            },
            &mut out,
        )?;

        assert_eq!(router.now_ms(), TimestampMs(500));
        assert_eq!(
            out[0],
            RouterCommand::Store(RouterStoreCommand::ExpireBefore(TimestampMs(500)))
        );
        Ok(())
    }

    #[test]
    fn router_reports_bounded_output_and_link_capacity() -> Result<(), RouterError> {
        let mut router = Router::<1, 4>::new(RouterPolicy::new(LOCAL, [None; 8]));
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, 1, b"payload");
        let mut out = [drop_command(); 1];

        assert_eq!(
            router.handle_event(RouterEvent::LocalSubmit(envelope), &mut []),
            Err(RouterError::OutputTooSmall {
                actual: 0,
                required: 1,
            })
        );
        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
            &mut out,
        )?;
        assert_eq!(
            router.handle_event(
                RouterEvent::Link(LinkEvent::Up { link_id: LINK_B }),
                &mut out
            ),
            Err(RouterError::TooManyLinks { maximum: 1 })
        );
        Ok(())
    }

    #[test]
    fn local_community_submit_delivers_and_sends_to_all_up_links() -> Result<(), RouterError> {
        let mut router = community_router();
        let envelope = community_envelope(MessageId([0x21; 32]), ROOM_A, 100, 200, 4, b"room");
        let mut out = [drop_command(); 3];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
            &mut out,
        )?;
        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_B }),
            &mut out,
        )?;
        let count = router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;

        assert_eq!(count, 3);
        assert_eq!(out[0], RouterCommand::DeliverLocal(envelope));
        assert_eq!(
            out[1],
            RouterCommand::Send {
                link_id: LINK_A,
                envelope,
            }
        );
        assert_eq!(
            out[2],
            RouterCommand::Send {
                link_id: LINK_B,
                envelope,
            }
        );
        Ok(())
    }

    #[test]
    fn local_unsubscribed_community_stores_when_offline() -> Result<(), RouterError> {
        let mut router = community_router();
        let envelope = community_envelope(MessageId([0x22; 32]), ROOM_B, 100, 200, 4, b"room");
        let mut out = [drop_command(); 1];

        let count = router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out)?;

        assert_eq!(count, 1);
        assert_eq!(
            out[0],
            RouterCommand::Store(RouterStoreCommand::Put(envelope))
        );
        Ok(())
    }

    #[test]
    fn inbound_community_fanout_excludes_ingress_and_does_not_store() -> Result<(), RouterError> {
        let mut router = community_router();
        let envelope = community_envelope(MessageId([0x23; 32]), ROOM_A, 100, 200, 4, b"room");
        let expected_forward = HyfEnvelopeRef {
            hop_limit: 3,
            ..envelope
        };
        let mut frame = [0; 128];
        let frame_len =
            encode_envelope(envelope, &mut frame).map_err(RouterError::InvalidEnvelope)?;
        let mut out = [drop_command(); 2];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
            &mut out,
        )?;
        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_B }),
            &mut out,
        )?;
        let count = router.handle_event(
            RouterEvent::Link(LinkEvent::Frame(LinkFrameRef::new(
                LINK_A,
                TimestampMs(100),
                &frame[..frame_len],
            ))),
            &mut out,
        )?;

        assert_eq!(count, 2);
        assert_eq!(out[0], RouterCommand::DeliverLocal(envelope));
        assert_eq!(
            out[1],
            RouterCommand::Send {
                link_id: LINK_B,
                envelope: expected_forward,
            }
        );
        Ok(())
    }

    #[test]
    fn inbound_unsubscribed_community_without_egress_drops_no_route() -> Result<(), RouterError> {
        let mut router = community_router();
        let envelope = community_envelope(MessageId([0x24; 32]), ROOM_B, 100, 200, 4, b"room");
        let mut frame = [0; 128];
        let frame_len =
            encode_envelope(envelope, &mut frame).map_err(RouterError::InvalidEnvelope)?;
        let mut out = [drop_command(); 1];

        let count = router.handle_event(
            RouterEvent::Link(LinkEvent::Frame(LinkFrameRef::new(
                LINK_A,
                TimestampMs(100),
                &frame[..frame_len],
            ))),
            &mut out,
        )?;

        assert_eq!(count, 1);
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: envelope.message_id,
                reason: DropReason::NoRoute,
            }
        );
        Ok(())
    }

    #[test]
    fn community_fanout_reports_required_output_capacity() -> Result<(), RouterError> {
        let mut router = community_router();
        let envelope = community_envelope(MessageId([0x25; 32]), ROOM_A, 100, 200, 4, b"room");
        let mut out = [drop_command(); 1];

        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_A }),
            &mut out,
        )?;
        router.handle_event(
            RouterEvent::Link(LinkEvent::Up { link_id: LINK_B }),
            &mut out,
        )?;

        assert_eq!(
            router.handle_event(RouterEvent::LocalSubmit(envelope), &mut out),
            Err(RouterError::OutputTooSmall {
                actual: 1,
                required: 3,
            })
        );
        Ok(())
    }

    #[test]
    fn same_message_id_in_different_communities_is_not_duplicate() -> Result<(), RouterError> {
        let mut router = community_router();
        let room_a = community_envelope(MessageId([0x26; 32]), ROOM_A, 100, 200, 4, b"a");
        let room_b = community_envelope(MessageId([0x26; 32]), ROOM_B, 100, 200, 4, b"b");
        let mut out = [drop_command(); 1];

        router.handle_event(RouterEvent::LocalSubmit(room_a), &mut out)?;
        router.commit_seen(room_a);
        let count = router.handle_event(RouterEvent::LocalSubmit(room_b), &mut out)?;

        assert_eq!(count, 1);
        assert_eq!(
            out[0],
            RouterCommand::Store(RouterStoreCommand::Put(room_b))
        );

        router.commit_seen(room_b);
        router.handle_event(RouterEvent::LocalSubmit(room_b), &mut out)?;
        assert_eq!(
            out[0],
            RouterCommand::Drop {
                message_id: room_b.message_id,
                reason: DropReason::Duplicate,
            }
        );
        Ok(())
    }

    pub(crate) fn sample_envelope<'a>(
        message_id: MessageId,
        created_at_ms: u64,
        expires_at_ms: u64,
        hop_limit: u8,
        payload: &'a [u8],
    ) -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id,
            source: LOCAL,
            destination: HyfDestination::Node(REMOTE),
            created_at_ms: TimestampMs(created_at_ms),
            expires_at_ms: TimestampMs(expires_at_ms),
            hop_limit,
            payload_kind: PayloadKind::HyfNativeV0,
            payload,
        }
    }

    fn community_envelope<'a>(
        message_id: MessageId,
        community_id: CommunityId,
        created_at_ms: u64,
        expires_at_ms: u64,
        hop_limit: u8,
        payload: &'a [u8],
    ) -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            destination: HyfDestination::Community(community_id),
            ..sample_envelope(message_id, created_at_ms, expires_at_ms, hop_limit, payload)
        }
    }

    fn router() -> Router<2, 4> {
        Router::new(RouterPolicy::new(LOCAL, [None; 8]))
    }

    fn community_router() -> Router<2, 8> {
        let mut communities = [None; 8];
        communities[0] = Some(ROOM_A);
        Router::new(RouterPolicy::new(LOCAL, communities))
    }

    const fn drop_command<'a>() -> RouterCommand<'a> {
        RouterCommand::Drop {
            message_id: MessageId([0; 32]),
            reason: DropReason::Duplicate,
        }
    }
}
