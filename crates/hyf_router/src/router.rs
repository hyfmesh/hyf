use hyf_core::{MessageId, TimestampMs};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Router<const MAX_LINKS: usize, const MAX_SEEN: usize> {
    policy: RouterPolicy,
    now_ms: TimestampMs,
    links: [Option<LinkState>; MAX_LINKS],
    seen: [Option<MessageId>; MAX_SEEN],
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
        if let Err(error) = validate_envelope(envelope) {
            return match invalid_envelope_drop_reason(error) {
                Some(reason) => emit(
                    out,
                    RouterCommand::Drop {
                        message_id: envelope.message_id,
                        reason,
                    },
                ),
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
            );
        }
        if envelope.hop_limit == 0 {
            return emit(
                out,
                RouterCommand::Drop {
                    message_id: envelope.message_id,
                    reason: DropReason::HopLimitExhausted,
                },
            );
        }
        if self.has_seen(envelope.message_id) {
            return emit(
                out,
                RouterCommand::Drop {
                    message_id: envelope.message_id,
                    reason: DropReason::Duplicate,
                },
            );
        }
        self.mark_seen(envelope.message_id);

        if self.is_local_destination(envelope.destination) {
            return emit(out, RouterCommand::DeliverLocal(envelope));
        }
        if let Some(link_id) = self.first_up_link_except(ingress) {
            return emit(out, RouterCommand::Send { link_id, envelope });
        }

        emit(out, RouterCommand::Store(RouterStoreCommand::Put(envelope)))
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

    fn first_up_link_except(&self, ingress: Option<LinkId>) -> Option<LinkId> {
        for link in self.links.iter().flatten() {
            if link.up && Some(link.link_id) != ingress {
                return Some(link.link_id);
            }
        }
        None
    }

    fn has_seen(&self, message_id: MessageId) -> bool {
        self.seen
            .iter()
            .any(|seen| seen.is_some_and(|existing| existing == message_id))
    }

    fn mark_seen(&mut self, message_id: MessageId) {
        if MAX_SEEN == 0 {
            return;
        }
        if let Some(index) = self.seen.iter().position(Option::is_none) {
            self.seen[index] = Some(message_id);
            self.next_seen = (index + 1) % MAX_SEEN;
            return;
        }
        self.seen[self.next_seen] = Some(message_id);
        self.next_seen = (self.next_seen + 1) % MAX_SEEN;
    }

    fn is_local_destination(&self, destination: HyfDestination) -> bool {
        matches!(destination, HyfDestination::Node(node_id) if node_id == self.policy.local_node_id)
    }
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
    use hyf_core::{MessageId, NodeId, TimestampMs};
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
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, 1, b"payload");
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
                envelope,
            }
        );
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
        let mut router = Router::<1, 4>::new(RouterPolicy::new(LOCAL));
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

    fn router() -> Router<2, 4> {
        Router::new(RouterPolicy::new(LOCAL))
    }

    const fn drop_command<'a>() -> RouterCommand<'a> {
        RouterCommand::Drop {
            message_id: MessageId([0; 32]),
            reason: DropReason::Duplicate,
        }
    }
}
