use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{Link, LinkClass, LinkDriverErrorKind, LinkId};
use hyf_link_nostr::FakeNostrRelay;

use crate::{GatewayError, GatewayLinkExecutor};

pub struct NostrGatewayExecutor<R> {
    link_id: LinkId,
    mtu: usize,
    up: bool,
    relay: R,
}

impl<R> NostrGatewayExecutor<R> {
    pub const fn new(link_id: LinkId, mtu: usize, relay: R) -> Self {
        Self {
            link_id,
            mtu,
            up: false,
            relay,
        }
    }

    pub const fn link_id(&self) -> LinkId {
        self.link_id
    }

    pub const fn link_class(&self) -> LinkClass {
        LinkClass::Nostr
    }

    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    pub const fn is_up(&self) -> bool {
        self.up
    }

    pub fn set_up(&mut self, up: bool) {
        self.up = up;
    }

    pub const fn relay(&self) -> &R {
        &self.relay
    }

    pub fn relay_mut(&mut self) -> &mut R {
        &mut self.relay
    }

    pub fn into_relay(self) -> R {
        self.relay
    }
}

impl<R> fmt::Debug for NostrGatewayExecutor<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrGatewayExecutor")
            .field("link_id", &self.link_id)
            .field("link_class", &LinkClass::Nostr)
            .field("mtu", &self.mtu)
            .field("up", &self.up)
            .finish()
    }
}

impl<R> Link for NostrGatewayExecutor<R> {
    fn link_id(&self) -> LinkId {
        self.link_id
    }

    fn link_class(&self) -> LinkClass {
        LinkClass::Nostr
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

impl<
    'a,
    const EVENT_CAPACITY: usize,
    const SUBSCRIPTION_CAPACITY: usize,
    const OUTPUT_CAPACITY: usize,
> GatewayLinkExecutor
    for NostrGatewayExecutor<
        FakeNostrRelay<'a, EVENT_CAPACITY, SUBSCRIPTION_CAPACITY, OUTPUT_CAPACITY>,
    >
{
    fn send_link_bytes(
        &mut self,
        link_id: LinkId,
        bytes: &[u8],
        _now_ms: TimestampMs,
    ) -> Result<(), GatewayError> {
        if link_id != self.link_id {
            return Err(GatewayError::UnsupportedLink { link_id });
        }
        if !self.up {
            return Err(GatewayError::Driver {
                link_id,
                kind: LinkDriverErrorKind::LinkDown,
            });
        }
        if bytes.len() > self.mtu {
            return Err(GatewayError::Driver {
                link_id,
                kind: LinkDriverErrorKind::FrameTooLarge,
            });
        }
        Err(GatewayError::Driver {
            link_id,
            kind: LinkDriverErrorKind::Unsupported,
        })
    }
}

#[cfg(test)]
mod tests {
    use hyf_link::{Link, LinkDriverErrorKind, LinkId};
    use hyf_link_nostr::FakeNostrRelay;

    use super::NostrGatewayExecutor;
    use crate::{GatewayError, GatewayLinkExecutor};

    const NOSTR_LINK: LinkId = LinkId([0x51; 16]);
    const OTHER_LINK: LinkId = LinkId([0x52; 16]);

    #[test]
    fn nostr_gateway_executor_exposes_link_metadata() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let mut executor = NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay);

        assert_eq!(executor.link_id(), NOSTR_LINK);
        assert_eq!(Link::link_class(&executor), hyf_link::LinkClass::Nostr);
        assert_eq!(executor.mtu(), 2048);
        assert!(!executor.is_up());
        executor.set_up(true);
        assert!(executor.is_up());
        assert_eq!(executor.relay().event_capacity(), 1);
    }

    #[test]
    fn nostr_gateway_executor_debug_omits_relay_payloads() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let executor = NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay);
        let debug = format!("{executor:?}");

        assert!(debug.contains("NostrGatewayExecutor"));
        assert!(debug.contains("link_id"));
        assert!(!debug.contains("content"));
        assert!(!debug.contains("payload"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn nostr_gateway_executor_rejects_unsupported_link_ids() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let mut executor = NostrGatewayExecutor::new(NOSTR_LINK, 2048, relay);

        assert_eq!(
            executor.send_link_bytes(OTHER_LINK, b"frame", hyf_core::TimestampMs(1)),
            Err(GatewayError::UnsupportedLink {
                link_id: OTHER_LINK,
            })
        );
    }

    #[test]
    fn nostr_gateway_executor_rejects_wrong_state_and_oversize_frames() {
        let relay = FakeNostrRelay::<1, 1, 1>::new();
        let mut executor = NostrGatewayExecutor::new(NOSTR_LINK, 4, relay);

        assert_eq!(
            executor.send_link_bytes(NOSTR_LINK, b"frame", hyf_core::TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind: LinkDriverErrorKind::LinkDown,
            })
        );

        executor.set_up(true);
        assert_eq!(
            executor.send_link_bytes(NOSTR_LINK, b"frames", hyf_core::TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind: LinkDriverErrorKind::FrameTooLarge,
            })
        );
        assert_eq!(
            executor.send_link_bytes(NOSTR_LINK, b"ok", hyf_core::TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: NOSTR_LINK,
                kind: LinkDriverErrorKind::Unsupported,
            })
        );
    }
}
