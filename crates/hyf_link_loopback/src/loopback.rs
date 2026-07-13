use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{Link, LinkClass, LinkCommand, LinkDriver, LinkEvent, LinkFrameRef, LinkId};

use crate::LoopbackError;

pub const LOOPBACK_MAX_FRAME_LEN: usize = 2048;
pub const LOOPBACK_LEFT_ID: LinkId = LinkId([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
pub const LOOPBACK_RIGHT_ID: LinkId = LinkId([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopbackSide {
    Left,
    Right,
}

impl LoopbackSide {
    pub const fn link_id(self) -> LinkId {
        match self {
            Self::Left => LOOPBACK_LEFT_ID,
            Self::Right => LOOPBACK_RIGHT_ID,
        }
    }

    pub const fn peer_link_id(self) -> LinkId {
        match self {
            Self::Left => LOOPBACK_RIGHT_ID,
            Self::Right => LOOPBACK_LEFT_ID,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct QueuedFrame {
    bytes: [u8; LOOPBACK_MAX_FRAME_LEN],
    len: usize,
    received_at_ms: TimestampMs,
}

impl fmt::Debug for QueuedFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueuedFrame")
            .field("bytes", &"<redacted>")
            .field("len", &self.len)
            .field("received_at_ms", &self.received_at_ms)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackPair<const N: usize> {
    left: LoopbackEndpoint<N>,
    right: LoopbackEndpoint<N>,
}

impl<const N: usize> LoopbackPair<N> {
    pub const fn new(mtu: usize) -> Self {
        Self {
            left: LoopbackEndpoint::new(LOOPBACK_LEFT_ID, mtu),
            right: LoopbackEndpoint::new(LOOPBACK_RIGHT_ID, mtu),
        }
    }

    pub fn split(&mut self) -> (&mut LoopbackEndpoint<N>, &mut LoopbackEndpoint<N>) {
        (&mut self.left, &mut self.right)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LoopbackDriver<const N: usize> {
    pair: LoopbackPair<N>,
    side: LoopbackSide,
}

impl<const N: usize> fmt::Debug for LoopbackDriver<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackDriver")
            .field("side", &self.side)
            .field("tx_link_id", &self.side.link_id())
            .field("rx_link_id", &self.side.peer_link_id())
            .field("tx_up", &self.tx_endpoint().is_up())
            .field("rx_up", &self.rx_endpoint().is_up())
            .field("tx_queued", &self.tx_endpoint().queued_len())
            .field("rx_queued", &self.rx_endpoint().queued_len())
            .finish()
    }
}

impl<const N: usize> LoopbackDriver<N> {
    pub const fn new(side: LoopbackSide, mtu: usize) -> Self {
        Self {
            pair: LoopbackPair::new(mtu),
            side,
        }
    }

    pub const fn left(mtu: usize) -> Self {
        Self::new(LoopbackSide::Left, mtu)
    }

    pub const fn right(mtu: usize) -> Self {
        Self::new(LoopbackSide::Right, mtu)
    }

    pub fn set_link_up(
        &mut self,
        link_id: LinkId,
        up: bool,
    ) -> Result<LinkEvent<'static>, LoopbackError> {
        endpoint_for_link_mut(&mut self.pair, link_id).map(|endpoint| endpoint.set_up(up))
    }

    pub fn queued_len(&self, link_id: LinkId) -> Result<usize, LoopbackError> {
        Ok(endpoint_for_link_ref(&self.pair, link_id)?.queued_len())
    }

    pub fn receive_link_frame<'a>(
        &mut self,
        link_id: LinkId,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, LoopbackError> {
        endpoint_for_link_mut(&mut self.pair, link_id)?.receive_into(output)
    }

    pub fn send_link_bytes(
        &mut self,
        link_id: LinkId,
        bytes: &[u8],
        now_ms: TimestampMs,
    ) -> Result<(), LoopbackError> {
        if link_id == LOOPBACK_LEFT_ID {
            self.pair
                .left
                .send_bytes_to(&mut self.pair.right, bytes, now_ms)
        } else if link_id == LOOPBACK_RIGHT_ID {
            self.pair
                .right
                .send_bytes_to(&mut self.pair.left, bytes, now_ms)
        } else {
            Err(LoopbackError::LinkMismatch {
                expected: self.side.link_id(),
                actual: link_id,
            })
        }
    }

    fn tx_endpoint(&self) -> &LoopbackEndpoint<N> {
        match self.side {
            LoopbackSide::Left => &self.pair.left,
            LoopbackSide::Right => &self.pair.right,
        }
    }

    fn rx_endpoint(&self) -> &LoopbackEndpoint<N> {
        match self.side {
            LoopbackSide::Left => &self.pair.right,
            LoopbackSide::Right => &self.pair.left,
        }
    }

    fn tx_rx(&mut self) -> (&mut LoopbackEndpoint<N>, &mut LoopbackEndpoint<N>) {
        match self.side {
            LoopbackSide::Left => (&mut self.pair.left, &mut self.pair.right),
            LoopbackSide::Right => (&mut self.pair.right, &mut self.pair.left),
        }
    }
}

impl<const N: usize> LinkDriver for LoopbackDriver<N> {
    type Error = LoopbackError;

    fn link_id(&self) -> LinkId {
        self.side.link_id()
    }

    fn link_class(&self) -> LinkClass {
        LinkClass::Loopback
    }

    fn mtu(&self) -> usize {
        self.tx_endpoint().mtu()
    }

    fn is_up(&self) -> bool {
        self.tx_endpoint().is_up() && self.rx_endpoint().is_up()
    }

    fn send_bytes(&mut self, bytes: &[u8], now_ms: TimestampMs) -> Result<(), Self::Error> {
        let (tx, rx) = self.tx_rx();
        tx.send_bytes_to(rx, bytes, now_ms)
    }

    fn poll_frame<'a>(
        &mut self,
        _now_ms: TimestampMs,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, Self::Error> {
        self.rx_endpoint_mut().receive_into(output)
    }
}

impl<const N: usize> LoopbackDriver<N> {
    fn rx_endpoint_mut(&mut self) -> &mut LoopbackEndpoint<N> {
        match self.side {
            LoopbackSide::Left => &mut self.pair.right,
            LoopbackSide::Right => &mut self.pair.left,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LoopbackEndpoint<const N: usize> {
    link_id: LinkId,
    mtu: usize,
    up: bool,
    queue: [Option<QueuedFrame>; N],
}

impl<const N: usize> fmt::Debug for LoopbackEndpoint<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackEndpoint")
            .field("link_id", &self.link_id)
            .field("mtu", &self.mtu)
            .field("up", &self.up)
            .field("queued", &self.queued_len())
            .finish()
    }
}

impl<const N: usize> LoopbackEndpoint<N> {
    pub const fn new(link_id: LinkId, mtu: usize) -> Self {
        Self {
            link_id,
            mtu,
            up: true,
            queue: [None; N],
        }
    }

    pub fn is_up(&self) -> bool {
        self.up
    }

    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn queued_len(&self) -> usize {
        self.queue.iter().filter(|frame| frame.is_some()).count()
    }

    pub fn set_up(&mut self, up: bool) -> LinkEvent<'static> {
        self.up = up;
        if up {
            LinkEvent::Up {
                link_id: self.link_id,
            }
        } else {
            LinkEvent::Down {
                link_id: self.link_id,
            }
        }
    }

    pub fn send_command_to(
        &self,
        peer: &mut Self,
        command: LinkCommand<'_>,
        now_ms: TimestampMs,
    ) -> Result<(), LoopbackError> {
        if command.link_id() != self.link_id {
            return Err(LoopbackError::LinkMismatch {
                expected: self.link_id,
                actual: command.link_id(),
            });
        }
        self.send_bytes_to(peer, command.bytes(), now_ms)
    }

    pub fn send_bytes_to(
        &self,
        peer: &mut Self,
        bytes: &[u8],
        now_ms: TimestampMs,
    ) -> Result<(), LoopbackError> {
        self.validate_send(bytes)?;
        peer.validate_receive(bytes)?;
        peer.enqueue(bytes, now_ms)
    }

    pub fn receive_into<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, LoopbackError> {
        let Some(frame) = self.queue[0] else {
            return Ok(None);
        };
        if output.len() < frame.len {
            return Err(LoopbackError::OutputTooSmall {
                actual: output.len(),
                required: frame.len,
            });
        }
        output[..frame.len].copy_from_slice(&frame.bytes[..frame.len]);
        self.shift_queue();
        Ok(Some(LinkFrameRef::new(
            self.link_id,
            frame.received_at_ms,
            &output[..frame.len],
        )))
    }

    fn validate_send(&self, bytes: &[u8]) -> Result<(), LoopbackError> {
        if !self.up {
            return Err(LoopbackError::Down {
                link_id: self.link_id,
            });
        }
        self.validate_frame_len(bytes)
    }

    fn validate_receive(&self, bytes: &[u8]) -> Result<(), LoopbackError> {
        if !self.up {
            return Err(LoopbackError::Down {
                link_id: self.link_id,
            });
        }
        self.validate_frame_len(bytes)
    }

    fn validate_frame_len(&self, bytes: &[u8]) -> Result<(), LoopbackError> {
        if bytes.len() > self.mtu {
            return Err(LoopbackError::FrameTooLarge {
                actual: bytes.len(),
                mtu: self.mtu,
            });
        }
        if bytes.len() > LOOPBACK_MAX_FRAME_LEN {
            return Err(LoopbackError::InternalFrameTooLarge {
                actual: bytes.len(),
                maximum: LOOPBACK_MAX_FRAME_LEN,
            });
        }
        Ok(())
    }

    fn enqueue(&mut self, bytes: &[u8], received_at_ms: TimestampMs) -> Result<(), LoopbackError> {
        let Some(index) = self.queue.iter().position(Option::is_none) else {
            return Err(LoopbackError::QueueFull {
                link_id: self.link_id,
                capacity: N,
            });
        };
        let mut stored = [0; LOOPBACK_MAX_FRAME_LEN];
        stored[..bytes.len()].copy_from_slice(bytes);
        self.queue[index] = Some(QueuedFrame {
            bytes: stored,
            len: bytes.len(),
            received_at_ms,
        });
        Ok(())
    }

    fn shift_queue(&mut self) {
        if N == 0 {
            return;
        }
        for index in 1..N {
            self.queue[index - 1] = self.queue[index];
        }
        self.queue[N - 1] = None;
    }
}

impl<const N: usize> Link for LoopbackEndpoint<N> {
    fn link_id(&self) -> LinkId {
        self.link_id
    }

    fn link_class(&self) -> LinkClass {
        LinkClass::Loopback
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

fn endpoint_for_link_ref<const N: usize>(
    pair: &LoopbackPair<N>,
    link_id: LinkId,
) -> Result<&LoopbackEndpoint<N>, LoopbackError> {
    if link_id == LOOPBACK_LEFT_ID {
        Ok(&pair.left)
    } else if link_id == LOOPBACK_RIGHT_ID {
        Ok(&pair.right)
    } else {
        Err(LoopbackError::LinkMismatch {
            expected: LOOPBACK_LEFT_ID,
            actual: link_id,
        })
    }
}

fn endpoint_for_link_mut<const N: usize>(
    pair: &mut LoopbackPair<N>,
    link_id: LinkId,
) -> Result<&mut LoopbackEndpoint<N>, LoopbackError> {
    if link_id == LOOPBACK_LEFT_ID {
        Ok(&mut pair.left)
    } else if link_id == LOOPBACK_RIGHT_ID {
        Ok(&mut pair.right)
    } else {
        Err(LoopbackError::LinkMismatch {
            expected: LOOPBACK_LEFT_ID,
            actual: link_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::TimestampMs;
    use hyf_link::{LinkCommand, LinkDriver, LinkEvent, LinkId};

    use super::{
        LOOPBACK_LEFT_ID, LOOPBACK_RIGHT_ID, LoopbackDriver, LoopbackEndpoint, LoopbackPair,
        LoopbackSide,
    };
    use crate::{LOOPBACK_MAX_FRAME_LEN, LoopbackError};

    #[test]
    fn loopback_pair_splits_deterministic_endpoints() {
        let mut pair = LoopbackPair::<2>::new(256);
        let (left, right) = pair.split();

        assert_eq!(left.link_id(), LOOPBACK_LEFT_ID);
        assert_eq!(right.link_id(), LOOPBACK_RIGHT_ID);
        assert_eq!(left.mtu(), 256);
        assert_eq!(right.mtu(), 256);
    }

    #[test]
    fn loopback_side_exposes_tx_and_peer_ids() {
        assert_eq!(LoopbackSide::Left.link_id(), LOOPBACK_LEFT_ID);
        assert_eq!(LoopbackSide::Left.peer_link_id(), LOOPBACK_RIGHT_ID);
        assert_eq!(LoopbackSide::Right.link_id(), LOOPBACK_RIGHT_ID);
        assert_eq!(LoopbackSide::Right.peer_link_id(), LOOPBACK_LEFT_ID);
    }

    #[test]
    fn loopback_driver_sends_and_polls_peer_frames() -> Result<(), LoopbackError> {
        let mut driver = LoopbackDriver::<2>::left(16);
        let mut output = [0; 8];

        assert_eq!(driver.link_id(), LOOPBACK_LEFT_ID);
        assert_eq!(driver.link_class(), hyf_link::LinkClass::Loopback);
        assert_eq!(driver.mtu(), 16);
        assert!(driver.is_up());

        driver.send_bytes(b"one", TimestampMs(10))?;
        assert_eq!(driver.queued_len(LOOPBACK_RIGHT_ID)?, 1);

        let frame =
            driver
                .poll_frame(TimestampMs(99), &mut output)?
                .ok_or(LoopbackError::QueueFull {
                    link_id: LOOPBACK_RIGHT_ID,
                    capacity: 2,
                })?;
        assert_eq!(frame.link_id, LOOPBACK_RIGHT_ID);
        assert_eq!(frame.received_at_ms, TimestampMs(10));
        assert_eq!(frame.bytes, b"one");
        assert_eq!(driver.poll_frame(TimestampMs(100), &mut output)?, None);
        Ok(())
    }

    #[test]
    fn loopback_driver_preserves_short_output_without_dequeueing() -> Result<(), LoopbackError> {
        let mut driver = LoopbackDriver::<1>::left(16);
        let mut short = [0; 2];
        let mut full = [0; 4];

        driver.send_bytes(b"four", TimestampMs(1))?;
        assert_eq!(
            driver.poll_frame(TimestampMs(2), &mut short),
            Err(LoopbackError::OutputTooSmall {
                actual: 2,
                required: 4,
            })
        );
        assert_eq!(driver.queued_len(LOOPBACK_RIGHT_ID)?, 1);
        let frame =
            driver
                .poll_frame(TimestampMs(3), &mut full)?
                .ok_or(LoopbackError::QueueFull {
                    link_id: LOOPBACK_RIGHT_ID,
                    capacity: 1,
                })?;
        assert_eq!(frame.received_at_ms, TimestampMs(1));
        assert_eq!(frame.bytes, b"four");
        Ok(())
    }

    #[test]
    fn loopback_driver_reports_down_mtu_and_queue_errors() -> Result<(), LoopbackError> {
        let mut driver = LoopbackDriver::<1>::left(3);

        assert_eq!(
            driver.send_bytes(b"four", TimestampMs(1)),
            Err(LoopbackError::FrameTooLarge { actual: 4, mtu: 3 })
        );

        driver.send_bytes(b"one", TimestampMs(1))?;
        assert_eq!(
            driver.send_bytes(b"two", TimestampMs(2)),
            Err(LoopbackError::QueueFull {
                link_id: LOOPBACK_RIGHT_ID,
                capacity: 1,
            })
        );

        assert_eq!(
            driver.set_link_up(LOOPBACK_LEFT_ID, false)?,
            LinkEvent::Down {
                link_id: LOOPBACK_LEFT_ID,
            }
        );
        assert!(!driver.is_up());
        assert_eq!(
            driver.send_bytes(b"two", TimestampMs(2)),
            Err(LoopbackError::Down {
                link_id: LOOPBACK_LEFT_ID,
            })
        );
        Ok(())
    }

    #[test]
    fn loopback_driver_can_send_from_either_link_id() -> Result<(), LoopbackError> {
        let mut driver = LoopbackDriver::<2>::left(16);
        let mut left_output = [0; 8];
        let mut right_output = [0; 8];

        driver.send_link_bytes(LOOPBACK_RIGHT_ID, b"left", TimestampMs(4))?;
        assert_eq!(
            driver
                .receive_link_frame(LOOPBACK_LEFT_ID, &mut left_output)?
                .map(|frame| frame.bytes),
            Some(&b"left"[..])
        );

        driver.send_link_bytes(LOOPBACK_LEFT_ID, b"right", TimestampMs(5))?;
        assert_eq!(
            driver
                .receive_link_frame(LOOPBACK_RIGHT_ID, &mut right_output)?
                .map(|frame| frame.bytes),
            Some(&b"right"[..])
        );
        Ok(())
    }

    #[test]
    fn loopback_driver_debug_redacts_payload_bytes() -> Result<(), LoopbackError> {
        let mut driver = LoopbackDriver::<1>::left(16);

        driver.send_bytes(b"secret", TimestampMs(1))?;
        let debug = format!("{driver:?}");

        assert!(debug.contains("LoopbackDriver"));
        assert!(debug.contains("rx_queued"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }

    #[test]
    fn send_command_delivers_to_peer_fifo() -> Result<(), LoopbackError> {
        let mut pair = LoopbackPair::<2>::new(256);
        let (left, right) = pair.split();
        let mut output = [0; 16];

        left.send_command_to(
            right,
            LinkCommand::send(LOOPBACK_LEFT_ID, b"one"),
            TimestampMs(10),
        )?;
        left.send_bytes_to(right, b"two", TimestampMs(11))?;

        let first = right
            .receive_into(&mut output)?
            .ok_or(LoopbackError::QueueFull {
                link_id: LOOPBACK_RIGHT_ID,
                capacity: 2,
            })?;
        assert_eq!(first.link_id, LOOPBACK_RIGHT_ID);
        assert_eq!(first.received_at_ms, TimestampMs(10));
        assert_eq!(first.bytes, b"one");

        let second = right
            .receive_into(&mut output)?
            .ok_or(LoopbackError::QueueFull {
                link_id: LOOPBACK_RIGHT_ID,
                capacity: 2,
            })?;
        assert_eq!(second.bytes, b"two");
        assert_eq!(right.receive_into(&mut output)?, None);
        Ok(())
    }

    #[test]
    fn loopback_enforces_up_down_mtu_and_queue_capacity() -> Result<(), LoopbackError> {
        let mut pair = LoopbackPair::<1>::new(3);
        let (left, right) = pair.split();

        assert_eq!(
            left.send_bytes_to(right, b"four", TimestampMs(1)),
            Err(LoopbackError::FrameTooLarge { actual: 4, mtu: 3 })
        );
        assert_eq!(
            left.send_command_to(
                right,
                LinkCommand::send(LinkId([9; 16]), b"one"),
                TimestampMs(1),
            ),
            Err(LoopbackError::LinkMismatch {
                expected: LOOPBACK_LEFT_ID,
                actual: LinkId([9; 16]),
            })
        );

        left.send_bytes_to(right, b"one", TimestampMs(1))?;
        assert_eq!(
            left.send_bytes_to(right, b"two", TimestampMs(2)),
            Err(LoopbackError::QueueFull {
                link_id: LOOPBACK_RIGHT_ID,
                capacity: 1,
            })
        );

        assert_eq!(
            left.set_up(false),
            LinkEvent::Down {
                link_id: LOOPBACK_LEFT_ID,
            }
        );
        assert_eq!(
            left.send_bytes_to(right, b"two", TimestampMs(2)),
            Err(LoopbackError::Down {
                link_id: LOOPBACK_LEFT_ID,
            })
        );
        Ok(())
    }

    #[test]
    fn receive_reports_short_output_without_dequeueing() -> Result<(), LoopbackError> {
        let mut pair = LoopbackPair::<1>::new(16);
        let (left, right) = pair.split();
        let mut short = [0; 2];
        let mut full = [0; 4];

        left.send_bytes_to(right, b"four", TimestampMs(1))?;
        assert_eq!(
            right.receive_into(&mut short),
            Err(LoopbackError::OutputTooSmall {
                actual: 2,
                required: 4,
            })
        );
        assert_eq!(
            right.receive_into(&mut full)?.map(|frame| frame.bytes),
            Some(&b"four"[..])
        );
        Ok(())
    }

    #[test]
    fn loopback_rejects_frames_above_internal_maximum() {
        let left = LoopbackEndpoint::<1>::new(LOOPBACK_LEFT_ID, LOOPBACK_MAX_FRAME_LEN + 1);
        let mut right = LoopbackEndpoint::<1>::new(LOOPBACK_RIGHT_ID, LOOPBACK_MAX_FRAME_LEN + 1);
        let oversized = [0; LOOPBACK_MAX_FRAME_LEN + 1];

        assert_eq!(
            left.send_bytes_to(&mut right, &oversized, TimestampMs(1)),
            Err(LoopbackError::InternalFrameTooLarge {
                actual: LOOPBACK_MAX_FRAME_LEN + 1,
                maximum: LOOPBACK_MAX_FRAME_LEN,
            })
        );
    }

    #[test]
    fn debug_redacts_internal_queue_bytes() -> Result<(), LoopbackError> {
        let mut pair = LoopbackPair::<1>::new(16);
        let (left, right) = pair.split();

        left.send_bytes_to(right, b"secret", TimestampMs(1))?;
        let debug = format!("{right:?}");

        assert!(debug.contains("LoopbackEndpoint"));
        assert!(debug.contains("queued"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }
}
