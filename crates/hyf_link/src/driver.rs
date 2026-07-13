use hyf_core::TimestampMs;

use crate::{LinkClass, LinkFrameRef, LinkId};

pub trait LinkDriver {
    type Error;

    fn link_id(&self) -> LinkId;
    fn link_class(&self) -> LinkClass;
    fn mtu(&self) -> usize;
    fn is_up(&self) -> bool;

    fn send_bytes(&mut self, bytes: &[u8], now_ms: TimestampMs) -> Result<(), Self::Error>;

    fn poll_frame<'a>(
        &mut self,
        now_ms: TimestampMs,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkDriverErrorKind {
    LinkDown,
    Backpressure,
    TransientSend,
    TransientReceive,
    OutputTooSmall,
    FrameTooLarge,
    Protocol,
    Unsupported,
    Fatal,
}

impl LinkDriverErrorKind {
    pub const fn is_recoverable(self) -> bool {
        matches!(
            self,
            Self::LinkDown
                | Self::Backpressure
                | Self::TransientSend
                | Self::TransientReceive
                | Self::OutputTooSmall
        )
    }

    pub const fn is_recoverable_send_failure(self) -> bool {
        matches!(
            self,
            Self::LinkDown | Self::Backpressure | Self::TransientSend
        )
    }
}

pub trait LinkDriverError {
    fn driver_error_kind(&self) -> LinkDriverErrorKind;
}

#[cfg(test)]
mod tests {
    use hyf_core::TimestampMs;

    use super::{LinkDriver, LinkDriverError, LinkDriverErrorKind};
    use crate::{LinkClass, LinkFrameRef, LinkId};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FixedDriverError {
        Down,
    }

    impl LinkDriverError for FixedDriverError {
        fn driver_error_kind(&self) -> LinkDriverErrorKind {
            match self {
                Self::Down => LinkDriverErrorKind::LinkDown,
            }
        }
    }

    struct FixedDriver {
        up: bool,
    }

    impl LinkDriver for FixedDriver {
        type Error = FixedDriverError;

        fn link_id(&self) -> LinkId {
            LinkId([8; 16])
        }

        fn link_class(&self) -> LinkClass {
            LinkClass::Loopback
        }

        fn mtu(&self) -> usize {
            32
        }

        fn is_up(&self) -> bool {
            self.up
        }

        fn send_bytes(&mut self, _bytes: &[u8], _now_ms: TimestampMs) -> Result<(), Self::Error> {
            if self.up {
                Ok(())
            } else {
                Err(FixedDriverError::Down)
            }
        }

        fn poll_frame<'a>(
            &mut self,
            now_ms: TimestampMs,
            output: &'a mut [u8],
        ) -> Result<Option<LinkFrameRef<'a>>, Self::Error> {
            if !self.up {
                return Err(FixedDriverError::Down);
            }
            Ok(Some(LinkFrameRef::new(
                self.link_id(),
                now_ms,
                &output[..0],
            )))
        }
    }

    #[test]
    fn link_driver_trait_is_synchronous_and_borrowed() -> Result<(), FixedDriverError> {
        let mut driver = FixedDriver { up: true };
        let mut output = [0; 8];

        assert_eq!(driver.link_id(), LinkId([8; 16]));
        assert_eq!(driver.link_class(), LinkClass::Loopback);
        assert_eq!(driver.mtu(), 32);
        assert!(driver.is_up());

        driver.send_bytes(b"abc", TimestampMs(1))?;
        let frame = driver
            .poll_frame(TimestampMs(7), &mut output)?
            .ok_or(FixedDriverError::Down)?;

        assert_eq!(frame.link_id, LinkId([8; 16]));
        assert_eq!(frame.received_at_ms, TimestampMs(7));
        assert_eq!(frame.bytes, b"");
        Ok(())
    }

    #[test]
    fn driver_error_kinds_classify_recoverable_send_failures() {
        assert!(LinkDriverErrorKind::LinkDown.is_recoverable());
        assert!(LinkDriverErrorKind::Backpressure.is_recoverable());
        assert!(LinkDriverErrorKind::TransientSend.is_recoverable_send_failure());
        assert!(!LinkDriverErrorKind::FrameTooLarge.is_recoverable_send_failure());
        assert!(!LinkDriverErrorKind::Protocol.is_recoverable());
        assert_eq!(
            FixedDriverError::Down.driver_error_kind(),
            LinkDriverErrorKind::LinkDown
        );
    }
}
