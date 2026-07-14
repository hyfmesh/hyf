use core::fmt;

use hyf_core::TimestampMs;
use hyf_link::{Link, LinkClass, LinkDriverErrorKind, LinkFrameRef, LinkId};
use hyf_link_fips::{FakeFipsSidecar, FipsDatagramRef, FipsEndpoint, FipsError};

use crate::{GatewayError, GatewayLinkExecutor};

pub trait FipsGatewaySidecarDriver {
    fn local_endpoint(&self) -> FipsEndpoint;
    fn mtu(&self) -> usize;
    fn has_peer(&self, endpoint: FipsEndpoint) -> bool;
    fn set_up(&mut self, up: bool);
    fn send_to(&mut self, destination: FipsEndpoint, bytes: &[u8]) -> Result<(), FipsError>;
    fn poll_inbound<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<FipsDatagramRef<'a>>, FipsError>;
}

impl<const PEERS: usize, const QUEUE: usize, const FRAME_MAX: usize> FipsGatewaySidecarDriver
    for FakeFipsSidecar<PEERS, QUEUE, FRAME_MAX>
{
    fn local_endpoint(&self) -> FipsEndpoint {
        FakeFipsSidecar::local_endpoint(self)
    }

    fn mtu(&self) -> usize {
        FakeFipsSidecar::mtu(self)
    }

    fn has_peer(&self, endpoint: FipsEndpoint) -> bool {
        FakeFipsSidecar::has_peer(self, endpoint)
    }

    fn set_up(&mut self, up: bool) {
        FakeFipsSidecar::set_up(self, up);
    }

    fn send_to(&mut self, destination: FipsEndpoint, bytes: &[u8]) -> Result<(), FipsError> {
        FakeFipsSidecar::send_to(self, destination, bytes)
    }

    fn poll_inbound<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<FipsDatagramRef<'a>>, FipsError> {
        FakeFipsSidecar::poll_inbound(self, output)
    }
}

pub struct FipsGatewayExecutor<S> {
    link_id: LinkId,
    local_endpoint: FipsEndpoint,
    remote_endpoint: FipsEndpoint,
    sidecar: S,
    mtu: usize,
    up: bool,
}

impl<S> FipsGatewayExecutor<S> {
    pub const fn link_id(&self) -> LinkId {
        self.link_id
    }

    pub const fn link_class(&self) -> LinkClass {
        LinkClass::Fips
    }

    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    pub const fn is_up(&self) -> bool {
        self.up
    }

    pub const fn local_endpoint(&self) -> FipsEndpoint {
        self.local_endpoint
    }

    pub const fn remote_endpoint(&self) -> FipsEndpoint {
        self.remote_endpoint
    }

    pub const fn sidecar(&self) -> &S {
        &self.sidecar
    }

    pub fn sidecar_mut(&mut self) -> &mut S {
        &mut self.sidecar
    }

    pub fn into_sidecar(self) -> S {
        self.sidecar
    }
}

impl<S> FipsGatewayExecutor<S>
where
    S: FipsGatewaySidecarDriver,
{
    pub fn new(
        link_id: LinkId,
        local_endpoint: FipsEndpoint,
        remote_endpoint: FipsEndpoint,
        sidecar: S,
        mtu: usize,
    ) -> Result<Self, GatewayError> {
        let executor = Self {
            link_id,
            local_endpoint,
            remote_endpoint,
            sidecar,
            mtu,
            up: false,
        };
        executor.validate()?;
        Ok(executor)
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        self.local_endpoint
            .validate()
            .map_err(|error| map_fips_send_error(self.link_id, error))?;
        self.remote_endpoint
            .validate()
            .map_err(|error| map_fips_send_error(self.link_id, error))?;
        if self.mtu == 0
            || self.sidecar.local_endpoint() != self.local_endpoint
            || self.mtu > self.sidecar.mtu()
            || !self.sidecar.has_peer(self.remote_endpoint)
        {
            return Err(gateway_protocol_error(self.link_id));
        }
        Ok(())
    }

    pub fn set_up(&mut self, up: bool) {
        self.up = up;
        self.sidecar.set_up(up);
    }

    pub fn poll_sidecar_frame<'a>(
        &mut self,
        now_ms: TimestampMs,
        output: &'a mut [u8],
    ) -> Result<Option<LinkFrameRef<'a>>, GatewayError> {
        if !self.up {
            return Err(GatewayError::Driver {
                link_id: self.link_id,
                kind: LinkDriverErrorKind::LinkDown,
            });
        }

        let Some(datagram) = self
            .sidecar
            .poll_inbound(output)
            .map_err(|error| map_fips_receive_error(self.link_id, error))?
        else {
            return Ok(None);
        };
        if datagram.source != self.remote_endpoint || datagram.destination != self.local_endpoint {
            return Err(GatewayError::Driver {
                link_id: self.link_id,
                kind: LinkDriverErrorKind::Protocol,
            });
        }

        Ok(Some(LinkFrameRef::new(
            self.link_id,
            now_ms,
            datagram.bytes,
        )))
    }
}

impl<S> fmt::Debug for FipsGatewayExecutor<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FipsGatewayExecutor")
            .field("link_id", &self.link_id)
            .field("link_class", &LinkClass::Fips)
            .field("mtu", &self.mtu)
            .field("up", &self.up)
            .field("local_endpoint", &self.local_endpoint)
            .field("remote_endpoint", &self.remote_endpoint)
            .finish()
    }
}

impl<S> Link for FipsGatewayExecutor<S> {
    fn link_id(&self) -> LinkId {
        self.link_id
    }

    fn link_class(&self) -> LinkClass {
        LinkClass::Fips
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

impl<S> GatewayLinkExecutor for FipsGatewayExecutor<S>
where
    S: FipsGatewaySidecarDriver,
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

        self.sidecar
            .send_to(self.remote_endpoint, bytes)
            .map_err(|error| map_fips_send_error(link_id, error))
    }
}

fn map_fips_send_error(link_id: LinkId, error: FipsError) -> GatewayError {
    let kind = match error {
        FipsError::LinkDown => LinkDriverErrorKind::LinkDown,
        FipsError::OutboundFull { .. } | FipsError::InboundFull { .. } => {
            LinkDriverErrorKind::Backpressure
        }
        FipsError::FrameTooLarge { .. } => LinkDriverErrorKind::FrameTooLarge,
        FipsError::OutputTooSmall { .. } => LinkDriverErrorKind::OutputTooSmall,
        FipsError::UnknownPeer
        | FipsError::DuplicatePeer
        | FipsError::PeerTableFull { .. }
        | FipsError::InvalidEndpoint
        | FipsError::ControlResponseTooLarge { .. }
        | FipsError::MalformedControlStatus
        | FipsError::Utf8 => LinkDriverErrorKind::Protocol,
    };
    GatewayError::Driver { link_id, kind }
}

fn map_fips_receive_error(link_id: LinkId, error: FipsError) -> GatewayError {
    let kind = match error {
        FipsError::LinkDown => LinkDriverErrorKind::LinkDown,
        FipsError::OutboundFull { .. } | FipsError::InboundFull { .. } => {
            LinkDriverErrorKind::Backpressure
        }
        FipsError::OutputTooSmall { .. } => LinkDriverErrorKind::OutputTooSmall,
        FipsError::FrameTooLarge { .. }
        | FipsError::UnknownPeer
        | FipsError::DuplicatePeer
        | FipsError::PeerTableFull { .. }
        | FipsError::InvalidEndpoint
        | FipsError::ControlResponseTooLarge { .. }
        | FipsError::MalformedControlStatus
        | FipsError::Utf8 => LinkDriverErrorKind::Protocol,
    };
    GatewayError::Driver { link_id, kind }
}

fn gateway_protocol_error(link_id: LinkId) -> GatewayError {
    GatewayError::Driver {
        link_id,
        kind: LinkDriverErrorKind::Protocol,
    }
}

#[cfg(test)]
mod tests {
    use hyf_core::TimestampMs;
    use hyf_link::{Link, LinkDriverErrorKind, LinkId};
    use hyf_link_fips::{FakeFipsSidecar, FipsEndpoint, FipsPublicKey};

    use super::FipsGatewayExecutor;
    use crate::{GatewayError, GatewayLinkExecutor};

    const FIPS_LINK: LinkId = LinkId([0xf1; 16]);
    const OTHER_LINK: LinkId = LinkId([0xf2; 16]);

    type TestSidecar = FakeFipsSidecar<2, 2, 16>;
    type TestExecutor = FipsGatewayExecutor<TestSidecar>;

    #[test]
    fn fips_gateway_executor_exposes_link_metadata() -> Result<(), GatewayError> {
        let mut executor = executor(16)?;

        assert_eq!(executor.link_id(), FIPS_LINK);
        assert_eq!(Link::link_class(&executor), hyf_link::LinkClass::Fips);
        assert_eq!(executor.mtu(), 16);
        assert_eq!(executor.local_endpoint(), endpoint(1));
        assert_eq!(executor.remote_endpoint(), endpoint(2));
        assert!(!executor.is_up());
        assert_eq!(executor.validate(), Ok(()));
        executor.set_up(true);
        assert!(executor.is_up());
        assert!(executor.sidecar().is_up());
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_debug_redacts_sidecar_payloads() -> Result<(), GatewayError> {
        let mut executor = executor(16)?;
        executor.set_up(true);
        executor.send_link_bytes(FIPS_LINK, b"secret", TimestampMs(1))?;
        let debug = format!("{executor:?}");

        assert!(debug.contains("FipsGatewayExecutor"));
        assert!(debug.contains("link_id"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_rejects_unsupported_link_ids() -> Result<(), GatewayError> {
        let mut executor = executor(16)?;

        assert_eq!(
            executor.send_link_bytes(OTHER_LINK, b"frame", TimestampMs(1)),
            Err(GatewayError::UnsupportedLink {
                link_id: OTHER_LINK,
            })
        );
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_rejects_wrong_state_and_oversize_frames() -> Result<(), GatewayError> {
        let mut executor = executor(4)?;

        assert_eq!(
            executor.send_link_bytes(FIPS_LINK, b"frame", TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: FIPS_LINK,
                kind: LinkDriverErrorKind::LinkDown,
            })
        );

        executor.set_up(true);
        assert_eq!(
            executor.send_link_bytes(FIPS_LINK, b"frames", TimestampMs(1)),
            Err(GatewayError::Driver {
                link_id: FIPS_LINK,
                kind: LinkDriverErrorKind::FrameTooLarge,
            })
        );
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_sends_to_registered_remote_peer() -> Result<(), GatewayError> {
        let mut executor = executor(16)?;
        executor.set_up(true);
        executor.send_link_bytes(FIPS_LINK, b"frame", TimestampMs(1))?;

        let mut output = [0; 8];
        let datagram = executor
            .sidecar_mut()
            .poll_outbound(&mut output)
            .map_err(|error| super::map_fips_receive_error(FIPS_LINK, error))?
            .ok_or(GatewayError::Driver {
                link_id: FIPS_LINK,
                kind: LinkDriverErrorKind::Protocol,
            })?;
        assert_eq!(datagram.source, endpoint(1));
        assert_eq!(datagram.destination, endpoint(2));
        assert_eq!(datagram.bytes, b"frame");
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_rejects_missing_remote_peer() -> Result<(), GatewayError> {
        let sidecar = FakeFipsSidecar::<0, 1, 16>::new(endpoint(1), 16)
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;

        assert_constructor_protocol_error(FipsGatewayExecutor::new(
            FIPS_LINK,
            endpoint(1),
            endpoint(2),
            sidecar,
            16,
        ));
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_rejects_local_endpoint_mismatch() -> Result<(), GatewayError> {
        let mut sidecar = FakeFipsSidecar::<1, 1, 16>::new(endpoint(3), 16)
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        sidecar
            .register_peer(endpoint(2))
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;

        assert_constructor_protocol_error(FipsGatewayExecutor::new(
            FIPS_LINK,
            endpoint(1),
            endpoint(2),
            sidecar,
            16,
        ));
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_accepts_mtu_below_sidecar_mtu() -> Result<(), GatewayError> {
        let mut sidecar = FakeFipsSidecar::<1, 1, 16>::new(endpoint(1), 16)
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        sidecar
            .register_peer(endpoint(2))
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;

        let executor = FipsGatewayExecutor::new(FIPS_LINK, endpoint(1), endpoint(2), sidecar, 8)?;

        assert_eq!(executor.mtu(), 8);
        assert_eq!(executor.sidecar().mtu(), 16);
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_rejects_mtu_above_sidecar_mtu_and_zero_mtu() -> Result<(), GatewayError>
    {
        let mut sidecar = FakeFipsSidecar::<1, 1, 16>::new(endpoint(1), 8)
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        sidecar
            .register_peer(endpoint(2))
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;

        assert_constructor_protocol_error(FipsGatewayExecutor::new(
            FIPS_LINK,
            endpoint(1),
            endpoint(2),
            sidecar,
            16,
        ));

        let mut sidecar = FakeFipsSidecar::<1, 1, 16>::new(endpoint(1), 0)
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        sidecar
            .register_peer(endpoint(2))
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;

        assert_constructor_protocol_error(FipsGatewayExecutor::new(
            FIPS_LINK,
            endpoint(1),
            endpoint(2),
            sidecar,
            0,
        ));
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_maps_queue_full_to_backpressure() -> Result<(), GatewayError> {
        let mut sidecar = FakeFipsSidecar::<1, 1, 16>::new(endpoint(1), 16)
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        sidecar
            .register_peer(endpoint(2))
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        let mut executor =
            FipsGatewayExecutor::new(FIPS_LINK, endpoint(1), endpoint(2), sidecar, 16)?;
        executor.set_up(true);
        executor.send_link_bytes(FIPS_LINK, b"one", TimestampMs(1))?;

        assert_eq!(
            executor.send_link_bytes(FIPS_LINK, b"two", TimestampMs(2)),
            Err(GatewayError::Driver {
                link_id: FIPS_LINK,
                kind: LinkDriverErrorKind::Backpressure,
            })
        );
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_polls_inbound_sidecar_frames() -> Result<(), GatewayError> {
        let mut executor = executor(16)?;
        let mut output = [0; 8];
        executor.set_up(true);
        executor
            .sidecar_mut()
            .inject_from(endpoint(2), b"in")
            .map_err(|error| super::map_fips_receive_error(FIPS_LINK, error))?;

        let frame = executor
            .poll_sidecar_frame(TimestampMs(55), &mut output)?
            .ok_or(GatewayError::Driver {
                link_id: FIPS_LINK,
                kind: LinkDriverErrorKind::Protocol,
            })?;

        assert_eq!(frame.link_id, FIPS_LINK);
        assert_eq!(frame.received_at_ms, TimestampMs(55));
        assert_eq!(frame.bytes, b"in");
        Ok(())
    }

    #[test]
    fn fips_gateway_executor_preserves_inbound_on_short_output() -> Result<(), GatewayError> {
        let mut executor = executor(16)?;
        let mut short = [0; 1];
        let mut output = [0; 8];
        executor.set_up(true);
        executor
            .sidecar_mut()
            .inject_from(endpoint(2), b"in")
            .map_err(|error| super::map_fips_receive_error(FIPS_LINK, error))?;

        assert_eq!(
            executor.poll_sidecar_frame(TimestampMs(55), &mut short),
            Err(GatewayError::Driver {
                link_id: FIPS_LINK,
                kind: LinkDriverErrorKind::OutputTooSmall,
            })
        );
        assert_eq!(executor.sidecar().inbound_len(), 1);
        assert!(
            executor
                .poll_sidecar_frame(TimestampMs(56), &mut output)?
                .is_some()
        );
        Ok(())
    }

    fn executor(mtu: usize) -> Result<TestExecutor, GatewayError> {
        let mut sidecar = FakeFipsSidecar::new(endpoint(1), mtu)
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        sidecar
            .register_peer(endpoint(2))
            .map_err(|error| super::map_fips_send_error(FIPS_LINK, error))?;
        FipsGatewayExecutor::new(FIPS_LINK, endpoint(1), endpoint(2), sidecar, mtu)
    }

    fn assert_constructor_protocol_error<S>(result: Result<FipsGatewayExecutor<S>, GatewayError>) {
        assert_eq!(
            result.err(),
            Some(GatewayError::Driver {
                link_id: FIPS_LINK,
                kind: LinkDriverErrorKind::Protocol,
            })
        );
    }

    fn endpoint(seed: u8) -> FipsEndpoint {
        FipsEndpoint::from_public_key(FipsPublicKey::from_bytes([seed; 32]))
    }
}
