use core::fmt;

use crate::{FipsDatagramRecord, FipsDatagramRef, FipsEndpoint, FipsError};

#[derive(Clone, Eq, PartialEq)]
pub struct FakeFipsSidecar<const PEERS: usize, const QUEUE: usize, const FRAME_MAX: usize> {
    local_endpoint: FipsEndpoint,
    peers: [Option<FipsEndpoint>; PEERS],
    outbound: [Option<FipsDatagramRecord<FRAME_MAX>>; QUEUE],
    inbound: [Option<FipsDatagramRecord<FRAME_MAX>>; QUEUE],
    up: bool,
    mtu: usize,
    outbound_len: usize,
    inbound_len: usize,
}

impl<const PEERS: usize, const QUEUE: usize, const FRAME_MAX: usize> fmt::Debug
    for FakeFipsSidecar<PEERS, QUEUE, FRAME_MAX>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeFipsSidecar")
            .field("local_endpoint", &self.local_endpoint)
            .field("up", &self.up)
            .field("mtu", &self.mtu)
            .field("peer_count", &self.peer_count())
            .field("peer_capacity", &PEERS)
            .field("outbound_len", &self.outbound_len)
            .field("inbound_len", &self.inbound_len)
            .field("queue_capacity", &QUEUE)
            .field("frame_max", &FRAME_MAX)
            .finish()
    }
}

impl<const PEERS: usize, const QUEUE: usize, const FRAME_MAX: usize>
    FakeFipsSidecar<PEERS, QUEUE, FRAME_MAX>
{
    pub fn new(local_endpoint: FipsEndpoint, mtu: usize) -> Result<Self, FipsError> {
        local_endpoint.validate()?;
        if mtu > FRAME_MAX {
            return Err(FipsError::FrameTooLarge {
                len: mtu,
                mtu: FRAME_MAX,
            });
        }

        Ok(Self {
            local_endpoint,
            peers: [None; PEERS],
            outbound: [const { None }; QUEUE],
            inbound: [const { None }; QUEUE],
            up: true,
            mtu,
            outbound_len: 0,
            inbound_len: 0,
        })
    }

    pub fn set_up(&mut self, up: bool) {
        self.up = up;
    }

    pub const fn is_up(&self) -> bool {
        self.up
    }

    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    pub const fn local_endpoint(&self) -> FipsEndpoint {
        self.local_endpoint
    }

    pub const fn outbound_len(&self) -> usize {
        self.outbound_len
    }

    pub const fn inbound_len(&self) -> usize {
        self.inbound_len
    }

    pub fn register_peer(&mut self, endpoint: FipsEndpoint) -> Result<(), FipsError> {
        endpoint.validate()?;
        if endpoints_overlap(self.local_endpoint, endpoint)
            || self
                .peers
                .iter()
                .flatten()
                .any(|registered| endpoints_overlap(*registered, endpoint))
        {
            return Err(FipsError::DuplicatePeer);
        }

        let Some(slot) = self.peers.iter_mut().find(|slot| slot.is_none()) else {
            return Err(FipsError::PeerTableFull { capacity: PEERS });
        };
        *slot = Some(endpoint);
        Ok(())
    }

    pub fn peer_count(&self) -> usize {
        self.peers.iter().filter(|peer| peer.is_some()).count()
    }

    pub fn send_to(&mut self, destination: FipsEndpoint, bytes: &[u8]) -> Result<(), FipsError> {
        self.validate_up()?;
        if !self.has_peer(destination) {
            return Err(FipsError::UnknownPeer);
        }
        self.validate_frame_len(bytes)?;
        if self.outbound_len >= QUEUE {
            return Err(FipsError::OutboundFull { capacity: QUEUE });
        }

        let record = FipsDatagramRecord::new(self.local_endpoint, destination, bytes)?;
        enqueue(&mut self.outbound, &mut self.outbound_len, record);
        Ok(())
    }

    pub fn inject_from(&mut self, source: FipsEndpoint, bytes: &[u8]) -> Result<(), FipsError> {
        self.validate_up()?;
        if !self.has_peer(source) {
            return Err(FipsError::UnknownPeer);
        }
        self.validate_frame_len(bytes)?;
        if self.inbound_len >= QUEUE {
            return Err(FipsError::InboundFull { capacity: QUEUE });
        }

        let record = FipsDatagramRecord::new(source, self.local_endpoint, bytes)?;
        enqueue(&mut self.inbound, &mut self.inbound_len, record);
        Ok(())
    }

    pub fn poll_inbound<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<FipsDatagramRef<'a>>, FipsError> {
        poll_queue(&mut self.inbound, &mut self.inbound_len, output)
    }

    pub fn poll_outbound<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<Option<FipsDatagramRef<'a>>, FipsError> {
        poll_queue(&mut self.outbound, &mut self.outbound_len, output)
    }

    fn has_peer(&self, endpoint: FipsEndpoint) -> bool {
        self.peers.iter().flatten().any(|peer| *peer == endpoint)
    }

    fn validate_up(&self) -> Result<(), FipsError> {
        if self.up {
            Ok(())
        } else {
            Err(FipsError::LinkDown)
        }
    }

    fn validate_frame_len(&self, bytes: &[u8]) -> Result<(), FipsError> {
        if bytes.len() > self.mtu {
            Err(FipsError::FrameTooLarge {
                len: bytes.len(),
                mtu: self.mtu,
            })
        } else {
            Ok(())
        }
    }
}

fn enqueue<const QUEUE: usize, const FRAME_MAX: usize>(
    queue: &mut [Option<FipsDatagramRecord<FRAME_MAX>>; QUEUE],
    len: &mut usize,
    record: FipsDatagramRecord<FRAME_MAX>,
) {
    queue[*len] = Some(record);
    *len += 1;
}

fn poll_queue<'a, const QUEUE: usize, const FRAME_MAX: usize>(
    queue: &mut [Option<FipsDatagramRecord<FRAME_MAX>>; QUEUE],
    len: &mut usize,
    output: &'a mut [u8],
) -> Result<Option<FipsDatagramRef<'a>>, FipsError> {
    if *len == 0 {
        return Ok(None);
    }

    let Some(record) = queue[0] else {
        *len = 0;
        return Ok(None);
    };
    if output.len() < record.len() {
        return Err(FipsError::OutputTooSmall {
            needed: record.len(),
            available: output.len(),
        });
    }

    let record_len = record.len();
    let source = record.source();
    let destination = record.destination();
    output[..record_len].copy_from_slice(record.bytes());
    shift_queue(queue, len);
    Ok(Some(FipsDatagramRef {
        source,
        destination,
        bytes: &output[..record_len],
    }))
}

fn shift_queue<const QUEUE: usize, const FRAME_MAX: usize>(
    queue: &mut [Option<FipsDatagramRecord<FRAME_MAX>>; QUEUE],
    len: &mut usize,
) {
    if *len == 0 {
        return;
    }
    for index in 1..*len {
        queue[index - 1] = queue[index];
    }
    *len -= 1;
    queue[*len] = None;
}

fn endpoints_overlap(left: FipsEndpoint, right: FipsEndpoint) -> bool {
    left.public_key() == right.public_key()
        || left.node_addr() == right.node_addr()
        || left.ipv6_addr() == right.ipv6_addr()
}

#[cfg(test)]
mod tests {
    use super::FakeFipsSidecar;
    use crate::{FipsEndpoint, FipsError, FipsPublicKey};

    fn endpoint(seed: u8) -> FipsEndpoint {
        FipsEndpoint::from_public_key(FipsPublicKey::from_bytes([seed; 32]))
    }

    fn sidecar() -> Result<FakeFipsSidecar<2, 2, 8>, FipsError> {
        let mut sidecar = FakeFipsSidecar::new(endpoint(1), 8)?;
        sidecar.register_peer(endpoint(2))?;
        Ok(sidecar)
    }

    #[test]
    fn fake_sidecar_registers_peers_and_rejects_duplicates() -> Result<(), FipsError> {
        let mut sidecar = FakeFipsSidecar::<2, 2, 8>::new(endpoint(1), 8)?;
        sidecar.register_peer(endpoint(2))?;

        assert_eq!(sidecar.peer_count(), 1);
        assert_eq!(
            sidecar.register_peer(endpoint(2)),
            Err(FipsError::DuplicatePeer)
        );
        assert_eq!(
            sidecar.register_peer(endpoint(1)),
            Err(FipsError::DuplicatePeer)
        );
        Ok(())
    }

    #[test]
    fn fake_sidecar_rejects_peer_table_overflow() -> Result<(), FipsError> {
        let mut sidecar = FakeFipsSidecar::<1, 1, 8>::new(endpoint(1), 8)?;
        sidecar.register_peer(endpoint(2))?;

        assert_eq!(
            sidecar.register_peer(endpoint(3)),
            Err(FipsError::PeerTableFull { capacity: 1 })
        );
        Ok(())
    }

    #[test]
    fn fake_sidecar_link_down_blocks_send_and_inject() -> Result<(), FipsError> {
        let mut sidecar = sidecar()?;
        sidecar.set_up(false);

        assert_eq!(
            sidecar.send_to(endpoint(2), b"ok"),
            Err(FipsError::LinkDown)
        );
        assert_eq!(
            sidecar.inject_from(endpoint(2), b"ok"),
            Err(FipsError::LinkDown)
        );
        Ok(())
    }

    #[test]
    fn fake_sidecar_rejects_unknown_peers() -> Result<(), FipsError> {
        let mut sidecar = sidecar()?;

        assert_eq!(
            sidecar.send_to(endpoint(3), b"ok"),
            Err(FipsError::UnknownPeer)
        );
        assert_eq!(
            sidecar.inject_from(endpoint(3), b"ok"),
            Err(FipsError::UnknownPeer)
        );
        Ok(())
    }

    #[test]
    fn fake_sidecar_enforces_mtu_and_queue_limits() -> Result<(), FipsError> {
        let mut sidecar = FakeFipsSidecar::<1, 1, 8>::new(endpoint(1), 3)?;
        sidecar.register_peer(endpoint(2))?;

        assert_eq!(
            sidecar.send_to(endpoint(2), b"four"),
            Err(FipsError::FrameTooLarge { len: 4, mtu: 3 })
        );
        sidecar.send_to(endpoint(2), b"one")?;
        assert_eq!(
            sidecar.send_to(endpoint(2), b"two"),
            Err(FipsError::OutboundFull { capacity: 1 })
        );
        assert_eq!(sidecar.outbound_len(), 1);
        Ok(())
    }

    #[test]
    fn fake_sidecar_polls_outbound_fifo_and_retries_short_output() -> Result<(), FipsError> {
        let mut sidecar = sidecar()?;
        let mut short = [0; 2];
        let mut output = [0; 5];

        sidecar.send_to(endpoint(2), b"one")?;
        sidecar.send_to(endpoint(2), b"two")?;
        assert_eq!(
            sidecar.poll_outbound(&mut short),
            Err(FipsError::OutputTooSmall {
                needed: 3,
                available: 2
            })
        );
        assert_eq!(sidecar.outbound_len(), 2);

        let first = sidecar
            .poll_outbound(&mut output)?
            .ok_or(FipsError::UnknownPeer)?;
        assert_eq!(first.source, endpoint(1));
        assert_eq!(first.destination, endpoint(2));
        assert_eq!(first.bytes, b"one");

        let second = sidecar
            .poll_outbound(&mut output)?
            .ok_or(FipsError::UnknownPeer)?;
        assert_eq!(second.bytes, b"two");
        assert_eq!(sidecar.poll_outbound(&mut output)?, None);
        Ok(())
    }

    #[test]
    fn fake_sidecar_polls_inbound_fifo_and_retries_short_output() -> Result<(), FipsError> {
        let mut sidecar = sidecar()?;
        let mut short = [0; 1];
        let mut output = [0; 5];

        sidecar.inject_from(endpoint(2), b"in")?;
        assert_eq!(
            sidecar.poll_inbound(&mut short),
            Err(FipsError::OutputTooSmall {
                needed: 2,
                available: 1
            })
        );
        assert_eq!(sidecar.inbound_len(), 1);

        let frame = sidecar
            .poll_inbound(&mut output)?
            .ok_or(FipsError::UnknownPeer)?;
        assert_eq!(frame.source, endpoint(2));
        assert_eq!(frame.destination, endpoint(1));
        assert_eq!(frame.bytes, b"in");
        assert_eq!(sidecar.poll_inbound(&mut output)?, None);
        Ok(())
    }

    #[test]
    fn fake_sidecar_debug_redacts_payload_bytes() -> Result<(), FipsError> {
        let mut sidecar = sidecar()?;
        sidecar.send_to(endpoint(2), b"secret")?;
        let debug = format!("{sidecar:?}");

        assert!(debug.contains("FakeFipsSidecar"));
        assert!(debug.contains("outbound_len"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115"));
        Ok(())
    }
}
