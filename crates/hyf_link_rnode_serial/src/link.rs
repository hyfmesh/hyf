use core::fmt;

use hyf_link_rnode::RNodeState;

use crate::{RNodeSerialConfig, RNodeSerialError, SerialIo};

pub struct RNodeSerialLink<Io, const FRAME_MAX: usize> {
    config: RNodeSerialConfig,
    io: Io,
    state: RNodeState,
}

impl<Io, const FRAME_MAX: usize> fmt::Debug for RNodeSerialLink<Io, FRAME_MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RNodeSerialLink")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("frame_max", &FRAME_MAX)
            .finish_non_exhaustive()
    }
}

impl<Io, const FRAME_MAX: usize> RNodeSerialLink<Io, FRAME_MAX>
where
    Io: SerialIo,
{
    pub fn new(config: RNodeSerialConfig, io: Io) -> Result<Self, RNodeSerialError> {
        config.validate()?;
        if config.mtu > FRAME_MAX {
            return Err(RNodeSerialError::InvalidFrameCapacity {
                mtu: config.mtu,
                capacity: FRAME_MAX,
            });
        }

        Ok(Self {
            config,
            io,
            state: RNodeState::new(config.flow_control),
        })
    }

    pub fn config(&self) -> RNodeSerialConfig {
        self.config
    }

    pub fn state(&self) -> RNodeState {
        self.state
    }

    pub fn io(&self) -> &Io {
        &self.io
    }

    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }
}

#[cfg(test)]
mod tests {
    use hyf_link::LinkId;

    use super::RNodeSerialLink;
    use crate::{FakeSerial, RNodeDataMode, RNodeSerialConfig, RNodeSerialError};

    type TestLink = RNodeSerialLink<FakeSerial<16, 16>, 8>;

    #[test]
    fn link_constructs_with_config_io_and_state() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope);
        let link = TestLink::new(config, FakeSerial::new())?;

        assert_eq!(link.config(), config);
        assert!(!link.state().can_transmit());
        assert_eq!(link.io().written(), b"");
        Ok(())
    }

    #[test]
    fn link_rejects_mtu_larger_than_frame_capacity() {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 9, RNodeDataMode::HyfEnvelope);

        assert_eq!(
            TestLink::new(config, FakeSerial::new()).map(|_| ()),
            Err(RNodeSerialError::InvalidFrameCapacity {
                mtu: 9,
                capacity: 8,
            })
        );
    }

    #[test]
    fn link_debug_redacts_io() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([1; 16]), 8, RNodeDataMode::HyfEnvelope);
        let mut io = FakeSerial::<16, 16>::new();
        io.push_read_bytes(b"secret")?;
        let link = TestLink::new(config, io)?;
        let debug = format!("{link:?}");

        assert!(debug.contains("RNodeSerialLink"));
        assert!(debug.contains("frame_max"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
        Ok(())
    }
}
