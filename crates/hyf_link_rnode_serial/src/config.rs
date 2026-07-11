use hyf_link::LinkId;

use crate::RNodeSerialError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeSerialConfig {
    pub link_id: LinkId,
    pub mtu: usize,
    pub flow_control: bool,
    pub data_mode: RNodeDataMode,
}

impl RNodeSerialConfig {
    pub const fn new(link_id: LinkId, mtu: usize, data_mode: RNodeDataMode) -> Self {
        Self {
            link_id,
            mtu,
            flow_control: true,
            data_mode,
        }
    }

    pub const fn without_flow_control(mut self) -> Self {
        self.flow_control = false;
        self
    }

    pub fn validate(&self) -> Result<(), RNodeSerialError> {
        if self.mtu == 0 {
            return Err(RNodeSerialError::InvalidMtu { mtu: self.mtu });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeDataMode {
    HyfEnvelope,
    RawRnsPacket,
}

#[cfg(test)]
mod tests {
    use hyf_link::LinkId;

    use super::{RNodeDataMode, RNodeSerialConfig};
    use crate::RNodeSerialError;

    #[test]
    fn config_preserves_link_id_mtu_and_mode() -> Result<(), RNodeSerialError> {
        let config = RNodeSerialConfig::new(LinkId([7; 16]), 256, RNodeDataMode::HyfEnvelope);

        config.validate()?;
        assert_eq!(config.link_id, LinkId([7; 16]));
        assert_eq!(config.mtu, 256);
        assert_eq!(config.data_mode, RNodeDataMode::HyfEnvelope);
        assert!(config.flow_control);
        Ok(())
    }

    #[test]
    fn config_rejects_zero_mtu_and_exposes_explicit_modes() {
        let bad = RNodeSerialConfig::new(LinkId([7; 16]), 0, RNodeDataMode::RawRnsPacket);

        assert_eq!(bad.validate(), Err(RNodeSerialError::InvalidMtu { mtu: 0 }));
        assert_eq!(
            RNodeSerialConfig::new(LinkId([7; 16]), 256, RNodeDataMode::RawRnsPacket).data_mode,
            RNodeDataMode::RawRnsPacket
        );
    }

    #[test]
    fn flow_control_can_be_disabled_explicitly() {
        let config = RNodeSerialConfig::new(LinkId([7; 16]), 256, RNodeDataMode::HyfEnvelope)
            .without_flow_control();

        assert!(!config.flow_control);
    }
}
