use crate::{
    RNODE_BANDWIDTH_MAX_HZ, RNODE_BANDWIDTH_MIN_HZ, RNODE_CODING_RATE_MAX, RNODE_CODING_RATE_MIN,
    RNODE_FREQUENCY_MAX_HZ, RNODE_FREQUENCY_MIN_HZ, RNODE_SPREADING_FACTOR_MAX,
    RNODE_SPREADING_FACTOR_MIN, RNODE_TX_POWER_MAX_DBM, RNodeError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeConfig {
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    pub tx_power_dbm: u8,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub flow_control: bool,
}

pub fn validate_config(config: &RNodeConfig) -> Result<(), RNodeError> {
    validate_frequency_hz(config.frequency_hz)?;
    validate_bandwidth_hz(config.bandwidth_hz)?;
    validate_tx_power_dbm(config.tx_power_dbm)?;
    validate_spreading_factor(config.spreading_factor)?;
    validate_coding_rate(config.coding_rate)?;
    Ok(())
}

pub fn validate_frequency_hz(value: u32) -> Result<(), RNodeError> {
    if (RNODE_FREQUENCY_MIN_HZ..=RNODE_FREQUENCY_MAX_HZ).contains(&value) {
        Ok(())
    } else {
        Err(RNodeError::InvalidFrequencyHz {
            actual: value,
            minimum: RNODE_FREQUENCY_MIN_HZ,
            maximum: RNODE_FREQUENCY_MAX_HZ,
        })
    }
}

pub fn validate_bandwidth_hz(value: u32) -> Result<(), RNodeError> {
    if (RNODE_BANDWIDTH_MIN_HZ..=RNODE_BANDWIDTH_MAX_HZ).contains(&value) {
        Ok(())
    } else {
        Err(RNodeError::InvalidBandwidthHz {
            actual: value,
            minimum: RNODE_BANDWIDTH_MIN_HZ,
            maximum: RNODE_BANDWIDTH_MAX_HZ,
        })
    }
}

pub fn validate_tx_power_dbm(value: u8) -> Result<(), RNodeError> {
    if value <= RNODE_TX_POWER_MAX_DBM {
        Ok(())
    } else {
        Err(RNodeError::InvalidTxPowerDbm {
            actual: value,
            maximum: RNODE_TX_POWER_MAX_DBM,
        })
    }
}

pub fn validate_spreading_factor(value: u8) -> Result<(), RNodeError> {
    if (RNODE_SPREADING_FACTOR_MIN..=RNODE_SPREADING_FACTOR_MAX).contains(&value) {
        Ok(())
    } else {
        Err(RNodeError::InvalidSpreadingFactor {
            actual: value,
            minimum: RNODE_SPREADING_FACTOR_MIN,
            maximum: RNODE_SPREADING_FACTOR_MAX,
        })
    }
}

pub fn validate_coding_rate(value: u8) -> Result<(), RNodeError> {
    if (RNODE_CODING_RATE_MIN..=RNODE_CODING_RATE_MAX).contains(&value) {
        Ok(())
    } else {
        Err(RNodeError::InvalidCodingRate {
            actual: value,
            minimum: RNODE_CODING_RATE_MIN,
            maximum: RNODE_CODING_RATE_MAX,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{RNodeConfig, validate_config};
    use crate::RNodeError;

    #[test]
    fn validates_reticulum_compatible_config_boundaries() {
        assert!(
            validate_config(&RNodeConfig {
                frequency_hz: 137_000_000,
                bandwidth_hz: 7_800,
                tx_power_dbm: 0,
                spreading_factor: 5,
                coding_rate: 5,
                flow_control: false,
            })
            .is_ok()
        );
        assert!(
            validate_config(&RNodeConfig {
                frequency_hz: 3_000_000_000,
                bandwidth_hz: 1_625_000,
                tx_power_dbm: 37,
                spreading_factor: 12,
                coding_rate: 8,
                flow_control: true,
            })
            .is_ok()
        );
    }

    #[test]
    fn rejects_invalid_config_values() {
        assert!(matches!(
            validate_config(&RNodeConfig {
                frequency_hz: 136_999_999,
                bandwidth_hz: 125_000,
                tx_power_dbm: 22,
                spreading_factor: 7,
                coding_rate: 5,
                flow_control: true,
            }),
            Err(RNodeError::InvalidFrequencyHz { .. })
        ));
        assert!(matches!(
            validate_config(&RNodeConfig {
                frequency_hz: 915_000_000,
                bandwidth_hz: 7_799,
                tx_power_dbm: 22,
                spreading_factor: 7,
                coding_rate: 5,
                flow_control: true,
            }),
            Err(RNodeError::InvalidBandwidthHz { .. })
        ));
        assert!(matches!(
            validate_config(&RNodeConfig {
                frequency_hz: 915_000_000,
                bandwidth_hz: 125_000,
                tx_power_dbm: 38,
                spreading_factor: 7,
                coding_rate: 5,
                flow_control: true,
            }),
            Err(RNodeError::InvalidTxPowerDbm { .. })
        ));
    }
}
