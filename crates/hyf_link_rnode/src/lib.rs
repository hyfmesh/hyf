#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

mod command;
mod config;
mod constants;
mod error;
mod state;

pub use command::{
    RNodeCommand, RNodeConfigReport, RNodeEvent, RNodeFirmwareVersion, RNodeHardwareError,
    RNodeRadioState, RNodeStat, encode_command, parse_command_frame,
};
pub use config::{
    RNodeConfig, validate_bandwidth_hz, validate_coding_rate, validate_config,
    validate_frequency_hz, validate_spreading_factor, validate_tx_power_dbm,
};
pub use constants::{
    RNODE_BANDWIDTH_MAX_HZ, RNODE_BANDWIDTH_MIN_HZ, RNODE_CMD_BANDWIDTH, RNODE_CMD_CR,
    RNODE_CMD_DATA, RNODE_CMD_DETECT, RNODE_CMD_ERROR, RNODE_CMD_FREQUENCY, RNODE_CMD_FW_VERSION,
    RNODE_CMD_LEAVE, RNODE_CMD_MCU, RNODE_CMD_PLATFORM, RNODE_CMD_RADIO_STATE, RNODE_CMD_READY,
    RNODE_CMD_SF, RNODE_CMD_STAT_RSSI, RNODE_CMD_STAT_RX, RNODE_CMD_STAT_SNR, RNODE_CMD_STAT_TX,
    RNODE_CMD_TXPOWER, RNODE_CODING_RATE_MAX, RNODE_CODING_RATE_MIN, RNODE_DETECT_REQUEST,
    RNODE_ERROR_EEPROM_LOCKED, RNODE_ERROR_INITRADIO, RNODE_ERROR_MEMORY_LOW,
    RNODE_ERROR_MODEM_TIMEOUT, RNODE_ERROR_QUEUE_FULL, RNODE_ERROR_TXFAILED,
    RNODE_FREQUENCY_MAX_HZ, RNODE_FREQUENCY_MIN_HZ, RNODE_HIL_MANIFEST_SCHEMA, RNODE_LEAVE_REQUEST,
    RNODE_RADIO_STATE_ASK, RNODE_RADIO_STATE_OFF, RNODE_RADIO_STATE_ON, RNODE_REQUIRED_FW_MAJOR,
    RNODE_REQUIRED_FW_MINOR, RNODE_RSSI_OFFSET, RNODE_SPREADING_FACTOR_MAX,
    RNODE_SPREADING_FACTOR_MIN, RNODE_TX_POWER_MAX_DBM,
};
pub use error::RNodeError;
pub use state::RNodeState;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
