pub const RNODE_CMD_DATA: u8 = 0x00;
pub const RNODE_CMD_FREQUENCY: u8 = 0x01;
pub const RNODE_CMD_BANDWIDTH: u8 = 0x02;
pub const RNODE_CMD_TXPOWER: u8 = 0x03;
pub const RNODE_CMD_SF: u8 = 0x04;
pub const RNODE_CMD_CR: u8 = 0x05;
pub const RNODE_CMD_RADIO_STATE: u8 = 0x06;
pub const RNODE_CMD_DETECT: u8 = 0x08;
pub const RNODE_CMD_LEAVE: u8 = 0x0a;
pub const RNODE_CMD_READY: u8 = 0x0f;
pub const RNODE_CMD_STAT_RX: u8 = 0x21;
pub const RNODE_CMD_STAT_TX: u8 = 0x22;
pub const RNODE_CMD_STAT_RSSI: u8 = 0x23;
pub const RNODE_CMD_STAT_SNR: u8 = 0x24;
pub const RNODE_CMD_PLATFORM: u8 = 0x48;
pub const RNODE_CMD_MCU: u8 = 0x49;
pub const RNODE_CMD_FW_VERSION: u8 = 0x50;
pub const RNODE_CMD_ERROR: u8 = 0x90;

pub const RNODE_DETECT_REQUEST: u8 = 0x73;
pub const RNODE_LEAVE_REQUEST: u8 = 0xff;
pub const RNODE_RADIO_STATE_OFF: u8 = 0x00;
pub const RNODE_RADIO_STATE_ON: u8 = 0x01;
pub const RNODE_RADIO_STATE_ASK: u8 = 0xff;

pub const RNODE_ERROR_INITRADIO: u8 = 0x01;
pub const RNODE_ERROR_TXFAILED: u8 = 0x02;
pub const RNODE_ERROR_EEPROM_LOCKED: u8 = 0x03;
pub const RNODE_ERROR_QUEUE_FULL: u8 = 0x04;
pub const RNODE_ERROR_MEMORY_LOW: u8 = 0x05;
pub const RNODE_ERROR_MODEM_TIMEOUT: u8 = 0x06;

pub const RNODE_FREQUENCY_MIN_HZ: u32 = 137_000_000;
pub const RNODE_FREQUENCY_MAX_HZ: u32 = 3_000_000_000;
pub const RNODE_BANDWIDTH_MIN_HZ: u32 = 7_800;
pub const RNODE_BANDWIDTH_MAX_HZ: u32 = 1_625_000;
pub const RNODE_TX_POWER_MAX_DBM: u8 = 37;
pub const RNODE_SPREADING_FACTOR_MIN: u8 = 5;
pub const RNODE_SPREADING_FACTOR_MAX: u8 = 12;
pub const RNODE_CODING_RATE_MIN: u8 = 5;
pub const RNODE_CODING_RATE_MAX: u8 = 8;
pub const RNODE_RSSI_OFFSET: i16 = 157;
pub const RNODE_REQUIRED_FW_MAJOR: u8 = 1;
pub const RNODE_REQUIRED_FW_MINOR: u8 = 52;
pub const RNODE_HIL_MANIFEST_SCHEMA: &str = "hyf.rnode.hil.v1";
pub const RNODE_HIL_DEFAULT_BAUD: u32 = 115_200;

#[cfg(test)]
mod tests {
    use super::{
        RNODE_BANDWIDTH_MAX_HZ, RNODE_BANDWIDTH_MIN_HZ, RNODE_CMD_BANDWIDTH, RNODE_CMD_CR,
        RNODE_CMD_ERROR, RNODE_CMD_FREQUENCY, RNODE_CMD_FW_VERSION, RNODE_CMD_READY, RNODE_CMD_SF,
        RNODE_CMD_STAT_RSSI, RNODE_CMD_STAT_RX, RNODE_CMD_STAT_SNR, RNODE_CMD_STAT_TX,
        RNODE_CMD_TXPOWER, RNODE_FREQUENCY_MAX_HZ, RNODE_FREQUENCY_MIN_HZ, RNODE_RSSI_OFFSET,
    };

    #[test]
    fn rnode_constants_match_profile_values() {
        assert_eq!(RNODE_CMD_FREQUENCY, 0x01);
        assert_eq!(RNODE_CMD_BANDWIDTH, 0x02);
        assert_eq!(RNODE_CMD_TXPOWER, 0x03);
        assert_eq!(RNODE_CMD_SF, 0x04);
        assert_eq!(RNODE_CMD_CR, 0x05);
        assert_eq!(RNODE_CMD_READY, 0x0f);
        assert_eq!(RNODE_CMD_STAT_RX, 0x21);
        assert_eq!(RNODE_CMD_STAT_TX, 0x22);
        assert_eq!(RNODE_CMD_STAT_RSSI, 0x23);
        assert_eq!(RNODE_CMD_STAT_SNR, 0x24);
        assert_eq!(RNODE_CMD_FW_VERSION, 0x50);
        assert_eq!(RNODE_CMD_ERROR, 0x90);
        assert_eq!(RNODE_FREQUENCY_MIN_HZ, 137_000_000);
        assert_eq!(RNODE_FREQUENCY_MAX_HZ, 3_000_000_000);
        assert_eq!(RNODE_BANDWIDTH_MIN_HZ, 7_800);
        assert_eq!(RNODE_BANDWIDTH_MAX_HZ, 1_625_000);
        assert_eq!(RNODE_RSSI_OFFSET, 157);
    }
}
