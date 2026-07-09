use core::fmt;

use hyf_link_kiss::{KissFrameRef, encode_command_frame};

use crate::{
    RNODE_CMD_BANDWIDTH, RNODE_CMD_CR, RNODE_CMD_DATA, RNODE_CMD_DETECT, RNODE_CMD_ERROR,
    RNODE_CMD_FREQUENCY, RNODE_CMD_FW_VERSION, RNODE_CMD_LEAVE, RNODE_CMD_MCU, RNODE_CMD_PLATFORM,
    RNODE_CMD_RADIO_STATE, RNODE_CMD_READY, RNODE_CMD_SF, RNODE_CMD_STAT_RSSI, RNODE_CMD_STAT_RX,
    RNODE_CMD_STAT_SNR, RNODE_CMD_STAT_TX, RNODE_CMD_TXPOWER, RNODE_DETECT_REQUEST,
    RNODE_ERROR_EEPROM_LOCKED, RNODE_ERROR_INITRADIO, RNODE_ERROR_MEMORY_LOW,
    RNODE_ERROR_MODEM_TIMEOUT, RNODE_ERROR_QUEUE_FULL, RNODE_ERROR_TXFAILED, RNODE_LEAVE_REQUEST,
    RNODE_RADIO_STATE_ASK, RNODE_RADIO_STATE_OFF, RNODE_RADIO_STATE_ON, RNODE_REQUIRED_FW_MAJOR,
    RNODE_REQUIRED_FW_MINOR, RNODE_RSSI_OFFSET, RNodeError, validate_bandwidth_hz,
    validate_coding_rate, validate_frequency_hz, validate_spreading_factor, validate_tx_power_dbm,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeRadioState {
    Off,
    On,
    Ask,
}

impl RNodeRadioState {
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Off => RNODE_RADIO_STATE_OFF,
            Self::On => RNODE_RADIO_STATE_ON,
            Self::Ask => RNODE_RADIO_STATE_ASK,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeCommand {
    FrequencyHz(u32),
    BandwidthHz(u32),
    TxPowerDbm(u8),
    SpreadingFactor(u8),
    CodingRate(u8),
    RadioState(RNodeRadioState),
    Detect,
    Leave,
    Ready(bool),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeHardwareError {
    InitRadio,
    TxFailed,
    EepromLocked,
    QueueFull,
    MemoryLow,
    ModemTimeout,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeFirmwareVersion {
    pub major: u8,
    pub minor: u8,
    pub supported: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeConfigReport {
    FrequencyHz(u32),
    BandwidthHz(u32),
    TxPowerDbm(u8),
    SpreadingFactor(u8),
    CodingRate(u8),
    RadioState(RNodeRadioState),
    Platform(u8),
    Mcu(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeStat {
    RxBytes(u32),
    TxBytes(u32),
    RssiDbm(i16),
    SnrQuarterDb(i8),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RNodeEvent<'a> {
    Data(&'a [u8]),
    Ready,
    Error(RNodeHardwareError),
    FirmwareVersion(RNodeFirmwareVersion),
    ConfigReport(RNodeConfigReport),
    Stat(RNodeStat),
    Unknown { command: u8, payload: &'a [u8] },
}

impl fmt::Debug for RNodeEvent<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(payload) => formatter
                .debug_struct("Data")
                .field("payload", &"<redacted>")
                .field("payload_len", &payload.len())
                .finish(),
            Self::Ready => formatter.write_str("Ready"),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
            Self::FirmwareVersion(version) => formatter
                .debug_tuple("FirmwareVersion")
                .field(version)
                .finish(),
            Self::ConfigReport(report) => {
                formatter.debug_tuple("ConfigReport").field(report).finish()
            }
            Self::Stat(stat) => formatter.debug_tuple("Stat").field(stat).finish(),
            Self::Unknown { command, payload } => formatter
                .debug_struct("Unknown")
                .field("command", command)
                .field("payload", &"<redacted>")
                .field("payload_len", &payload.len())
                .finish(),
        }
    }
}

pub fn encode_command(command: RNodeCommand, out: &mut [u8]) -> Result<usize, RNodeError> {
    let mut payload = [0; 4];
    let (command_byte, payload) = match command {
        RNodeCommand::FrequencyHz(value) => {
            validate_frequency_hz(value)?;
            payload.copy_from_slice(&value.to_be_bytes());
            (RNODE_CMD_FREQUENCY, &payload[..4])
        }
        RNodeCommand::BandwidthHz(value) => {
            validate_bandwidth_hz(value)?;
            payload.copy_from_slice(&value.to_be_bytes());
            (RNODE_CMD_BANDWIDTH, &payload[..4])
        }
        RNodeCommand::TxPowerDbm(value) => {
            validate_tx_power_dbm(value)?;
            payload[0] = value;
            (RNODE_CMD_TXPOWER, &payload[..1])
        }
        RNodeCommand::SpreadingFactor(value) => {
            validate_spreading_factor(value)?;
            payload[0] = value;
            (RNODE_CMD_SF, &payload[..1])
        }
        RNodeCommand::CodingRate(value) => {
            validate_coding_rate(value)?;
            payload[0] = value;
            (RNODE_CMD_CR, &payload[..1])
        }
        RNodeCommand::RadioState(state) => {
            payload[0] = state.as_byte();
            (RNODE_CMD_RADIO_STATE, &payload[..1])
        }
        RNodeCommand::Detect => {
            payload[0] = RNODE_DETECT_REQUEST;
            (RNODE_CMD_DETECT, &payload[..1])
        }
        RNodeCommand::Leave => {
            payload[0] = RNODE_LEAVE_REQUEST;
            (RNODE_CMD_LEAVE, &payload[..1])
        }
        RNodeCommand::Ready(enabled) => {
            payload[0] = u8::from(enabled);
            (RNODE_CMD_READY, &payload[..1])
        }
    };

    Ok(encode_command_frame(command_byte, payload, out)?)
}

pub fn parse_command_frame<'a>(frame: KissFrameRef<'a>) -> Result<RNodeEvent<'a>, RNodeError> {
    let command = frame.command();
    let payload = frame.payload();
    match command {
        RNODE_CMD_DATA => Ok(RNodeEvent::Data(payload)),
        RNODE_CMD_READY => parse_ready(payload),
        RNODE_CMD_ERROR => parse_error(command, payload),
        RNODE_CMD_FW_VERSION => parse_firmware_version(command, payload),
        RNODE_CMD_STAT_RX => parse_u32_stat(command, payload, RNodeStat::RxBytes),
        RNODE_CMD_STAT_TX => parse_u32_stat(command, payload, RNodeStat::TxBytes),
        RNODE_CMD_STAT_RSSI => parse_rssi(command, payload),
        RNODE_CMD_STAT_SNR => parse_snr(command, payload),
        RNODE_CMD_FREQUENCY => parse_u32_config(command, payload, RNodeConfigReport::FrequencyHz),
        RNODE_CMD_BANDWIDTH => parse_u32_config(command, payload, RNodeConfigReport::BandwidthHz),
        RNODE_CMD_TXPOWER => parse_u8_config(command, payload, RNodeConfigReport::TxPowerDbm),
        RNODE_CMD_SF => parse_u8_config(command, payload, RNodeConfigReport::SpreadingFactor),
        RNODE_CMD_CR => parse_u8_config(command, payload, RNodeConfigReport::CodingRate),
        RNODE_CMD_RADIO_STATE => parse_radio_state(command, payload),
        RNODE_CMD_PLATFORM => parse_u8_config(command, payload, RNodeConfigReport::Platform),
        RNODE_CMD_MCU => parse_u8_config(command, payload, RNodeConfigReport::Mcu),
        command => Ok(RNodeEvent::Unknown { command, payload }),
    }
}

fn parse_ready(payload: &[u8]) -> Result<RNodeEvent<'_>, RNodeError> {
    if payload.len() <= 1 {
        Ok(RNodeEvent::Ready)
    } else {
        Err(invalid_len(RNODE_CMD_READY, payload.len(), 1))
    }
}

fn parse_error(command: u8, payload: &[u8]) -> Result<RNodeEvent<'_>, RNodeError> {
    expect_len(command, payload, 1)?;
    let error = match payload[0] {
        RNODE_ERROR_INITRADIO => RNodeHardwareError::InitRadio,
        RNODE_ERROR_TXFAILED => RNodeHardwareError::TxFailed,
        RNODE_ERROR_EEPROM_LOCKED => RNodeHardwareError::EepromLocked,
        RNODE_ERROR_QUEUE_FULL => RNodeHardwareError::QueueFull,
        RNODE_ERROR_MEMORY_LOW => RNodeHardwareError::MemoryLow,
        RNODE_ERROR_MODEM_TIMEOUT => RNodeHardwareError::ModemTimeout,
        other => RNodeHardwareError::Unknown(other),
    };
    Ok(RNodeEvent::Error(error))
}

fn parse_firmware_version(command: u8, payload: &[u8]) -> Result<RNodeEvent<'_>, RNodeError> {
    expect_len(command, payload, 2)?;
    let major = payload[0];
    let minor = payload[1];
    Ok(RNodeEvent::FirmwareVersion(RNodeFirmwareVersion {
        major,
        minor,
        supported: firmware_supported(major, minor),
    }))
}

fn parse_u32_stat(
    command: u8,
    payload: &[u8],
    build: fn(u32) -> RNodeStat,
) -> Result<RNodeEvent<'_>, RNodeError> {
    let value = parse_u32(command, payload)?;
    Ok(RNodeEvent::Stat(build(value)))
}

fn parse_rssi(command: u8, payload: &[u8]) -> Result<RNodeEvent<'_>, RNodeError> {
    expect_len(command, payload, 1)?;
    Ok(RNodeEvent::Stat(RNodeStat::RssiDbm(
        i16::from(payload[0]) - RNODE_RSSI_OFFSET,
    )))
}

fn parse_snr(command: u8, payload: &[u8]) -> Result<RNodeEvent<'_>, RNodeError> {
    expect_len(command, payload, 1)?;
    Ok(RNodeEvent::Stat(RNodeStat::SnrQuarterDb(
        i8::from_be_bytes([payload[0]]),
    )))
}

fn parse_u32_config(
    command: u8,
    payload: &[u8],
    build: fn(u32) -> RNodeConfigReport,
) -> Result<RNodeEvent<'_>, RNodeError> {
    let value = parse_u32(command, payload)?;
    Ok(RNodeEvent::ConfigReport(build(value)))
}

fn parse_u8_config(
    command: u8,
    payload: &[u8],
    build: fn(u8) -> RNodeConfigReport,
) -> Result<RNodeEvent<'_>, RNodeError> {
    expect_len(command, payload, 1)?;
    Ok(RNodeEvent::ConfigReport(build(payload[0])))
}

fn parse_radio_state(command: u8, payload: &[u8]) -> Result<RNodeEvent<'_>, RNodeError> {
    expect_len(command, payload, 1)?;
    let state = match payload[0] {
        RNODE_RADIO_STATE_OFF => RNodeRadioState::Off,
        RNODE_RADIO_STATE_ON => RNodeRadioState::On,
        RNODE_RADIO_STATE_ASK => RNodeRadioState::Ask,
        _ => {
            return Ok(RNodeEvent::Unknown { command, payload });
        }
    };
    Ok(RNodeEvent::ConfigReport(RNodeConfigReport::RadioState(
        state,
    )))
}

fn parse_u32(command: u8, payload: &[u8]) -> Result<u32, RNodeError> {
    expect_len(command, payload, 4)?;
    Ok(u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

fn expect_len(command: u8, payload: &[u8], expected: usize) -> Result<(), RNodeError> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(invalid_len(command, payload.len(), expected))
    }
}

fn invalid_len(command: u8, actual: usize, expected: usize) -> RNodeError {
    RNodeError::InvalidPayloadLength {
        command,
        actual,
        expected,
    }
}

fn firmware_supported(major: u8, minor: u8) -> bool {
    major > RNODE_REQUIRED_FW_MAJOR
        || major == RNODE_REQUIRED_FW_MAJOR && minor >= RNODE_REQUIRED_FW_MINOR
}

#[cfg(test)]
mod tests {
    use hyf_link_kiss::KissFrameRef;

    use super::{
        RNodeCommand, RNodeConfigReport, RNodeEvent, RNodeHardwareError, RNodeRadioState,
        RNodeStat, encode_command, parse_command_frame,
    };
    use crate::{RNODE_CMD_FW_VERSION, RNodeError};

    #[test]
    fn encodes_config_commands_as_kiss_frames() -> Result<(), RNodeError> {
        let mut output = [0; 16];
        let len = encode_command(RNodeCommand::FrequencyHz(915_000_000), &mut output)?;
        assert_eq!(
            &output[..len],
            &[0xc0, 0x01, 0x36, 0x89, 0xca, 0xdb, 0xdc, 0xc0]
        );

        let len = encode_command(RNodeCommand::BandwidthHz(125_000), &mut output)?;
        assert_eq!(&output[..len], &[0xc0, 0x02, 0x00, 0x01, 0xe8, 0x48, 0xc0]);

        let len = encode_command(RNodeCommand::TxPowerDbm(22), &mut output)?;
        assert_eq!(&output[..len], &[0xc0, 0x03, 0x16, 0xc0]);
        Ok(())
    }

    #[test]
    fn encodes_radio_state_and_detect_commands() -> Result<(), RNodeError> {
        let mut output = [0; 8];
        let len = encode_command(RNodeCommand::RadioState(RNodeRadioState::On), &mut output)?;
        assert_eq!(&output[..len], &[0xc0, 0x06, 0x01, 0xc0]);

        let len = encode_command(RNodeCommand::Detect, &mut output)?;
        assert_eq!(&output[..len], &[0xc0, 0x08, 0x73, 0xc0]);
        Ok(())
    }

    #[test]
    fn parse_command_frame_maps_ready_error_firmware_and_stats() -> Result<(), RNodeError> {
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0x0f, &[0x01]))?,
            RNodeEvent::Ready
        );
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0x90, &[0x04]))?,
            RNodeEvent::Error(RNodeHardwareError::QueueFull)
        );
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0x50, &[0x01, 0x34]))?,
            RNodeEvent::FirmwareVersion(super::RNodeFirmwareVersion {
                major: 1,
                minor: 52,
                supported: true,
            })
        );
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0x21, &[0x00, 0x01, 0xe2, 0x40]))?,
            RNodeEvent::Stat(RNodeStat::RxBytes(123_456))
        );
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0x23, &[0xa0]))?,
            RNodeEvent::Stat(RNodeStat::RssiDbm(3))
        );
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0x24, &[0xf4]))?,
            RNodeEvent::Stat(RNodeStat::SnrQuarterDb(-12))
        );
        Ok(())
    }

    #[test]
    fn parse_command_frame_rejects_bad_payload_lengths() {
        assert_eq!(
            parse_command_frame(KissFrameRef::new(RNODE_CMD_FW_VERSION, &[0x01])),
            Err(RNodeError::InvalidPayloadLength {
                command: RNODE_CMD_FW_VERSION,
                actual: 1,
                expected: 2,
            })
        );
    }

    #[test]
    fn parse_command_frame_reports_unknown_commands() -> Result<(), RNodeError> {
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0xee, &[0x01, 0x02]))?,
            RNodeEvent::Unknown {
                command: 0xee,
                payload: &[0x01, 0x02],
            }
        );
        assert_eq!(
            parse_command_frame(KissFrameRef::new(0x01, &[0x36, 0x89, 0xca, 0xc0]))?,
            RNodeEvent::ConfigReport(RNodeConfigReport::FrequencyHz(915_000_000))
        );
        Ok(())
    }

    #[test]
    fn event_debug_redacts_data_payload_bytes() {
        let event = RNodeEvent::Data(b"secret");
        let debug = format!("{event:?}");

        assert!(debug.contains("Data"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("payload_len"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
    }

    #[test]
    fn event_debug_redacts_unknown_payload_bytes() {
        let event = RNodeEvent::Unknown {
            command: 0xee,
            payload: b"secret",
        };
        let debug = format!("{event:?}");

        assert!(debug.contains("Unknown"));
        assert!(debug.contains("command"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("payload_len"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115, 101, 99"));
    }
}
