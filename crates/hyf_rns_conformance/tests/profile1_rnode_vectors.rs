use hyf_link_kiss::{KissDecoder, KissFrameRef, encode_command_frame};
use hyf_link_rnode::{
    RNodeCommand, RNodeConfig, RNodeError, RNodeEvent, RNodeHardwareError, RNodeRadioState,
    RNodeStat, encode_command, parse_command_frame, validate_config,
};
use hyf_rns_conformance::fixtures::{
    ExpectedManifestEntry, FixtureCasesFile, FixtureError, PROFILE_1_KISS_RNODE,
    assert_exact_manifest_entries, decode_hex, decode_hex_exact, parse_fixture_cases_for_profile,
    parse_manifest_for_profile,
};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../../../fixtures/rns/profile_1_kiss_rnode/manifest.json");
const KISS_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/kiss_vectors.json");
const KISS_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/kiss_negative_vectors.json");
const RNODE_COMMAND_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_command_vectors.json");
const RNODE_CONFIG_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_config_validation_vectors.json");
const RNODE_STAT_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_stat_vectors.json");

#[derive(Debug, Deserialize)]
struct RNodeCommandVector {
    schema: String,
    profile: String,
    case_id: String,
    command: String,
    command_byte_hex: String,
    value: u32,
    payload_hex: String,
    kiss_frame_hex: String,
}

#[derive(Debug, Deserialize)]
struct RNodeConfigVector {
    schema: String,
    profile: String,
    case_id: String,
    config: RNodeConfigCase,
    expected: RNodeConfigExpected,
}

#[derive(Debug, Deserialize)]
struct RNodeConfigCase {
    frequency_hz: u32,
    bandwidth_hz: u32,
    tx_power_dbm: u8,
    spreading_factor: u8,
    coding_rate: u8,
    flow_control: bool,
}

#[derive(Debug, Deserialize)]
struct RNodeConfigExpected {
    valid: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RNodeEventVector {
    schema: String,
    profile: String,
    case_id: String,
    command_byte_hex: String,
    payload_hex: String,
    kiss_frame_hex: String,
    expected: RNodeEventExpected,
}

#[derive(Debug, Deserialize)]
struct RNodeEventExpected {
    kind: String,
    value: Option<u32>,
    rssi_dbm: Option<i16>,
    snr_quarter_db: Option<i8>,
    major: Option<u8>,
    minor: Option<u8>,
    supported: Option<bool>,
    error: Option<String>,
}

#[test]
fn profile_1_manifest_tracks_rnode_vectors() -> Result<(), FixtureError> {
    let manifest = parse_manifest_for_profile(MANIFEST, PROFILE_1_KISS_RNODE)?;

    assert_exact_manifest_entries(
        &manifest,
        &[
            ExpectedManifestEntry {
                file: "kiss_vectors.json",
                category: "kiss",
                case_count: 3,
                contents: KISS_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "kiss_negative_vectors.json",
                category: "kiss_negative",
                case_count: 2,
                contents: KISS_NEGATIVE_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_command_vectors.json",
                category: "rnode_command",
                case_count: 6,
                contents: RNODE_COMMAND_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_config_validation_vectors.json",
                category: "rnode_config_validation",
                case_count: 3,
                contents: RNODE_CONFIG_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_stat_vectors.json",
                category: "rnode_stat",
                case_count: 6,
                contents: RNODE_STAT_FIXTURE,
            },
        ],
    )
}

#[test]
fn rnode_command_vectors_encode_kiss_frames() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<RNodeCommandVector> =
        parse_fixture_cases_for_profile(RNODE_COMMAND_FIXTURE, PROFILE_1_KISS_RNODE)?;

    for case in fixture.cases {
        assert_eq!(case.schema, "hyf.rnode.command_vector.v1");
        assert_eq!(case.profile, PROFILE_1_KISS_RNODE);
        assert!(!case.case_id.is_empty());
        let command_byte = decode_hex_exact::<1>(&case.command_byte_hex)?[0];
        let payload = decode_hex(&case.payload_hex)?;
        let expected_frame = decode_hex(&case.kiss_frame_hex)?;
        let command = rnode_command_from_case(&case)?;
        let mut encoded = vec![0; expected_frame.len()];
        let encoded_len = encode_command(command, &mut encoded)?;

        assert_eq!(&encoded[..encoded_len], expected_frame);
        assert_eq!(
            KissFrameRef::new(command_byte, &payload).command(),
            command_byte
        );
    }

    Ok(())
}

#[test]
fn rnode_config_vectors_validate_boundaries() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<RNodeConfigVector> =
        parse_fixture_cases_for_profile(RNODE_CONFIG_FIXTURE, PROFILE_1_KISS_RNODE)?;

    for case in fixture.cases {
        assert_eq!(case.schema, "hyf.rnode.config_vector.v1");
        assert_eq!(case.profile, PROFILE_1_KISS_RNODE);
        let config = RNodeConfig {
            frequency_hz: case.config.frequency_hz,
            bandwidth_hz: case.config.bandwidth_hz,
            tx_power_dbm: case.config.tx_power_dbm,
            spreading_factor: case.config.spreading_factor,
            coding_rate: case.config.coding_rate,
            flow_control: case.config.flow_control,
        };
        let result = validate_config(&config);

        if case.expected.valid {
            assert!(result.is_ok());
        } else {
            let Err(error) = result else {
                return Err(FixtureError::UnexpectedFixtureValue {
                    field: "case_id".to_owned(),
                    value: case.case_id,
                });
            };
            assert_eq!(rnode_error_code(error), case.expected.error.as_deref());
        }
    }

    Ok(())
}

#[test]
fn rnode_stat_vectors_parse_events() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<RNodeEventVector> =
        parse_fixture_cases_for_profile(RNODE_STAT_FIXTURE, PROFILE_1_KISS_RNODE)?;

    for case in fixture.cases {
        assert_eq!(case.schema, "hyf.rnode.event_vector.v1");
        assert_eq!(case.profile, PROFILE_1_KISS_RNODE);
        assert!(!case.case_id.is_empty());
        let command = decode_hex_exact::<1>(&case.command_byte_hex)?[0];
        let payload = decode_hex(&case.payload_hex)?;
        let expected_frame = decode_hex(&case.kiss_frame_hex)?;
        let mut encoded = vec![0; expected_frame.len()];
        let encoded_len = encode_command_frame(command, &payload, &mut encoded)?;
        assert_single_frame(&expected_frame, command, &payload)?;
        let event = parse_command_frame(KissFrameRef::new(command, &payload))?;

        assert_eq!(&encoded[..encoded_len], expected_frame);
        assert_expected_event(event, &case.expected)?;
    }

    Ok(())
}

fn rnode_command_from_case(case: &RNodeCommandVector) -> Result<RNodeCommand, FixtureError> {
    match case.command.as_str() {
        "frequency" => Ok(RNodeCommand::FrequencyHz(case.value)),
        "bandwidth" => Ok(RNodeCommand::BandwidthHz(case.value)),
        "tx_power" => Ok(RNodeCommand::TxPowerDbm(u8::try_from(case.value).map_err(
            |_| FixtureError::UnexpectedFixtureValue {
                field: "value".to_owned(),
                value: case.value.to_string(),
            },
        )?)),
        "spreading_factor" => Ok(RNodeCommand::SpreadingFactor(
            u8::try_from(case.value).map_err(|_| FixtureError::UnexpectedFixtureValue {
                field: "value".to_owned(),
                value: case.value.to_string(),
            })?,
        )),
        "coding_rate" => Ok(RNodeCommand::CodingRate(u8::try_from(case.value).map_err(
            |_| FixtureError::UnexpectedFixtureValue {
                field: "value".to_owned(),
                value: case.value.to_string(),
            },
        )?)),
        "radio_state" => Ok(RNodeCommand::RadioState(match case.value {
            0 => RNodeRadioState::Off,
            1 => RNodeRadioState::On,
            255 => RNodeRadioState::Ask,
            other => {
                return Err(FixtureError::UnexpectedFixtureValue {
                    field: "value".to_owned(),
                    value: other.to_string(),
                });
            }
        })),
        other => Err(FixtureError::UnexpectedFixtureValue {
            field: "command".to_owned(),
            value: other.to_owned(),
        }),
    }
}

fn assert_single_frame(
    frame: &[u8],
    expected_command: u8,
    expected_payload: &[u8],
) -> Result<(), FixtureError> {
    let mut frame_count = 0usize;
    let mut decoder = KissDecoder::<32>::new();
    decoder.push_bytes(frame, |frame| {
        frame_count += 1;
        assert_eq!(frame.command(), expected_command);
        assert_eq!(frame.payload(), expected_payload);
        Ok(())
    })?;
    if frame_count == 1 {
        Ok(())
    } else {
        Err(FixtureError::UnexpectedFixtureValue {
            field: "kiss_frame_hex".to_owned(),
            value: frame_count.to_string(),
        })
    }
}

fn assert_expected_event(
    event: RNodeEvent<'_>,
    expected: &RNodeEventExpected,
) -> Result<(), FixtureError> {
    match (event, expected.kind.as_str()) {
        (RNodeEvent::Ready, "ready") => Ok(()),
        (RNodeEvent::Error(error), "error") => {
            assert_eq!(hardware_error_code(error), expected.error.as_deref());
            Ok(())
        }
        (RNodeEvent::FirmwareVersion(version), "firmware") => {
            assert_eq!(Some(version.major), expected.major);
            assert_eq!(Some(version.minor), expected.minor);
            assert_eq!(Some(version.supported), expected.supported);
            Ok(())
        }
        (RNodeEvent::Stat(RNodeStat::RxBytes(value)), "rx_bytes")
        | (RNodeEvent::Stat(RNodeStat::TxBytes(value)), "tx_bytes") => {
            assert_eq!(Some(value), expected.value);
            Ok(())
        }
        (RNodeEvent::Stat(RNodeStat::RssiDbm(value)), "rssi") => {
            assert_eq!(Some(value), expected.rssi_dbm);
            Ok(())
        }
        (RNodeEvent::Stat(RNodeStat::SnrQuarterDb(value)), "snr") => {
            assert_eq!(Some(value), expected.snr_quarter_db);
            Ok(())
        }
        (_, other) => Err(FixtureError::UnexpectedFixtureValue {
            field: "kind".to_owned(),
            value: other.to_owned(),
        }),
    }
}

fn rnode_error_code(error: RNodeError) -> Option<&'static str> {
    Some(match error {
        RNodeError::Kiss(_) => "kiss",
        RNodeError::InvalidFrequencyHz { .. } => "invalid_frequency_hz",
        RNodeError::InvalidBandwidthHz { .. } => "invalid_bandwidth_hz",
        RNodeError::InvalidTxPowerDbm { .. } => "invalid_tx_power_dbm",
        RNodeError::InvalidSpreadingFactor { .. } => "invalid_spreading_factor",
        RNodeError::InvalidCodingRate { .. } => "invalid_coding_rate",
        RNodeError::InvalidPayloadLength { .. } => "invalid_payload_length",
    })
}

fn hardware_error_code(error: RNodeHardwareError) -> Option<&'static str> {
    Some(match error {
        RNodeHardwareError::InitRadio => "init_radio",
        RNodeHardwareError::TxFailed => "tx_failed",
        RNodeHardwareError::EepromLocked => "eeprom_locked",
        RNodeHardwareError::QueueFull => "queue_full",
        RNodeHardwareError::MemoryLow => "memory_low",
        RNodeHardwareError::ModemTimeout => "modem_timeout",
        RNodeHardwareError::Unknown(_) => "unknown",
    })
}
