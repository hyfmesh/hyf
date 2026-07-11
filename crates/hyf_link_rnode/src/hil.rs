use core::fmt;
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::{RNODE_HIL_DEFAULT_BAUD, RNODE_HIL_MANIFEST_SCHEMA, RNODE_HIL_READY_CHECK_ID};

pub const RNODE_HIL_ARTIFACT_ROOT: &str = "target/hyf_hil/rnode";
pub const RNODE_HIL_MANIFEST_FILE_NAME: &str = "manifest.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeHilCheckStatus {
    Passed,
    Failed,
    Skipped,
}

impl RNodeHilCheckStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeHilCheck<'a> {
    pub id: &'a str,
    pub status: RNodeHilCheckStatus,
    pub detail: Option<&'a str>,
}

impl<'a> RNodeHilCheck<'a> {
    pub const fn new(id: &'a str, status: RNodeHilCheckStatus) -> Self {
        Self {
            id,
            status,
            detail: None,
        }
    }

    pub const fn ready(status: RNodeHilCheckStatus) -> Self {
        Self::new(RNODE_HIL_READY_CHECK_ID, status)
    }

    pub const fn with_detail(mut self, detail: &'a str) -> Self {
        self.detail = Some(detail);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeHilManifest<'a> {
    pub run_id: &'a str,
    pub generated_at: &'a str,
    pub port: &'a str,
    pub baud: u32,
    pub hardware_model: Option<&'a str>,
    pub firmware_version: Option<&'a str>,
    pub allow_rf_tx: bool,
    pub transmission_performed: bool,
    pub checks: &'a [RNodeHilCheck<'a>],
}

impl<'a> RNodeHilManifest<'a> {
    pub fn new(run_id: &'a str, generated_at: &'a str, port: &'a str) -> Self {
        Self {
            run_id,
            generated_at,
            port,
            baud: RNODE_HIL_DEFAULT_BAUD,
            hardware_model: None,
            firmware_version: None,
            allow_rf_tx: false,
            transmission_performed: false,
            checks: &[],
        }
    }
}

#[derive(Debug)]
pub enum RNodeHilManifestError {
    EmptyRunId,
    EmptyGeneratedAt,
    InvalidGeneratedAt,
    EmptyPort,
    InvalidBaud,
    EmptyChecks,
    EmptyCheckId,
    RfTransmissionRecorded,
    Io(io::Error),
}

pub fn validate_hil_manifest(manifest: &RNodeHilManifest<'_>) -> Result<(), RNodeHilManifestError> {
    if manifest.run_id.is_empty() {
        return Err(RNodeHilManifestError::EmptyRunId);
    }
    if manifest.generated_at.is_empty() {
        return Err(RNodeHilManifestError::EmptyGeneratedAt);
    }
    if !is_utc_rfc3339_timestamp(manifest.generated_at) {
        return Err(RNodeHilManifestError::InvalidGeneratedAt);
    }
    if manifest.port.is_empty() {
        return Err(RNodeHilManifestError::EmptyPort);
    }
    if manifest.baud == 0 {
        return Err(RNodeHilManifestError::InvalidBaud);
    }
    if manifest.transmission_performed {
        return Err(RNodeHilManifestError::RfTransmissionRecorded);
    }
    if manifest.checks.is_empty() {
        return Err(RNodeHilManifestError::EmptyChecks);
    }
    if manifest.checks.iter().any(|check| check.id.is_empty()) {
        return Err(RNodeHilManifestError::EmptyCheckId);
    }
    Ok(())
}

pub fn default_hil_manifest_artifact_path(
    generated_at: &str,
) -> Result<PathBuf, RNodeHilManifestError> {
    hil_manifest_artifact_path(RNODE_HIL_ARTIFACT_ROOT, generated_at)
}

pub fn hil_manifest_artifact_path<P: AsRef<Path>>(
    root: P,
    generated_at: &str,
) -> Result<PathBuf, RNodeHilManifestError> {
    if generated_at.is_empty() {
        return Err(RNodeHilManifestError::EmptyGeneratedAt);
    }
    if !is_utc_rfc3339_timestamp(generated_at) {
        return Err(RNodeHilManifestError::InvalidGeneratedAt);
    }

    Ok(root
        .as_ref()
        .join(artifact_timestamp_segment(generated_at))
        .join(RNODE_HIL_MANIFEST_FILE_NAME))
}

fn artifact_timestamp_segment(generated_at: &str) -> String {
    let mut segment = String::with_capacity(generated_at.len());
    for character in generated_at.chars() {
        match character {
            ':' => {}
            '.' => segment.push('-'),
            character => segment.push(character),
        }
    }
    segment
}

fn is_utc_rfc3339_timestamp(value: &str) -> bool {
    let Some((date, time_with_zone)) = value.split_once('T') else {
        return false;
    };
    let Some(time) = time_with_zone.strip_suffix('Z') else {
        return false;
    };

    valid_rfc3339_date(date) && valid_rfc3339_time(time)
}

fn valid_rfc3339_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }

    let Some(year) = parse_digits(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = parse_digits(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = parse_digits(&bytes[8..10]) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }

    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn valid_rfc3339_time(time: &str) -> bool {
    let (whole_time, fractional) = match time.split_once('.') {
        Some((whole_time, fractional)) => (whole_time, Some(fractional)),
        None => (time, None),
    };
    let bytes = whole_time.as_bytes();
    if bytes.len() != 8 || bytes[2] != b':' || bytes[5] != b':' {
        return false;
    }

    let Some(hour) = parse_digits(&bytes[0..2]) else {
        return false;
    };
    let Some(minute) = parse_digits(&bytes[3..5]) else {
        return false;
    };
    let Some(second) = parse_digits(&bytes[6..8]) else {
        return false;
    };

    hour <= 23
        && minute <= 59
        && second <= 59
        && fractional.is_none_or(|value| {
            !value.is_empty() && value.as_bytes().iter().all(u8::is_ascii_digit)
        })
}

fn parse_digits(bytes: &[u8]) -> Option<u32> {
    let mut value = 0_u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Some(value)
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

pub fn write_hil_manifest_json<W: Write>(
    manifest: &RNodeHilManifest<'_>,
    out: &mut W,
) -> Result<(), RNodeHilManifestError> {
    validate_hil_manifest(manifest)?;

    out.write_all(b"{\n  \"schema\": ")?;
    write_json_string(out, RNODE_HIL_MANIFEST_SCHEMA)?;
    out.write_all(b",\n  \"run_id\": ")?;
    write_json_string(out, manifest.run_id)?;
    out.write_all(b",\n  \"generated_at\": ")?;
    write_json_string(out, manifest.generated_at)?;
    out.write_all(b",\n  \"rnode\": {\n    \"port\": ")?;
    write_json_string(out, manifest.port)?;
    write!(
        out,
        ",\n    \"baud\": {},\n    \"hardware_model\": ",
        manifest.baud
    )?;
    write_optional_json_string(out, manifest.hardware_model)?;
    out.write_all(b",\n    \"firmware_version\": ")?;
    write_optional_json_string(out, manifest.firmware_version)?;
    write!(
        out,
        "\n  }},\n  \"rf\": {{\n    \"allow_rf_tx\": {},\n    \"transmission_performed\": {}\n  }},\n  \"checks\": [",
        manifest.allow_rf_tx, manifest.transmission_performed
    )?;
    for (index, check) in manifest.checks.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        write_hil_check_json(out, check)?;
    }
    out.write_all(b"\n  ]\n}\n")?;
    Ok(())
}

fn write_hil_check_json<W: Write>(out: &mut W, check: &RNodeHilCheck<'_>) -> io::Result<()> {
    out.write_all(b"\n    {\n      \"id\": ")?;
    write_json_string(out, check.id)?;
    out.write_all(b",\n      \"status\": ")?;
    write_json_string(out, check.status.as_str())?;
    if let Some(detail) = check.detail {
        out.write_all(b",\n      \"detail\": ")?;
        write_json_string(out, detail)?;
    }
    out.write_all(b"\n    }")
}

fn write_optional_json_string<W: Write>(out: &mut W, value: Option<&str>) -> io::Result<()> {
    match value {
        Some(value) => write_json_string(out, value),
        None => out.write_all(b"null"),
    }
}

fn write_json_string<W: Write>(out: &mut W, value: &str) -> io::Result<()> {
    out.write_all(b"\"")?;
    for character in value.chars() {
        match character {
            '"' => out.write_all(br#"\""#)?,
            '\\' => out.write_all(br#"\\"#)?,
            '\n' => out.write_all(br#"\n"#)?,
            '\r' => out.write_all(br#"\r"#)?,
            '\t' => out.write_all(br#"\t"#)?,
            character if character.is_control() => {
                write!(out, "\\u{:04x}", character as u32)?;
            }
            character => {
                let mut encoded = [0_u8; 4];
                out.write_all(character.encode_utf8(&mut encoded).as_bytes())?;
            }
        }
    }
    out.write_all(b"\"")
}

impl fmt::Display for RNodeHilManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRunId => formatter.write_str("empty rnode hil manifest run id"),
            Self::EmptyGeneratedAt => formatter.write_str("empty rnode hil manifest generated_at"),
            Self::InvalidGeneratedAt => {
                formatter.write_str("invalid rnode hil manifest generated_at")
            }
            Self::EmptyPort => formatter.write_str("empty rnode hil manifest port"),
            Self::InvalidBaud => formatter.write_str("invalid rnode hil manifest baud"),
            Self::EmptyChecks => formatter.write_str("empty rnode hil manifest checks"),
            Self::EmptyCheckId => formatter.write_str("empty rnode hil manifest check id"),
            Self::RfTransmissionRecorded => {
                formatter.write_str("rnode hil manifest recorded rf transmission")
            }
            Self::Io(error) => write!(formatter, "rnode hil manifest io error: {error}"),
        }
    }
}

impl std::error::Error for RNodeHilManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for RNodeHilManifestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RNodeHilCheck, RNodeHilCheckStatus, RNodeHilManifest, RNodeHilManifestError,
        default_hil_manifest_artifact_path, hil_manifest_artifact_path, validate_hil_manifest,
        write_hil_manifest_json,
    };
    use crate::RNODE_HIL_READY_CHECK_ID;
    use serde_json::Value;
    use std::path::PathBuf;

    const HIL_SCHEMA: &str = include_str!("../../../schemas/rnode_hil_manifest.schema.json");

    #[test]
    fn manifest_writer_emits_non_transmitting_contract() -> Result<(), RNodeHilManifestError> {
        let check = [RNodeHilCheck::ready(RNodeHilCheckStatus::Passed)];
        let mut manifest =
            RNodeHilManifest::new("rnode-hil-test", "2026-07-09T00:00:00Z", "loop://rnode0");
        manifest.checks = &check;
        let mut json = Vec::new();

        write_hil_manifest_json(&manifest, &mut json)?;

        let output = String::from_utf8(json)
            .map_err(|_| RNodeHilManifestError::Io(std::io::ErrorKind::InvalidData.into()))?;
        assert!(output.contains("\"schema\": \"hyf.rnode.hil.v1\""));
        assert!(output.contains("\"port\": \"loop://rnode0\""));
        assert!(output.contains("\"baud\": 115200"));
        assert!(output.contains("\"transmission_performed\": false"));
        assert!(output.contains("\"id\": \"hil.rnode.ready\""));
        assert!(output.contains("\"status\": \"passed\""));
        Ok(())
    }

    #[test]
    fn manifest_writer_output_matches_schema_contract() -> Result<(), Box<dyn std::error::Error>> {
        let mut manifest =
            RNodeHilManifest::new("rnode-hil-test", "2026-07-09T00:00:00Z", "loop://rnode0");
        let check = [RNodeHilCheck::ready(RNodeHilCheckStatus::Passed)
            .with_detail("non-transmitting readiness probe passed")];
        manifest.hardware_model = Some("RNode Test");
        manifest.firmware_version = Some("0.0.0-test");
        manifest.checks = &check;
        let mut json = Vec::new();

        write_hil_manifest_json(&manifest, &mut json)?;

        let schema: Value = serde_json::from_str(HIL_SCHEMA)?;
        let output: Value = serde_json::from_slice(&json)?;
        assert_eq!(schema["properties"]["schema"]["const"], "hyf.rnode.hil.v1");
        assert_eq!(schema["properties"]["generated_at"]["format"], "date-time");
        assert_eq!(schema["properties"]["generated_at"]["pattern"], "Z$");
        assert_eq!(
            schema["properties"]["checks"]["items"]["properties"]["id"]["enum"][0],
            RNODE_HIL_READY_CHECK_ID
        );
        assert_eq!(output["schema"], "hyf.rnode.hil.v1");
        assert_eq!(output["generated_at"], "2026-07-09T00:00:00Z");
        assert_eq!(output["rnode"]["port"], "loop://rnode0");
        assert_eq!(output["rnode"]["baud"], 115200);
        assert_eq!(output["rnode"]["hardware_model"], "RNode Test");
        assert_eq!(output["rnode"]["firmware_version"], "0.0.0-test");
        assert_eq!(output["rf"]["allow_rf_tx"], false);
        assert_eq!(output["rf"]["transmission_performed"], false);
        assert_eq!(output["checks"].as_array().map(Vec::len), Some(1));
        assert_eq!(output["checks"][0]["id"], RNODE_HIL_READY_CHECK_ID);
        assert_eq!(output["checks"][0]["status"], "passed");
        assert_eq!(
            output["checks"][0]["detail"],
            "non-transmitting readiness probe passed"
        );
        Ok(())
    }

    #[test]
    fn default_artifact_path_uses_timestamped_target_manifest() -> Result<(), RNodeHilManifestError>
    {
        let path = default_hil_manifest_artifact_path("2026-07-09T00:00:00Z")?;

        assert_eq!(
            path,
            PathBuf::from("target")
                .join("hyf_hil")
                .join("rnode")
                .join("2026-07-09T000000Z")
                .join("manifest.json")
        );
        Ok(())
    }

    #[test]
    fn artifact_path_override_still_uses_timestamped_manifest() -> Result<(), RNodeHilManifestError>
    {
        let path = hil_manifest_artifact_path("custom-root", "2026-07-09T00:00:00.123Z")?;

        assert_eq!(
            path,
            PathBuf::from("custom-root")
                .join("2026-07-09T000000-123Z")
                .join("manifest.json")
        );
        Ok(())
    }

    #[test]
    fn artifact_path_rejects_invalid_timestamp() {
        assert!(matches!(
            default_hil_manifest_artifact_path("not-a-date"),
            Err(RNodeHilManifestError::InvalidGeneratedAt)
        ));
    }

    #[test]
    fn validation_accepts_utc_generated_at_with_fractional_seconds() {
        let check = [RNodeHilCheck::ready(RNodeHilCheckStatus::Skipped)];
        let mut manifest = RNodeHilManifest::new(
            "rnode-hil-test",
            "2026-07-09T00:00:00.123Z",
            "loop://rnode0",
        );
        manifest.checks = &check;

        assert!(validate_hil_manifest(&manifest).is_ok());
    }

    #[test]
    fn validation_rejects_schema_invalid_generated_at_values() {
        for generated_at in [
            "2026-07-09T00:00:00",
            "2026-07-09T00:00:00+00:00",
            "2026-13-09T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2024-02-30T00:00:00Z",
            "2026-07-09T24:00:00Z",
            "2026-07-09T00:60:00Z",
            "2026-07-09T00:00:60Z",
            "2026-07-09T00:00:00.Z",
            "not-a-date",
        ] {
            let check = [RNodeHilCheck::ready(RNodeHilCheckStatus::Skipped)];
            let mut manifest =
                RNodeHilManifest::new("rnode-hil-test", generated_at, "loop://rnode0");
            manifest.checks = &check;

            assert!(matches!(
                validate_hil_manifest(&manifest),
                Err(RNodeHilManifestError::InvalidGeneratedAt)
            ));
        }
    }

    #[test]
    fn validation_rejects_recorded_rf_transmission() {
        let mut manifest =
            RNodeHilManifest::new("rnode-hil-test", "2026-07-09T00:00:00Z", "loop://rnode0");
        let check = [RNodeHilCheck::ready(RNodeHilCheckStatus::Failed)];
        manifest.checks = &check;
        manifest.transmission_performed = true;

        let result = validate_hil_manifest(&manifest);

        assert!(matches!(
            result,
            Err(RNodeHilManifestError::RfTransmissionRecorded)
        ));
    }

    #[test]
    fn validation_rejects_missing_checks() {
        let manifest =
            RNodeHilManifest::new("rnode-hil-test", "2026-07-09T00:00:00Z", "loop://rnode0");

        assert!(matches!(
            validate_hil_manifest(&manifest),
            Err(RNodeHilManifestError::EmptyChecks)
        ));
    }

    #[test]
    fn validation_rejects_empty_check_id() {
        let check = [RNodeHilCheck::new("", RNodeHilCheckStatus::Failed)];
        let mut manifest =
            RNodeHilManifest::new("rnode-hil-test", "2026-07-09T00:00:00Z", "loop://rnode0");
        manifest.checks = &check;

        assert!(matches!(
            validate_hil_manifest(&manifest),
            Err(RNodeHilManifestError::EmptyCheckId)
        ));
    }

    #[test]
    fn manifest_writer_escapes_json_strings() -> Result<(), RNodeHilManifestError> {
        let mut manifest =
            RNodeHilManifest::new("run\"id", "2026-07-09T00:00:00Z", "loop:\\rnode\n0");
        let check =
            [RNodeHilCheck::ready(RNodeHilCheckStatus::Passed).with_detail("ready\twith detail")];
        manifest.hardware_model = Some("model\tone");
        manifest.checks = &check;
        let mut json = Vec::new();

        write_hil_manifest_json(&manifest, &mut json)?;

        let output = String::from_utf8(json)
            .map_err(|_| RNodeHilManifestError::Io(std::io::ErrorKind::InvalidData.into()))?;
        assert!(output.contains("\"run_id\": \"run\\\"id\""));
        assert!(output.contains("\"port\": \"loop:\\\\rnode\\n0\""));
        assert!(output.contains("\"hardware_model\": \"model\\tone\""));
        assert!(output.contains("\"detail\": \"ready\\twith detail\""));
        Ok(())
    }
}
