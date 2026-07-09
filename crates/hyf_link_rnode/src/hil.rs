use core::fmt;
use std::io::{self, Write};

use crate::{RNODE_HIL_DEFAULT_BAUD, RNODE_HIL_MANIFEST_SCHEMA};

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
        }
    }
}

#[derive(Debug)]
pub enum RNodeHilManifestError {
    EmptyRunId,
    EmptyGeneratedAt,
    EmptyPort,
    InvalidBaud,
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
    if manifest.port.is_empty() {
        return Err(RNodeHilManifestError::EmptyPort);
    }
    if manifest.baud == 0 {
        return Err(RNodeHilManifestError::InvalidBaud);
    }
    if manifest.transmission_performed {
        return Err(RNodeHilManifestError::RfTransmissionRecorded);
    }
    Ok(())
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
        "\n  }},\n  \"rf\": {{\n    \"allow_rf_tx\": {},\n    \"transmission_performed\": {}\n  }},\n  \"checks\": []\n}}\n",
        manifest.allow_rf_tx, manifest.transmission_performed
    )?;
    Ok(())
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
            Self::EmptyPort => formatter.write_str("empty rnode hil manifest port"),
            Self::InvalidBaud => formatter.write_str("invalid rnode hil manifest baud"),
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
        RNodeHilManifest, RNodeHilManifestError, validate_hil_manifest, write_hil_manifest_json,
    };

    #[test]
    fn manifest_writer_emits_non_transmitting_contract() -> Result<(), RNodeHilManifestError> {
        let manifest =
            RNodeHilManifest::new("rnode-hil-test", "2026-07-09T00:00:00Z", "loop://rnode0");
        let mut json = Vec::new();

        write_hil_manifest_json(&manifest, &mut json)?;

        let output = String::from_utf8(json)
            .map_err(|_| RNodeHilManifestError::Io(std::io::ErrorKind::InvalidData.into()))?;
        assert!(output.contains("\"schema\": \"hyf.rnode.hil.v1\""));
        assert!(output.contains("\"port\": \"loop://rnode0\""));
        assert!(output.contains("\"baud\": 115200"));
        assert!(output.contains("\"transmission_performed\": false"));
        Ok(())
    }

    #[test]
    fn validation_rejects_recorded_rf_transmission() {
        let mut manifest =
            RNodeHilManifest::new("rnode-hil-test", "2026-07-09T00:00:00Z", "loop://rnode0");
        manifest.transmission_performed = true;

        let result = validate_hil_manifest(&manifest);

        assert!(matches!(
            result,
            Err(RNodeHilManifestError::RfTransmissionRecorded)
        ));
    }

    #[test]
    fn manifest_writer_escapes_json_strings() -> Result<(), RNodeHilManifestError> {
        let mut manifest =
            RNodeHilManifest::new("run\"id", "2026-07-09T00:00:00Z", "loop:\\rnode\n0");
        manifest.hardware_model = Some("model\tone");
        let mut json = Vec::new();

        write_hil_manifest_json(&manifest, &mut json)?;

        let output = String::from_utf8(json)
            .map_err(|_| RNodeHilManifestError::Io(std::io::ErrorKind::InvalidData.into()))?;
        assert!(output.contains("\"run_id\": \"run\\\"id\""));
        assert!(output.contains("\"port\": \"loop:\\\\rnode\\n0\""));
        assert!(output.contains("\"hardware_model\": \"model\\tone\""));
        Ok(())
    }
}
