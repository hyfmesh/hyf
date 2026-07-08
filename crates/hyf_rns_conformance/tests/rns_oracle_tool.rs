#![cfg(feature = "python_oracle")]

use std::path::{Path, PathBuf};
use std::process::Command;

use hyf_rns_conformance::fixtures::EXPECTED_RETICULUM_COMMIT;
use serde::Deserialize;

#[test]
fn rns_oracle_tool_replays_profile_1_and_profile_2_vectors() -> Result<(), OracleToolError> {
    let Some(kiss_response) =
        run_oracle(&["kiss-encode", "--case", "kiss.data.escapes_fend_fesc_001"])?
    else {
        return Ok(());
    };
    assert_eq!(kiss_response.command, "kiss-encode");
    assert_eq!(
        kiss_response.oracle.reticulum.commit,
        EXPECTED_RETICULUM_COMMIT
    );
    assert_eq!(
        kiss_response.case.and_then(|case| case.encoded_hex),
        Some("c000dbdcdbdd01c0".to_owned())
    );

    let Some(rnode_response) =
        run_oracle(&["rnode-command", "--case", "rnode.command.frequency_915mhz"])?
    else {
        return Ok(());
    };
    assert_eq!(rnode_response.command, "rnode-command");
    assert_eq!(
        rnode_response.case.and_then(|case| case.kiss_frame_hex),
        Some("c0013689cadbdcc0".to_owned())
    );

    let Some(token_response) = run_oracle(&["token-decrypt", "--hex", TOKEN_VECTOR_HEX])? else {
        return Ok(());
    };
    assert_eq!(token_response.command, "token-decrypt");
    assert_eq!(token_response.valid, Some(true));
    assert_eq!(
        token_response.plaintext_hex,
        Some("68656c6c6f20746f6b656e".to_owned())
    );

    let Some(ifac_response) = run_oracle(&["ifac-verify", "--hex", IFAC_VECTOR_HEX])? else {
        return Ok(());
    };
    assert_eq!(ifac_response.command, "ifac-verify");
    assert_eq!(ifac_response.valid, Some(true));
    assert_eq!(
        ifac_response.unmasked_hex,
        Some("00031111111111111111111111111111111100aabbcc".to_owned())
    );

    Ok(())
}

#[test]
fn rns_oracle_tool_rejects_unknown_cases() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&["hkdf-vector", "--case", "missing.case"])? else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown case"));
    assert!(output.stdout.is_empty());

    Ok(())
}

fn run_oracle(args: &[&str]) -> Result<Option<OracleResponse>, OracleToolError> {
    let Some(output) = run_oracle_raw(args)? else {
        return Ok(None);
    };
    if !output.status.success() {
        return Err(OracleToolError::OracleFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let response = serde_json::from_slice(&output.stdout)?;
    Ok(Some(response))
}

fn run_oracle_raw(args: &[&str]) -> Result<Option<std::process::Output>, OracleToolError> {
    let output = Command::new("uv")
        .arg("run")
        .arg("python")
        .arg(oracle_tool_path())
        .args(args)
        .output();

    match output {
        Ok(output) => Ok(Some(output)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("invalid oracle environment: uv command unavailable");
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn oracle_tool_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tools/rns_oracle/rns_oracle.py")
}

#[derive(Debug, Deserialize)]
struct OracleResponse {
    command: String,
    oracle: OracleMetadata,
    case: Option<OracleCase>,
    valid: Option<bool>,
    plaintext_hex: Option<String>,
    unmasked_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OracleMetadata {
    reticulum: ReticulumMetadata,
}

#[derive(Debug, Deserialize)]
struct ReticulumMetadata {
    commit: String,
}

#[derive(Debug, Deserialize)]
struct OracleCase {
    encoded_hex: Option<String>,
    kiss_frame_hex: Option<String>,
}

#[derive(Debug)]
enum OracleToolError {
    Io(String),
    Json(String),
    OracleFailed(String),
}

impl From<std::io::Error> for OracleToolError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for OracleToolError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl std::fmt::Display for OracleToolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) | Self::Json(error) | Self::OracleFailed(error) => {
                formatter.write_str(error)
            }
        }
    }
}

impl std::error::Error for OracleToolError {}

const TOKEN_VECTOR_HEX: &str = concat!(
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "111c0579413c7cd45de041e1e99e50a79a67288e721b62e303e18a6d4afcc34c75ff",
    "00a0919f0a0e67686886ede87f67",
);

const IFAC_VECTOR_HEX: &str = "dd38fc4c4749c011f90f9628d201d3afb2ff08c0741fd11d98a37c1b54ad";
