#![cfg(feature = "python_oracle")]

use std::path::{Path, PathBuf};
use std::process::Command;

use hyf_rns_conformance::{
    PINNED_CRYPTOGRAPHY_PACKAGE, PINNED_PYSERIAL_PACKAGE, fixtures::EXPECTED_RETICULUM_COMMIT,
};
use hyf_rns_crypto::{
    RNS_TOKEN_IV_LEN, RnsCryptoError, token_encrypt_with_iv, token_retag_for_test_vectors,
};
use serde::Deserialize;

#[test]
fn rns_oracle_tool_replays_profile_1_and_profile_2_vectors() -> Result<(), OracleToolError> {
    let Some(kiss_response) =
        run_oracle(&["kiss-encode", "--case", "kiss.data.escapes_fend_fesc_001"])?
    else {
        return Ok(());
    };
    assert_eq!(kiss_response.command, "kiss-encode");
    assert_eq!(kiss_response.oracle.mode, "fixture_replay");
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
    assert_eq!(token_response.oracle.mode, "fixture_replay");
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

#[test]
fn rns_oracle_tool_rejects_bad_hex_inputs() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&["token-decrypt", "--hex", "abc"])? else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("token hex must have an even length"));
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_tool_rejects_bad_test_only_inputs() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&[
        "token-decrypt",
        "--hex",
        TOKEN_VECTOR_HEX,
        "--test-token-key-hex",
        "00",
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("test token key hex must be 32 or 64 bytes")
    );
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_probe_rejects_invalid_environment() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&[
        "probe",
        "--reticulum-path",
        "/definitely/not/a/reticulum/checkout",
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("invalid_environment: Reticulum path is not a directory")
    );
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_tool_validates_rust_generated_token_with_reticulum() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };
    let mut token = [0; 128];
    let token_len = token_encrypt_with_iv(&TOKEN_KEY_32, TOKEN_PLAINTEXT, TOKEN_IV, &mut token)?;
    let args = token_oracle_args(&token[..token_len], &TOKEN_KEY_32, &reticulum_path);
    let Some(response) = run_oracle_with_packages(&args)? else {
        return Ok(());
    };

    assert_eq!(response.command, "token-decrypt");
    assert_eq!(response.oracle.mode, "python_reticulum");
    assert_eq!(response.valid, Some(true));
    assert_eq!(response.plaintext_hex, Some(hex(TOKEN_PLAINTEXT)));

    Ok(())
}

#[test]
fn rns_oracle_tool_reports_reticulum_token_failures() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };

    let short_args = token_oracle_args(&[0; 16], &TOKEN_KEY_32, &reticulum_path);
    let Some(short_response) = run_oracle_with_packages(&short_args)? else {
        return Ok(());
    };
    assert_eq!(short_response.oracle.mode, "python_reticulum");
    assert_eq!(short_response.valid, Some(false));
    assert_eq!(short_response.error, Some("invalid_token".to_owned()));

    let mut bad_hmac = [0; 128];
    let bad_hmac_len =
        token_encrypt_with_iv(&TOKEN_KEY_32, TOKEN_PLAINTEXT, TOKEN_IV, &mut bad_hmac)?;
    bad_hmac[bad_hmac_len - 1] ^= 0x01;
    let bad_hmac_args =
        token_oracle_args(&bad_hmac[..bad_hmac_len], &TOKEN_KEY_32, &reticulum_path);
    let Some(bad_hmac_response) = run_oracle_with_packages(&bad_hmac_args)? else {
        return Ok(());
    };
    assert_eq!(bad_hmac_response.oracle.mode, "python_reticulum");
    assert_eq!(bad_hmac_response.valid, Some(false));
    assert_eq!(
        bad_hmac_response.error,
        Some("authentication_failed".to_owned())
    );

    let mut bad_padding = [0; 128];
    let bad_padding_len =
        token_encrypt_with_iv(&TOKEN_KEY_32, TOKEN_PLAINTEXT, TOKEN_IV, &mut bad_padding)?;
    bad_padding[RNS_TOKEN_IV_LEN - 1] ^= 0x20;
    token_retag_for_test_vectors(&TOKEN_KEY_32, &mut bad_padding[..bad_padding_len])?;
    let bad_padding_args = token_oracle_args(
        &bad_padding[..bad_padding_len],
        &TOKEN_KEY_32,
        &reticulum_path,
    );
    let Some(bad_padding_response) = run_oracle_with_packages(&bad_padding_args)? else {
        return Ok(());
    };
    assert_eq!(bad_padding_response.oracle.mode, "python_reticulum");
    assert_eq!(bad_padding_response.valid, Some(false));
    assert_eq!(
        bad_padding_response.error,
        Some("invalid_padding".to_owned())
    );

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

fn run_oracle_with_packages(args: &[String]) -> Result<Option<OracleResponse>, OracleToolError> {
    let output = Command::new("uv")
        .arg("run")
        .arg("--with")
        .arg(PINNED_CRYPTOGRAPHY_PACKAGE)
        .arg("--with")
        .arg(PINNED_PYSERIAL_PACKAGE)
        .arg("python")
        .arg(oracle_tool_path())
        .args(args)
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                return Err(OracleToolError::OracleFailed(
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }
            Ok(Some(serde_json::from_slice(&output.stdout)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("invalid oracle environment: uv command unavailable");
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
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

fn token_oracle_args(token: &[u8], key: &[u8], reticulum_path: &Path) -> Vec<String> {
    vec![
        "token-decrypt".to_owned(),
        "--hex".to_owned(),
        hex(token),
        "--test-token-key-hex".to_owned(),
        hex(key),
        "--reticulum-path".to_owned(),
        reticulum_path.to_string_lossy().into_owned(),
    ]
}

fn reticulum_path_for_tool() -> Result<Option<PathBuf>, OracleToolError> {
    if let Some(path) = std::env::var_os("HYF_RETICULUM_PATH").map(PathBuf::from)
        && let Some(path) = resolve_reticulum_candidate(path)?
    {
        return Ok(Some(path));
    }

    let default_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("refs/Reticulum");
    resolve_reticulum_candidate(default_path)
}

fn resolve_reticulum_candidate(path: PathBuf) -> Result<Option<PathBuf>, OracleToolError> {
    if path.is_dir() {
        return Ok(Some(path.canonicalize()?));
    }
    if path.is_absolute() {
        return Ok(None);
    }

    let current_dir_path = std::env::current_dir()?.join(&path);
    if current_dir_path.is_dir() {
        return Ok(Some(current_dir_path.canonicalize()?));
    }

    let workspace_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(&path);
    if workspace_path.is_dir() {
        return Ok(Some(workspace_path.canonicalize()?));
    }

    Ok(None)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Deserialize)]
struct OracleResponse {
    command: String,
    oracle: OracleMetadata,
    case: Option<OracleCase>,
    valid: Option<bool>,
    plaintext_hex: Option<String>,
    unmasked_hex: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OracleMetadata {
    mode: String,
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
    Crypto(String),
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

impl From<RnsCryptoError> for OracleToolError {
    fn from(error: RnsCryptoError) -> Self {
        Self::Crypto(error.to_string())
    }
}

impl std::fmt::Display for OracleToolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error)
            | Self::Json(error)
            | Self::Crypto(error)
            | Self::OracleFailed(error) => formatter.write_str(error),
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

const TOKEN_PLAINTEXT: &[u8] = b"hello token";
const TOKEN_KEY_32: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const TOKEN_IV: [u8; RNS_TOKEN_IV_LEN] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
