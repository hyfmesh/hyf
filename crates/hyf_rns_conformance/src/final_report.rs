use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use serde_json::Value;

use crate::fixtures::EXPECTED_RETICULUM_COMMIT;
use crate::report::{ConformanceResult, ConformanceStatus, OracleEnvironment};

pub const DETAIL_KEY_ORACLE_MODE: &str = "oracle_mode";
pub const DETAIL_KEY_EVIDENCE_ROLE: &str = "evidence_role";
pub const DETAIL_KEY_COMPATIBILITY_PROOF: &str = "compatibility_proof";
pub const DETAIL_KEY_COMMANDS: &str = "commands";
pub const DETAIL_KEY_RETICULUM_COMMIT: &str = "reticulum_commit";
pub const EXPECTED_FINAL_ORACLE_RNS_VERSION: &str = "1.3.5";
pub const EXPECTED_FINAL_ORACLE_CRYPTOGRAPHY_VERSION: &str = "49.0.0";
pub const EXPECTED_FINAL_ORACLE_PYSERIAL_VERSION: &str = "3.5";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedOracleDetail<'a> {
    pub oracle_mode: &'a str,
    pub evidence_role: &'a str,
    pub compatibility_proof: bool,
    pub commands: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedFinalResult<'a> {
    pub id: &'a str,
    pub category: &'a str,
    pub detail: Option<ExpectedOracleDetail<'a>>,
}

#[derive(Debug)]
pub enum FinalReportError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidEvidence(String),
}

impl From<std::io::Error> for FinalReportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for FinalReportError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl std::fmt::Display for FinalReportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::InvalidEvidence(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for FinalReportError {}

pub fn oracle_detail(
    oracle_mode: &str,
    evidence_role: &str,
    compatibility_proof: bool,
    commands: &[String],
    reticulum_commit: &str,
) -> String {
    let proof = if compatibility_proof { "true" } else { "false" };
    format!(
        "{DETAIL_KEY_ORACLE_MODE}={oracle_mode}; \
         {DETAIL_KEY_EVIDENCE_ROLE}={evidence_role}; \
         {DETAIL_KEY_COMPATIBILITY_PROOF}={proof}; \
         {DETAIL_KEY_COMMANDS}={}; \
         {DETAIL_KEY_RETICULUM_COMMIT}={reticulum_commit}",
        commands.join(",")
    )
}

pub fn load_capture(capture_dir: &Path, filename: &str) -> Result<Value, FinalReportError> {
    let path = capture_dir.join(filename);
    let contents = fs::read_to_string(path)?;
    let document: Value = serde_json::from_str(&contents)?;
    if document.as_object().is_none() {
        return Err(invalid_evidence(format!("{filename} is not a JSON object")));
    }
    Ok(document)
}

pub fn expect_capture(
    document: &Value,
    filename: &str,
    command: &str,
    mode: &str,
    reticulum_commit: &str,
) -> Result<(), FinalReportError> {
    expect_string_field(document, filename, "command", command)?;
    expect_string_path(document, filename, &["oracle", "mode"], mode)?;
    expect_string_path(
        document,
        filename,
        &["oracle", "reticulum", "commit"],
        reticulum_commit,
    )
}

pub fn expect_bool_field(
    document: &Value,
    filename: &str,
    field: &str,
    expected: bool,
) -> Result<(), FinalReportError> {
    let Some(actual) = document.get(field).and_then(Value::as_bool) else {
        return Err(invalid_evidence(format!(
            "{filename} is missing boolean field {field}"
        )));
    };
    if actual != expected {
        return Err(invalid_evidence(format!(
            "{filename} has wrong {field}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

pub fn expect_string_field(
    document: &Value,
    filename: &str,
    field: &str,
    expected: &str,
) -> Result<(), FinalReportError> {
    let actual = required_string_field(document, filename, field)?;
    if actual != expected {
        return Err(invalid_evidence(format!(
            "{filename} has wrong {field}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

pub fn required_string_field<'a>(
    document: &'a Value,
    filename: &str,
    field: &str,
) -> Result<&'a str, FinalReportError> {
    let Some(actual) = document.get(field).and_then(Value::as_str) else {
        return Err(invalid_evidence(format!(
            "{filename} is missing string field {field}"
        )));
    };
    if actual.is_empty() {
        return Err(invalid_evidence(format!(
            "{filename} has empty string field {field}"
        )));
    }
    Ok(actual)
}

pub fn optional_string_field<'a>(
    document: &'a Value,
    field: &str,
) -> Result<Option<&'a str>, FinalReportError> {
    let Some(value) = document.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(invalid_evidence(format!("{field} is not a string")));
    };
    if value.is_empty() {
        return Err(invalid_evidence(format!("{field} is empty")));
    }
    Ok(Some(value))
}

pub fn require_equal(actual: &str, expected: &str, message: &str) -> Result<(), FinalReportError> {
    if actual != expected {
        return Err(invalid_evidence(format!(
            "{message}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

pub fn validate_final_oracle_metadata(
    oracle: &OracleEnvironment,
    expected_oracle_module_path: Option<&str>,
) -> Result<(), FinalReportError> {
    if let Some(expected_oracle_module_path) = expected_oracle_module_path
        && oracle.reticulum_module_path != expected_oracle_module_path
    {
        return Err(invalid_evidence("oracle Reticulum module path mismatch"));
    }
    if !is_portable_repo_relative_path(&oracle.reticulum_module_path) {
        return Err(invalid_evidence(
            "oracle Reticulum module path is not portable repo-relative",
        ));
    }
    if oracle.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
        return Err(invalid_evidence("oracle reticulum commit mismatch"));
    }
    if oracle.rns_version.as_deref() != Some(EXPECTED_FINAL_ORACLE_RNS_VERSION) {
        return Err(invalid_evidence("oracle RNS version mismatch"));
    }
    if oracle.cryptography_version != EXPECTED_FINAL_ORACLE_CRYPTOGRAPHY_VERSION {
        return Err(invalid_evidence("oracle cryptography version mismatch"));
    }
    if oracle.pyserial_version != EXPECTED_FINAL_ORACLE_PYSERIAL_VERSION {
        return Err(invalid_evidence("oracle pyserial version mismatch"));
    }
    Ok(())
}

fn is_portable_repo_relative_path(value: &str) -> bool {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.contains("//")
    {
        return false;
    }

    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

pub fn validate_final_results(
    results: &[ConformanceResult],
    expected: &[ExpectedFinalResult<'_>],
    reticulum_commit: &str,
) -> Result<(), FinalReportError> {
    if results.len() != expected.len() {
        return Err(invalid_evidence(format!(
            "result count mismatch: expected {}, got {}",
            expected.len(),
            results.len()
        )));
    }

    let mut seen_ids = BTreeSet::new();
    for result in results {
        if !seen_ids.insert(result.id.as_str()) {
            return Err(invalid_evidence(format!(
                "duplicate result id: {}",
                result.id
            )));
        }
    }

    for expected_row in expected {
        let Some(result) = results.iter().find(|result| result.id == expected_row.id) else {
            return Err(invalid_evidence(format!(
                "missing result id: {}",
                expected_row.id
            )));
        };
        if result.category != expected_row.category {
            return Err(invalid_evidence(format!(
                "{} has wrong category: expected {}, got {}",
                expected_row.id, expected_row.category, result.category
            )));
        }
        if result.status != ConformanceStatus::Passed {
            return Err(invalid_evidence(format!(
                "{} has wrong status: expected passed",
                expected_row.id
            )));
        }
        validate_detail(result, expected_row.detail, reticulum_commit)?;
    }

    for result in results {
        if !expected
            .iter()
            .any(|expected_row| expected_row.id == result.id.as_str())
        {
            return Err(invalid_evidence(format!(
                "unexpected result id: {}",
                result.id
            )));
        }
    }

    Ok(())
}

fn validate_detail(
    result: &ConformanceResult,
    expected: Option<ExpectedOracleDetail<'_>>,
    reticulum_commit: &str,
) -> Result<(), FinalReportError> {
    let Some(expected) = expected else {
        if result.detail.is_some() {
            return Err(invalid_evidence(format!(
                "{} has unexpected detail",
                result.id
            )));
        }
        return Ok(());
    };

    let Some(detail) = result.detail.as_deref() else {
        return Err(invalid_evidence(format!("{} is missing detail", result.id)));
    };
    let fields = parse_detail_fields(detail, &result.id)?;
    expect_detail_field(
        &fields,
        &result.id,
        DETAIL_KEY_ORACLE_MODE,
        expected.oracle_mode,
    )?;
    expect_detail_field(
        &fields,
        &result.id,
        DETAIL_KEY_EVIDENCE_ROLE,
        expected.evidence_role,
    )?;
    let compatibility_proof = if expected.compatibility_proof {
        "true"
    } else {
        "false"
    };
    expect_detail_field(
        &fields,
        &result.id,
        DETAIL_KEY_COMPATIBILITY_PROOF,
        compatibility_proof,
    )?;
    expect_detail_field(&fields, &result.id, DETAIL_KEY_COMMANDS, expected.commands)?;
    expect_detail_field(
        &fields,
        &result.id,
        DETAIL_KEY_RETICULUM_COMMIT,
        reticulum_commit,
    )?;
    if fields.len() != 5 {
        return Err(invalid_evidence(format!(
            "{} has unexpected detail fields",
            result.id
        )));
    }
    Ok(())
}

fn parse_detail_fields(
    detail: &str,
    result_id: &str,
) -> Result<Vec<(String, String)>, FinalReportError> {
    let mut fields = Vec::new();
    for raw_part in detail.split(';') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(invalid_evidence(format!(
                "{result_id} has malformed detail part: {part}"
            )));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(invalid_evidence(format!(
                "{result_id} has empty detail key or value"
            )));
        }
        if fields.iter().any(|(existing_key, _)| existing_key == key) {
            return Err(invalid_evidence(format!(
                "{result_id} duplicates detail field {key}"
            )));
        }
        fields.push((key.to_owned(), value.to_owned()));
    }
    Ok(fields)
}

fn expect_detail_field(
    fields: &[(String, String)],
    result_id: &str,
    key: &str,
    expected: &str,
) -> Result<(), FinalReportError> {
    let Some((_, actual)) = fields.iter().find(|(field_key, _)| field_key == key) else {
        return Err(invalid_evidence(format!("{result_id} is missing {key}")));
    };
    if actual != expected {
        return Err(invalid_evidence(format!(
            "{result_id} has wrong {key}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn expect_string_path(
    document: &Value,
    filename: &str,
    path: &[&str],
    expected: &str,
) -> Result<(), FinalReportError> {
    let actual = string_path(document, filename, path)?;
    if actual != expected {
        return Err(invalid_evidence(format!(
            "{filename} has wrong {}: expected {expected}, got {actual}",
            path.join(".")
        )));
    }
    Ok(())
}

fn string_path<'a>(
    document: &'a Value,
    filename: &str,
    path: &[&str],
) -> Result<&'a str, FinalReportError> {
    let mut value = document;
    for key in path {
        let Some(next) = value.get(*key) else {
            return Err(invalid_evidence(format!(
                "{filename} is missing {}",
                path.join(".")
            )));
        };
        value = next;
    }
    let Some(value) = value.as_str() else {
        return Err(invalid_evidence(format!(
            "{} in {filename} is not a string",
            path.join(".")
        )));
    };
    if value.is_empty() {
        return Err(invalid_evidence(format!(
            "{} in {filename} is empty",
            path.join(".")
        )));
    }
    Ok(value)
}

pub fn invalid_evidence(message: impl Into<String>) -> FinalReportError {
    FinalReportError::InvalidEvidence(message.into())
}
