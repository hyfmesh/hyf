use std::fmt;

use hyf_rns_core::full_hash;
use serde::{Deserialize, de::DeserializeOwned};

pub const EXPECTED_FIXTURE_SCHEMA: &str = "hyf.rns.fixture_case.v1";
pub const EXPECTED_FIXTURE_CASES_SCHEMA: &str = "hyf.rns.fixture_cases.v1";
pub const EXPECTED_MANIFEST_SCHEMA: &str = "hyf.rns.fixture_manifest.v1";
pub const EXPECTED_PROFILE: &str = "profile_0_packet_announce";
pub const EXPECTED_RETICULUM_COMMIT: &str = "422dc05549bf28f45e9b9c5172336a1ba4df0ec0";
pub const EXPECTED_RETICULUM_REPO: &str = "https://github.com/markqvist/Reticulum";

const RETICULUM_COMMIT_LEN: usize = 40;
const ZERO_RETICULUM_COMMIT: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Deserialize)]
pub struct FixtureFile<T> {
    pub schema: String,
    pub profile: String,
    pub reticulum: ReticulumProvenance,
    pub case: T,
}

#[derive(Debug, Deserialize)]
pub struct FixtureCasesFile<T> {
    pub schema: String,
    pub profile: String,
    pub reticulum: ReticulumProvenance,
    pub cases: Vec<T>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestFile {
    pub schema: String,
    pub profile: String,
    pub reticulum: ReticulumProvenance,
    pub generated_by: String,
    pub generated_at: String,
    pub fixtures: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestEntry {
    pub file: String,
    pub category: String,
    pub case_count: usize,
    pub sha256: String,
}

#[derive(Debug)]
pub struct ExpectedManifestEntry<'a> {
    pub file: &'a str,
    pub category: &'a str,
    pub case_count: usize,
    pub contents: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct ReticulumProvenance {
    pub repo: String,
    pub commit: String,
}

pub fn parse_fixture_case<T>(contents: &str) -> Result<FixtureFile<T>, FixtureError>
where
    T: DeserializeOwned,
{
    let fixture: FixtureFile<T> = serde_json::from_str(contents)?;

    validate_schema(&fixture.schema, EXPECTED_FIXTURE_SCHEMA)?;
    validate_profile(&fixture.profile)?;
    validate_reticulum_provenance(&fixture.reticulum)?;

    Ok(fixture)
}

pub fn parse_fixture_cases<T>(contents: &str) -> Result<FixtureCasesFile<T>, FixtureError>
where
    T: DeserializeOwned,
{
    let fixture: FixtureCasesFile<T> = serde_json::from_str(contents)?;

    validate_schema(&fixture.schema, EXPECTED_FIXTURE_CASES_SCHEMA)?;
    validate_profile(&fixture.profile)?;
    validate_reticulum_provenance(&fixture.reticulum)?;

    Ok(fixture)
}

pub fn parse_manifest(contents: &str) -> Result<ManifestFile, FixtureError> {
    let manifest: ManifestFile = serde_json::from_str(contents)?;

    validate_schema(&manifest.schema, EXPECTED_MANIFEST_SCHEMA)?;
    validate_profile(&manifest.profile)?;
    validate_reticulum_provenance(&manifest.reticulum)?;
    validate_manifest_metadata("generated_by", &manifest.generated_by)?;
    validate_manifest_metadata("generated_at", &manifest.generated_at)?;

    Ok(manifest)
}

fn validate_schema(actual: &str, expected: &'static str) -> Result<(), FixtureError> {
    if actual == expected {
        return Ok(());
    }

    Err(FixtureError::SchemaMismatch {
        actual: actual.to_owned(),
        expected,
    })
}

fn validate_profile(actual: &str) -> Result<(), FixtureError> {
    if actual == EXPECTED_PROFILE {
        return Ok(());
    }

    Err(FixtureError::ProfileMismatch {
        actual: actual.to_owned(),
        expected: EXPECTED_PROFILE,
    })
}

fn validate_reticulum_provenance(reticulum: &ReticulumProvenance) -> Result<(), FixtureError> {
    if reticulum.repo != EXPECTED_RETICULUM_REPO {
        return Err(FixtureError::ReticulumRepoMismatch {
            actual: reticulum.repo.clone(),
            expected: EXPECTED_RETICULUM_REPO,
        });
    }

    if !reticulum_commit_is_valid(&reticulum.commit) {
        return Err(FixtureError::InvalidReticulumCommit {
            commit: reticulum.commit.clone(),
        });
    }

    if reticulum.commit != EXPECTED_RETICULUM_COMMIT {
        return Err(FixtureError::ReticulumCommitMismatch {
            actual: reticulum.commit.clone(),
            expected: EXPECTED_RETICULUM_COMMIT,
        });
    }

    Ok(())
}

fn validate_manifest_metadata(field: &'static str, value: &str) -> Result<(), FixtureError> {
    if !value.is_empty() {
        return Ok(());
    }

    Err(FixtureError::MissingManifestMetadata { field })
}

pub fn reticulum_commit_is_valid(commit: &str) -> bool {
    commit.len() == RETICULUM_COMMIT_LEN
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        && commit.bytes().all(|byte| !byte.is_ascii_uppercase())
        && commit != ZERO_RETICULUM_COMMIT
}

pub fn assert_manifest_entry(
    manifest: &ManifestFile,
    file: &str,
    category: &str,
    case_count: usize,
    contents: &str,
) -> Result<(), FixtureError> {
    let Some(entry) = manifest.fixtures.iter().find(|entry| entry.file == file) else {
        return Err(FixtureError::MissingManifestEntry {
            file: file.to_owned(),
        });
    };

    if entry.category != category || entry.case_count != case_count {
        return Err(FixtureError::ManifestEntryMismatch {
            file: file.to_owned(),
        });
    }

    let expected_sha256 = decode_hex_exact::<32>(&entry.sha256)?;
    if full_hash(contents.as_bytes()).into_bytes() != expected_sha256 {
        return Err(FixtureError::ManifestChecksumMismatch {
            file: file.to_owned(),
        });
    }

    Ok(())
}

pub fn assert_exact_manifest_entries(
    manifest: &ManifestFile,
    expected_entries: &[ExpectedManifestEntry<'_>],
) -> Result<(), FixtureError> {
    for expected in expected_entries {
        match count_manifest_entries(manifest, expected.file) {
            0 => {
                return Err(FixtureError::MissingManifestEntry {
                    file: expected.file.to_owned(),
                });
            }
            1 => assert_manifest_entry(
                manifest,
                expected.file,
                expected.category,
                expected.case_count,
                expected.contents,
            )?,
            _ => {
                return Err(FixtureError::DuplicateManifestEntry {
                    file: expected.file.to_owned(),
                });
            }
        }
    }

    for entry in &manifest.fixtures {
        if !expected_entries
            .iter()
            .any(|expected| expected.file == entry.file)
        {
            return Err(FixtureError::UnexpectedManifestEntry {
                file: entry.file.clone(),
            });
        }
    }

    Ok(())
}

fn count_manifest_entries(manifest: &ManifestFile, file: &str) -> usize {
    manifest
        .fixtures
        .iter()
        .filter(|entry| entry.file == file)
        .count()
}

pub fn decode_hex_exact<const N: usize>(hex: &str) -> Result<[u8; N], FixtureError> {
    let bytes = decode_hex(hex)?;
    if bytes.len() != N {
        return Err(FixtureError::HexLength {
            actual: bytes.len(),
            expected: N,
        });
    }

    let mut output = [0; N];
    output.copy_from_slice(&bytes);
    Ok(output)
}

pub fn decode_optional_hex_exact<const N: usize>(
    hex: &Option<String>,
) -> Result<Option<[u8; N]>, FixtureError> {
    let Some(hex) = hex else {
        return Ok(None);
    };

    Ok(Some(decode_hex_exact::<N>(hex)?))
}

pub fn decode_hex(hex: &str) -> Result<Vec<u8>, FixtureError> {
    if !hex.len().is_multiple_of(2) {
        return Err(FixtureError::OddHexLength);
    }

    let mut output = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }

    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, FixtureError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(FixtureError::InvalidHex),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum FixtureError {
    Json(String),
    Core(hyf_rns_core::RnsCoreError),
    Crypto(hyf_rns_crypto::RnsCryptoError),
    Wire(hyf_rns_wire::RnsWireError),
    SchemaMismatch {
        actual: String,
        expected: &'static str,
    },
    ProfileMismatch {
        actual: String,
        expected: &'static str,
    },
    ReticulumRepoMismatch {
        actual: String,
        expected: &'static str,
    },
    InvalidReticulumCommit {
        commit: String,
    },
    ReticulumCommitMismatch {
        actual: String,
        expected: &'static str,
    },
    MissingManifestMetadata {
        field: &'static str,
    },
    HexLength {
        actual: usize,
        expected: usize,
    },
    InvalidHex,
    OddHexLength,
    MissingManifestEntry {
        file: String,
    },
    DuplicateManifestEntry {
        file: String,
    },
    UnexpectedManifestEntry {
        file: String,
    },
    ManifestEntryMismatch {
        file: String,
    },
    ManifestChecksumMismatch {
        file: String,
    },
    UnexpectedFixtureValue {
        field: String,
        value: String,
    },
}

impl From<serde_json::Error> for FixtureError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<hyf_rns_core::RnsCoreError> for FixtureError {
    fn from(error: hyf_rns_core::RnsCoreError) -> Self {
        Self::Core(error)
    }
}

impl From<hyf_rns_crypto::RnsCryptoError> for FixtureError {
    fn from(error: hyf_rns_crypto::RnsCryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<hyf_rns_wire::RnsWireError> for FixtureError {
    fn from(error: hyf_rns_wire::RnsWireError) -> Self {
        Self::Wire(error)
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "json error: {error}"),
            Self::Core(error) => write!(formatter, "core error: {error}"),
            Self::Crypto(error) => write!(formatter, "crypto error: {error}"),
            Self::Wire(error) => write!(formatter, "wire error: {error}"),
            Self::SchemaMismatch { actual, expected } => {
                write!(
                    formatter,
                    "schema mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ProfileMismatch { actual, expected } => {
                write!(
                    formatter,
                    "profile mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ReticulumRepoMismatch { actual, expected } => {
                write!(
                    formatter,
                    "Reticulum repo mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidReticulumCommit { commit } => {
                write!(formatter, "invalid Reticulum commit: {commit}")
            }
            Self::ReticulumCommitMismatch { actual, expected } => {
                write!(
                    formatter,
                    "Reticulum commit mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MissingManifestMetadata { field } => {
                write!(formatter, "missing manifest metadata: {field}")
            }
            Self::HexLength { actual, expected } => {
                write!(
                    formatter,
                    "hex length mismatch: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidHex => formatter.write_str("invalid hex"),
            Self::OddHexLength => formatter.write_str("odd hex length"),
            Self::MissingManifestEntry { file } => {
                write!(formatter, "missing manifest entry: {file}")
            }
            Self::DuplicateManifestEntry { file } => {
                write!(formatter, "duplicate manifest entry: {file}")
            }
            Self::UnexpectedManifestEntry { file } => {
                write!(formatter, "unexpected manifest entry: {file}")
            }
            Self::ManifestEntryMismatch { file } => {
                write!(formatter, "manifest entry mismatch: {file}")
            }
            Self::ManifestChecksumMismatch { file } => {
                write!(formatter, "manifest checksum mismatch: {file}")
            }
            Self::UnexpectedFixtureValue { field, value } => {
                write!(formatter, "unexpected fixture value for {field}: {value}")
            }
        }
    }
}

impl std::error::Error for FixtureError {}

#[cfg(test)]
mod tests {
    use hyf_rns_core::RnsCoreError;
    use hyf_rns_crypto::RnsCryptoError;
    use hyf_rns_wire::RnsWireError;
    use serde_json::Value;

    use super::{
        EXPECTED_FIXTURE_SCHEMA, EXPECTED_PROFILE, EXPECTED_RETICULUM_COMMIT,
        EXPECTED_RETICULUM_REPO, FixtureError, decode_hex, parse_fixture_case, parse_fixture_cases,
        parse_manifest, reticulum_commit_is_valid,
    };

    #[test]
    fn reticulum_commit_validation_rejects_uppercase_and_all_zero_commits() {
        assert!(reticulum_commit_is_valid(
            "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
        ));
        assert!(!reticulum_commit_is_valid(
            "422DC05549BF28F45E9B9C5172336A1BA4DF0EC0"
        ));
        assert!(!reticulum_commit_is_valid(
            "0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn hex_decoder_accepts_lowercase_and_rejects_uppercase() {
        assert_eq!(decode_hex("0a10ff"), Ok(vec![0x0a, 0x10, 0xff]));
        assert_eq!(decode_hex("0A"), Err(FixtureError::InvalidHex));
    }

    #[test]
    fn fixture_error_display_uses_stable_first_party_error_text() {
        assert_eq!(
            FixtureError::Core(RnsCoreError::DestinationAppNameContainsDot).to_string(),
            "core error: destination app name contains dot"
        );
        assert_eq!(
            FixtureError::Crypto(RnsCryptoError::InvalidSignature).to_string(),
            "crypto error: invalid signature"
        );
        assert_eq!(
            FixtureError::Wire(RnsWireError::PacketTooShort {
                actual: 1,
                minimum: 2,
            })
            .to_string(),
            "wire error: packet too short: actual 1, minimum 2"
        );
    }

    #[test]
    fn fixture_case_validation_returns_typed_schema_and_profile_errors() {
        let schema_result = parse_fixture_case::<Value>(
            r#"{
                "schema": "wrong",
                "profile": "profile_0_packet_announce",
                "reticulum": {
                    "repo": "https://github.com/markqvist/Reticulum",
                    "commit": "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
                },
                "case": {}
            }"#,
        );
        assert!(matches!(
            schema_result,
            Err(FixtureError::SchemaMismatch {
                actual,
                expected: EXPECTED_FIXTURE_SCHEMA,
            }) if actual == "wrong"
        ));

        let profile_result = parse_fixture_case::<Value>(
            r#"{
                "schema": "hyf.rns.fixture_case.v1",
                "profile": "wrong_profile",
                "reticulum": {
                    "repo": "https://github.com/markqvist/Reticulum",
                    "commit": "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
                },
                "case": {}
            }"#,
        );
        assert!(matches!(
            profile_result,
            Err(FixtureError::ProfileMismatch {
                actual,
                expected: EXPECTED_PROFILE,
            }) if actual == "wrong_profile"
        ));
    }

    #[test]
    fn fixture_cases_validation_returns_typed_provenance_errors() {
        let repo_result = parse_fixture_cases::<Value>(
            r#"{
                "schema": "hyf.rns.fixture_cases.v1",
                "profile": "profile_0_packet_announce",
                "reticulum": {
                    "repo": "https://example.invalid/Reticulum",
                    "commit": "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
                },
                "cases": []
            }"#,
        );
        assert!(matches!(
            repo_result,
            Err(FixtureError::ReticulumRepoMismatch {
                actual,
                expected: EXPECTED_RETICULUM_REPO,
            }) if actual == "https://example.invalid/Reticulum"
        ));

        let invalid_commit_result = parse_fixture_cases::<Value>(
            r#"{
                "schema": "hyf.rns.fixture_cases.v1",
                "profile": "profile_0_packet_announce",
                "reticulum": {
                    "repo": "https://github.com/markqvist/Reticulum",
                    "commit": "422DC05549BF28F45E9B9C5172336A1BA4DF0EC0"
                },
                "cases": []
            }"#,
        );
        assert!(matches!(
            invalid_commit_result,
            Err(FixtureError::InvalidReticulumCommit { commit })
                if commit == "422DC05549BF28F45E9B9C5172336A1BA4DF0EC0"
        ));

        let mismatch_result = parse_fixture_cases::<Value>(
            r#"{
                "schema": "hyf.rns.fixture_cases.v1",
                "profile": "profile_0_packet_announce",
                "reticulum": {
                    "repo": "https://github.com/markqvist/Reticulum",
                    "commit": "1111111111111111111111111111111111111111"
                },
                "cases": []
            }"#,
        );
        assert!(matches!(
            mismatch_result,
            Err(FixtureError::ReticulumCommitMismatch {
                actual,
                expected: EXPECTED_RETICULUM_COMMIT,
            }) if actual == "1111111111111111111111111111111111111111"
        ));
    }

    #[test]
    fn manifest_validation_returns_typed_metadata_errors() {
        let generated_by_result = parse_manifest(
            r#"{
                "schema": "hyf.rns.fixture_manifest.v1",
                "profile": "profile_0_packet_announce",
                "reticulum": {
                    "repo": "https://github.com/markqvist/Reticulum",
                    "commit": "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
                },
                "generated_by": "",
                "generated_at": "2026-07-08T00:00:00Z",
                "fixtures": []
            }"#,
        );
        assert!(matches!(
            generated_by_result,
            Err(FixtureError::MissingManifestMetadata {
                field: "generated_by",
            })
        ));

        let generated_at_result = parse_manifest(
            r#"{
                "schema": "hyf.rns.fixture_manifest.v1",
                "profile": "profile_0_packet_announce",
                "reticulum": {
                    "repo": "https://github.com/markqvist/Reticulum",
                    "commit": "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
                },
                "generated_by": "test",
                "generated_at": "",
                "fixtures": []
            }"#,
        );
        assert!(matches!(
            generated_at_result,
            Err(FixtureError::MissingManifestMetadata {
                field: "generated_at",
            })
        ));
    }
}
