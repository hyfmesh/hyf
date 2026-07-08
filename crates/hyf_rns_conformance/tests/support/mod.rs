#![allow(dead_code)]

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

    assert_eq!(fixture.schema, EXPECTED_FIXTURE_SCHEMA);
    assert_eq!(fixture.profile, EXPECTED_PROFILE);
    assert_reticulum_provenance(&fixture.reticulum);

    Ok(fixture)
}

pub fn parse_fixture_cases<T>(contents: &str) -> Result<FixtureCasesFile<T>, FixtureError>
where
    T: DeserializeOwned,
{
    let fixture: FixtureCasesFile<T> = serde_json::from_str(contents)?;

    assert_eq!(fixture.schema, EXPECTED_FIXTURE_CASES_SCHEMA);
    assert_eq!(fixture.profile, EXPECTED_PROFILE);
    assert_reticulum_provenance(&fixture.reticulum);

    Ok(fixture)
}

pub fn parse_manifest(contents: &str) -> Result<ManifestFile, FixtureError> {
    let manifest: ManifestFile = serde_json::from_str(contents)?;

    assert_eq!(manifest.schema, EXPECTED_MANIFEST_SCHEMA);
    assert_eq!(manifest.profile, EXPECTED_PROFILE);
    assert_reticulum_provenance(&manifest.reticulum);
    assert!(!manifest.generated_by.is_empty());
    assert!(!manifest.generated_at.is_empty());

    Ok(manifest)
}

pub fn assert_reticulum_provenance(reticulum: &ReticulumProvenance) {
    assert_eq!(reticulum.repo, EXPECTED_RETICULUM_REPO);
    assert!(reticulum_commit_is_valid(&reticulum.commit));
    assert_eq!(reticulum.commit, EXPECTED_RETICULUM_COMMIT);
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
    HexLength { actual: usize, expected: usize },
    InvalidHex,
    OddHexLength,
    MissingManifestEntry { file: String },
    DuplicateManifestEntry { file: String },
    UnexpectedManifestEntry { file: String },
    ManifestEntryMismatch { file: String },
    ManifestChecksumMismatch { file: String },
    UnexpectedFixtureValue { field: String, value: String },
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

#[cfg(test)]
mod tests {
    use super::{FixtureError, decode_hex, reticulum_commit_is_valid};

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
}
