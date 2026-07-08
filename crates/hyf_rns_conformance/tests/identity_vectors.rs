use hyf_rns_core::full_hash;
use hyf_rns_crypto::{
    RNS_PUBLIC_IDENTITY_LEN, RNS_SECRET_IDENTITY_LEN, identity_hash, public_identity_from_bytes,
    public_identity_to_bytes, secret_identity_from_bytes, sign, verify,
};
use serde::Deserialize;

const FIXTURE: &str = include_str!("../../../fixtures/rns/identity_vectors.json");
const MANIFEST: &str = include_str!("../../../fixtures/rns/manifest.json");
const EXPECTED_SCHEMA: &str = "hyf.rns.fixture_case.v1";
const EXPECTED_MANIFEST_SCHEMA: &str = "hyf.rns.fixture_manifest.v1";
const EXPECTED_PROFILE: &str = "profile_0_packet_announce";
const RETICULUM_COMMIT_LEN: usize = 40;

#[derive(Debug, Deserialize)]
struct FixtureFile {
    schema: String,
    profile: String,
    reticulum: ReticulumProvenance,
    case: FixtureCase,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    schema: String,
    profile: String,
    reticulum: ReticulumProvenance,
    generated_by: String,
    generated_at: String,
    fixtures: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    file: String,
    category: String,
    case_count: usize,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ReticulumProvenance {
    repo: String,
    commit: String,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    inputs: FixtureInputs,
    expected: FixtureExpected,
}

#[derive(Debug, Deserialize)]
struct FixtureInputs {
    secret_identity: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    public_identity: String,
    identity_hash: String,
    signature: String,
}

#[test]
fn identity_fixture_matches_reticulum_oracle() -> Result<(), FixtureError> {
    let fixture = parse_fixture()?;
    let case = fixture.case;

    let secret_identity =
        decode_hex_exact::<RNS_SECRET_IDENTITY_LEN>(&case.inputs.secret_identity)?;
    let public_identity =
        decode_hex_exact::<RNS_PUBLIC_IDENTITY_LEN>(&case.expected.public_identity)?;
    let identity_hash_bytes = decode_hex_exact::<16>(&case.expected.identity_hash)?;
    let signature = decode_hex_exact::<64>(&case.expected.signature)?;
    let message = decode_hex(&case.inputs.message)?;

    let secret = secret_identity_from_bytes(&secret_identity)?;
    let derived_public = secret.public_identity()?;
    let oracle_public = public_identity_from_bytes(&public_identity)?;

    assert_eq!(public_identity_to_bytes(&derived_public), public_identity);
    assert_eq!(derived_public, oracle_public);
    assert_eq!(
        identity_hash(&oracle_public).into_bytes(),
        identity_hash_bytes
    );
    assert_eq!(sign(&secret, &message)?, signature);
    assert_eq!(verify(&oracle_public, &message, &signature), Ok(()));

    Ok(())
}

#[test]
fn fixture_manifest_tracks_identity_vector() -> Result<(), FixtureError> {
    let manifest: ManifestFile = serde_json::from_str(MANIFEST)?;

    assert_eq!(manifest.schema, EXPECTED_MANIFEST_SCHEMA);
    assert_eq!(manifest.profile, EXPECTED_PROFILE);
    assert_eq!(
        manifest.reticulum.repo,
        "https://github.com/markqvist/Reticulum"
    );
    assert_valid_reticulum_commit(&manifest.reticulum.commit);
    assert_eq!(
        manifest.reticulum.commit,
        "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
    );
    assert_eq!(
        manifest.generated_by,
        "hyf_rns_conformance phase06 oracle probe"
    );
    assert_eq!(manifest.generated_at, "2026-07-08T00:00:00Z");
    assert_eq!(manifest.fixtures.len(), 1);

    let entry = &manifest.fixtures[0];
    assert_eq!(entry.file, "identity_vectors.json");
    assert_eq!(entry.category, "identity_signature");
    assert_eq!(entry.case_count, 1);
    assert_eq!(
        full_hash(FIXTURE.as_bytes()).into_bytes(),
        decode_hex_exact::<32>(&entry.sha256)?
    );

    Ok(())
}

fn parse_fixture() -> Result<FixtureFile, FixtureError> {
    let fixture: FixtureFile = serde_json::from_str(FIXTURE)?;

    assert_eq!(fixture.schema, EXPECTED_SCHEMA);
    assert_eq!(fixture.profile, EXPECTED_PROFILE);
    assert_eq!(
        fixture.reticulum.repo,
        "https://github.com/markqvist/Reticulum"
    );
    assert_valid_reticulum_commit(&fixture.reticulum.commit);
    assert_eq!(
        fixture.reticulum.commit,
        "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
    );
    assert_eq!(
        fixture.case.id,
        "profile_0_packet_announce.identity_signature.synthetic.0001"
    );
    assert_eq!(fixture.case.category, "identity_signature");
    assert!(fixture.case.deterministic);
    assert!(fixture.case.private_test_material);

    Ok(fixture)
}

fn assert_valid_reticulum_commit(commit: &str) {
    assert_eq!(commit.len(), RETICULUM_COMMIT_LEN);
    assert!(commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(commit.bytes().all(|byte| !byte.is_ascii_uppercase()));
    assert_ne!(commit, "0000000000000000000000000000000000000000");
}

fn decode_hex_exact<const N: usize>(hex: &str) -> Result<[u8; N], FixtureError> {
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

fn decode_hex(hex: &str) -> Result<Vec<u8>, FixtureError> {
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
enum FixtureError {
    Json(String),
    Crypto(hyf_rns_crypto::RnsCryptoError),
    HexLength { actual: usize, expected: usize },
    InvalidHex,
    OddHexLength,
}

impl From<serde_json::Error> for FixtureError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<hyf_rns_crypto::RnsCryptoError> for FixtureError {
    fn from(error: hyf_rns_crypto::RnsCryptoError) -> Self {
        Self::Crypto(error)
    }
}
