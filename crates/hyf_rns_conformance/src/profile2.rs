use std::collections::BTreeSet;

use serde_json::Value;

use crate::fixtures::{
    ExpectedManifestEntry, FixtureCasesFile, FixtureError, PROFILE_2_CRYPTO_IFAC,
    assert_exact_manifest_entries, parse_fixture_cases_for_profile, parse_manifest_for_profile,
};
use crate::report::{ConformanceEnvironment, ConformanceResult, ConformanceRun};
use crate::runner::{fixture_result, invalid_environment_result};

pub const CATEGORY_FIXTURE_MANIFEST: &str = "fixture_manifest";
pub const CATEGORY_HKDF: &str = "hkdf";
pub const CATEGORY_TOKEN: &str = "token";
pub const CATEGORY_IDENTITY_ENCRYPT: &str = "identity_encrypt";
pub const CATEGORY_IDENTITY_DECRYPT: &str = "identity_decrypt";
pub const CATEGORY_IFAC: &str = "ifac";
pub const CATEGORY_RNS_ORACLE_FIXTURE_REPLAY: &str = "rns_oracle_fixture_replay";
pub const CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM: &str = "rns_oracle_test_only_shim";
pub const CATEGORY_RNS_ORACLE_PYTHON_RETICULUM: &str = "rns_oracle_python_reticulum";

pub const RESULT_ID_FIXTURE_MANIFEST: &str = "profile_2_crypto_ifac.fixture_manifest";
pub const RESULT_ID_HKDF: &str = "profile_2_crypto_ifac.hkdf";
pub const RESULT_ID_TOKEN: &str = "profile_2_crypto_ifac.token";
pub const RESULT_ID_IDENTITY_ENCRYPT: &str = "profile_2_crypto_ifac.identity_encrypt";
pub const RESULT_ID_IDENTITY_DECRYPT: &str = "profile_2_crypto_ifac.identity_decrypt";
pub const RESULT_ID_IFAC: &str = "profile_2_crypto_ifac.ifac";
pub const RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY: &str =
    "profile_2_crypto_ifac.rns_oracle.fixture_replay";
pub const RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_TOKEN_GENERATION: &str =
    "profile_2_crypto_ifac.rns_oracle.test_only_oracle_shim.token_generation";
pub const RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_TOKEN: &str =
    "profile_2_crypto_ifac.rns_oracle.python_reticulum.token";
pub const RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_IDENTITY_GENERATION: &str =
    "profile_2_crypto_ifac.rns_oracle.test_only_oracle_shim.identity_generation";
pub const RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IDENTITY: &str =
    "profile_2_crypto_ifac.rns_oracle.python_reticulum.identity";
pub const RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IFAC: &str =
    "profile_2_crypto_ifac.rns_oracle.python_reticulum.ifac";

pub const REQUIRED_PROFILE_2_RESULTS: &[(&str, &str)] = &[
    (RESULT_ID_FIXTURE_MANIFEST, CATEGORY_FIXTURE_MANIFEST),
    (RESULT_ID_HKDF, CATEGORY_HKDF),
    (RESULT_ID_TOKEN, CATEGORY_TOKEN),
    (RESULT_ID_IDENTITY_ENCRYPT, CATEGORY_IDENTITY_ENCRYPT),
    (RESULT_ID_IDENTITY_DECRYPT, CATEGORY_IDENTITY_DECRYPT),
    (RESULT_ID_IFAC, CATEGORY_IFAC),
    (
        RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY,
        CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
    ),
    (
        RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_TOKEN_GENERATION,
        CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
    ),
    (
        RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_TOKEN,
        CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
    ),
    (
        RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_IDENTITY_GENERATION,
        CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
    ),
    (
        RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IDENTITY,
        CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
    ),
    (
        RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IFAC,
        CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
    ),
];

pub const REQUIRED_PROFILE_2_RESULT_CATEGORIES: &[&str] = &[
    CATEGORY_FIXTURE_MANIFEST,
    CATEGORY_HKDF,
    CATEGORY_TOKEN,
    CATEGORY_IDENTITY_ENCRYPT,
    CATEGORY_IDENTITY_DECRYPT,
    CATEGORY_IFAC,
    CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
    CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
    CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
];

const MANIFEST: &str = include_str!("../../../fixtures/rns/profile_2_crypto_ifac/manifest.json");
const HKDF_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/hkdf_vectors.json");
const TOKEN_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/token_vectors.json");
const TOKEN_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/token_negative_vectors.json");
const IDENTITY_ENCRYPT_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/identity_encrypt_vectors.json");
const IDENTITY_DECRYPT_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/identity_decrypt_vectors.json");
const IFAC_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/ifac_vectors.json");
const IFAC_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/ifac_negative_vectors.json");

pub fn profile_2_results() -> Vec<ConformanceResult> {
    let mut results = profile_2_fixture_results();
    results.extend(profile_2_oracle_unavailable_results());
    results
}

pub fn profile_2_fixture_results() -> Vec<ConformanceResult> {
    vec![
        fixture_result(
            RESULT_ID_FIXTURE_MANIFEST,
            CATEGORY_FIXTURE_MANIFEST,
            validate_fixture_manifest(),
        ),
        fixture_result(
            RESULT_ID_HKDF,
            CATEGORY_HKDF,
            validate_fixture_cases(HKDF_FIXTURE, 3),
        ),
        fixture_result(RESULT_ID_TOKEN, CATEGORY_TOKEN, validate_token_fixtures()),
        fixture_result(
            RESULT_ID_IDENTITY_ENCRYPT,
            CATEGORY_IDENTITY_ENCRYPT,
            validate_fixture_cases(IDENTITY_ENCRYPT_FIXTURE, 2),
        ),
        fixture_result(
            RESULT_ID_IDENTITY_DECRYPT,
            CATEGORY_IDENTITY_DECRYPT,
            validate_fixture_cases(IDENTITY_DECRYPT_FIXTURE, 6),
        ),
        fixture_result(RESULT_ID_IFAC, CATEGORY_IFAC, validate_ifac_fixtures()),
    ]
}

pub fn profile_2_oracle_unavailable_results() -> [ConformanceResult; 6] {
    [
        invalid_environment_result(
            RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY,
            CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
            "fixture replay captures are generated by private evidence tooling",
        ),
        invalid_environment_result(
            RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_TOKEN_GENERATION,
            CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
            "token generation oracle capture is generated by private evidence tooling",
        ),
        invalid_environment_result(
            RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_TOKEN,
            CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
            "Reticulum token decrypt proof requires python_oracle evidence tooling",
        ),
        invalid_environment_result(
            RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_IDENTITY_GENERATION,
            CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
            "identity generation oracle capture is generated by private evidence tooling",
        ),
        invalid_environment_result(
            RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IDENTITY,
            CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
            "Reticulum identity decrypt proof requires python_oracle evidence tooling",
        ),
        invalid_environment_result(
            RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IFAC,
            CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
            "Reticulum IFAC proof requires python_oracle evidence tooling",
        ),
    ]
}

pub fn profile_2_report(
    run_id: impl Into<String>,
    hyf_commit: impl Into<String>,
    started_at: impl Into<String>,
    environment: ConformanceEnvironment,
) -> ConformanceRun {
    ConformanceRun::new_profile(
        PROFILE_2_CRYPTO_IFAC,
        run_id,
        hyf_commit,
        crate::fixtures::EXPECTED_RETICULUM_COMMIT,
        started_at,
        environment,
        profile_2_results(),
    )
}

pub fn required_categories_are_present(results: &[ConformanceResult]) -> bool {
    let categories: BTreeSet<&str> = results
        .iter()
        .map(|result| result.category.as_str())
        .collect();
    REQUIRED_PROFILE_2_RESULT_CATEGORIES
        .iter()
        .all(|category| categories.contains(category))
}

fn validate_fixture_manifest() -> Result<(), FixtureError> {
    let manifest = parse_manifest_for_profile(MANIFEST, PROFILE_2_CRYPTO_IFAC)?;

    assert_exact_manifest_entries(
        &manifest,
        &[
            ExpectedManifestEntry {
                file: "hkdf_vectors.json",
                category: CATEGORY_HKDF,
                case_count: 3,
                contents: HKDF_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "token_vectors.json",
                category: CATEGORY_TOKEN,
                case_count: 2,
                contents: TOKEN_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "token_negative_vectors.json",
                category: "token_negative",
                case_count: 5,
                contents: TOKEN_NEGATIVE_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "identity_encrypt_vectors.json",
                category: CATEGORY_IDENTITY_ENCRYPT,
                case_count: 2,
                contents: IDENTITY_ENCRYPT_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "identity_decrypt_vectors.json",
                category: CATEGORY_IDENTITY_DECRYPT,
                case_count: 6,
                contents: IDENTITY_DECRYPT_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "ifac_vectors.json",
                category: CATEGORY_IFAC,
                case_count: 2,
                contents: IFAC_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "ifac_negative_vectors.json",
                category: "ifac_negative",
                case_count: 7,
                contents: IFAC_NEGATIVE_FIXTURE,
            },
        ],
    )
}

fn validate_token_fixtures() -> Result<(), FixtureError> {
    validate_fixture_cases(TOKEN_FIXTURE, 2)?;
    validate_fixture_cases(TOKEN_NEGATIVE_FIXTURE, 5)
}

fn validate_ifac_fixtures() -> Result<(), FixtureError> {
    validate_fixture_cases(IFAC_FIXTURE, 2)?;
    validate_fixture_cases(IFAC_NEGATIVE_FIXTURE, 7)
}

fn validate_fixture_cases(contents: &str, expected_count: usize) -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<Value> =
        parse_fixture_cases_for_profile(contents, PROFILE_2_CRYPTO_IFAC)?;
    if fixture.cases.len() == expected_count {
        return Ok(());
    }

    Err(FixtureError::UnexpectedFixtureValue {
        field: "case_count".to_owned(),
        value: fixture.cases.len().to_string(),
    })
}
