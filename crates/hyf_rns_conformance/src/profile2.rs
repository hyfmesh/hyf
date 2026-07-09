use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::final_report::{
    ExpectedFinalResult, ExpectedOracleDetail, FinalReportError, expect_bool_field, expect_capture,
    expect_string_field, invalid_evidence, load_capture, optional_string_field, oracle_detail,
    require_equal, required_string_field, validate_final_results,
};
use crate::fixtures::{
    EXPECTED_RETICULUM_COMMIT, ExpectedManifestEntry, FixtureCasesFile, FixtureError,
    PROFILE_2_CRYPTO_IFAC, assert_exact_manifest_entries, parse_fixture_cases_for_profile,
    parse_manifest_for_profile,
};
use crate::report::{
    ConformanceEnvironment, ConformanceResult, ConformanceRun, ConformanceStatus, OracleEnvironment,
};
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

pub const PROFILE_2_FINAL_RESULTS: &[ExpectedFinalResult<'_>] = &[
    ExpectedFinalResult {
        id: RESULT_ID_FIXTURE_MANIFEST,
        category: CATEGORY_FIXTURE_MANIFEST,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_HKDF,
        category: CATEGORY_HKDF,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_TOKEN,
        category: CATEGORY_TOKEN,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_IDENTITY_ENCRYPT,
        category: CATEGORY_IDENTITY_ENCRYPT,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_IDENTITY_DECRYPT,
        category: CATEGORY_IDENTITY_DECRYPT,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_IFAC,
        category: CATEGORY_IFAC,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY,
        category: CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
        detail: Some(ExpectedOracleDetail {
            oracle_mode: "fixture_replay",
            evidence_role: "fixture_replay",
            compatibility_proof: false,
            commands: "hkdf-vector,token-decrypt,identity-decrypt,ifac-verify",
        }),
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_TOKEN_GENERATION,
        category: CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
        detail: Some(ExpectedOracleDetail {
            oracle_mode: "test_only_oracle_shim",
            evidence_role: "deterministic_generation",
            compatibility_proof: false,
            commands: "token-encrypt",
        }),
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_TOKEN,
        category: CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
        detail: Some(ExpectedOracleDetail {
            oracle_mode: "python_reticulum",
            evidence_role: "reticulum_validation",
            compatibility_proof: true,
            commands: "token-decrypt",
        }),
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_IDENTITY_GENERATION,
        category: CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
        detail: Some(ExpectedOracleDetail {
            oracle_mode: "test_only_oracle_shim",
            evidence_role: "deterministic_generation",
            compatibility_proof: false,
            commands: "identity-encrypt",
        }),
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IDENTITY,
        category: CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
        detail: Some(ExpectedOracleDetail {
            oracle_mode: "python_reticulum",
            evidence_role: "reticulum_validation",
            compatibility_proof: true,
            commands: "identity-decrypt",
        }),
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IFAC,
        category: CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
        detail: Some(ExpectedOracleDetail {
            oracle_mode: "python_reticulum",
            evidence_role: "reticulum_validation",
            compatibility_proof: true,
            commands: "ifac-apply,ifac-verify",
        }),
    },
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile2FinalEvidence {
    oracle_environment: OracleEnvironment,
    fixture_replay_commands: Vec<String>,
    token_generation_command: String,
    token_python_command: String,
    identity_generation_command: String,
    identity_python_command: String,
    ifac_python_commands: Vec<String>,
}

impl Profile2FinalEvidence {
    pub fn new(
        oracle_environment: OracleEnvironment,
        fixture_replay_commands: Vec<String>,
        token_generation_command: impl Into<String>,
        token_python_command: impl Into<String>,
        identity_generation_command: impl Into<String>,
        identity_python_command: impl Into<String>,
        ifac_python_commands: Vec<String>,
    ) -> Result<Self, FinalReportError> {
        if oracle_environment.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
            return Err(invalid_evidence(
                "Profile 2 final evidence oracle Reticulum commit mismatch",
            ));
        }
        if fixture_replay_commands.as_slice()
            != [
                "hkdf-vector",
                "token-decrypt",
                "identity-decrypt",
                "ifac-verify",
            ]
        {
            return Err(invalid_evidence(
                "Profile 2 final evidence has wrong fixture replay commands",
            ));
        }
        let evidence = Self {
            oracle_environment,
            fixture_replay_commands,
            token_generation_command: token_generation_command.into(),
            token_python_command: token_python_command.into(),
            identity_generation_command: identity_generation_command.into(),
            identity_python_command: identity_python_command.into(),
            ifac_python_commands,
        };
        evidence.validate_commands()?;
        Ok(evidence)
    }

    pub fn from_capture_dir(capture_dir: &Path) -> Result<Self, FinalReportError> {
        let hkdf = load_capture(capture_dir, "hkdf_vector.json")?;
        let token_fixture = load_capture(capture_dir, "token_fixture_decrypt.json")?;
        let identity_fixture = load_capture(capture_dir, "identity_fixture_decrypt.json")?;
        let ifac_fixture = load_capture(capture_dir, "ifac_fixture_verify.json")?;
        let probe = load_capture(capture_dir, "probe.json")?;
        let token_generation = load_capture(capture_dir, "token_generation.json")?;
        let token_python = load_capture(capture_dir, "token_python_decrypt.json")?;
        let identity_generation = load_capture(capture_dir, "identity_generation.json")?;
        let identity_python = load_capture(capture_dir, "identity_python_decrypt.json")?;
        let ifac_python_apply = load_capture(capture_dir, "ifac_python_apply.json")?;
        let ifac_python_verify = load_capture(capture_dir, "ifac_python_verify.json")?;

        expect_capture(
            &hkdf,
            "hkdf_vector.json",
            "hkdf-vector",
            "fixture_replay",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_capture(
            &token_fixture,
            "token_fixture_decrypt.json",
            "token-decrypt",
            "fixture_replay",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_capture(
            &identity_fixture,
            "identity_fixture_decrypt.json",
            "identity-decrypt",
            "fixture_replay",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_capture(
            &ifac_fixture,
            "ifac_fixture_verify.json",
            "ifac-verify",
            "fixture_replay",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_capture(
            &probe,
            "probe.json",
            "probe",
            "python_reticulum",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_string_field(&probe, "probe.json", "status", "passed")?;
        expect_capture(
            &token_generation,
            "token_generation.json",
            "token-encrypt",
            "test_only_oracle_shim",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_bool_field(&token_generation, "token_generation.json", "valid", true)?;
        expect_bool_field(
            &token_generation,
            "token_generation.json",
            "test_only_secret_material",
            true,
        )?;
        expect_string_field(
            &token_generation,
            "token_generation.json",
            "reticulum_self_validation",
            "passed",
        )?;
        expect_capture(
            &token_python,
            "token_python_decrypt.json",
            "token-decrypt",
            "python_reticulum",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_bool_field(&token_python, "token_python_decrypt.json", "valid", true)?;
        require_equal(
            required_string_field(&token_python, "token_python_decrypt.json", "plaintext_hex")?,
            required_string_field(&token_generation, "token_generation.json", "plaintext_hex")?,
            "token generation Reticulum decrypt plaintext mismatch",
        )?;
        expect_capture(
            &identity_generation,
            "identity_generation.json",
            "identity-encrypt",
            "test_only_oracle_shim",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_bool_field(
            &identity_generation,
            "identity_generation.json",
            "valid",
            true,
        )?;
        expect_bool_field(
            &identity_generation,
            "identity_generation.json",
            "test_only_secret_material",
            true,
        )?;
        expect_string_field(
            &identity_generation,
            "identity_generation.json",
            "reticulum_self_validation",
            "passed",
        )?;
        let ciphertext_token_hex = required_string_field(
            &identity_generation,
            "identity_generation.json",
            "ciphertext_token_hex",
        )?;
        let ephemeral_public_hex = required_string_field(
            &identity_generation,
            "identity_generation.json",
            "ephemeral_public_hex",
        )?;
        if !ciphertext_token_hex.starts_with(ephemeral_public_hex) {
            return Err(invalid_evidence(
                "identity generation ciphertext does not start with ephemeral public key",
            ));
        }
        expect_capture(
            &identity_python,
            "identity_python_decrypt.json",
            "identity-decrypt",
            "python_reticulum",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_bool_field(
            &identity_python,
            "identity_python_decrypt.json",
            "valid",
            true,
        )?;
        require_equal(
            required_string_field(
                &identity_python,
                "identity_python_decrypt.json",
                "plaintext_hex",
            )?,
            required_string_field(
                &identity_generation,
                "identity_generation.json",
                "plaintext_hex",
            )?,
            "identity generation Reticulum decrypt plaintext mismatch",
        )?;
        expect_capture(
            &ifac_python_apply,
            "ifac_python_apply.json",
            "ifac-apply",
            "python_reticulum",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_bool_field(&ifac_python_apply, "ifac_python_apply.json", "valid", true)?;
        expect_capture(
            &ifac_python_verify,
            "ifac_python_verify.json",
            "ifac-verify",
            "python_reticulum",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_bool_field(
            &ifac_python_verify,
            "ifac_python_verify.json",
            "valid",
            true,
        )?;
        require_equal(
            required_string_field(&ifac_python_apply, "ifac_python_apply.json", "masked_hex")?,
            required_string_field(&ifac_fixture, "ifac_fixture_verify.json", "masked_hex")?,
            "IFAC Reticulum apply masked packet mismatch",
        )?;
        require_equal(
            required_string_field(&ifac_python_verify, "ifac_python_verify.json", "masked_hex")?,
            required_string_field(&ifac_python_apply, "ifac_python_apply.json", "masked_hex")?,
            "IFAC Reticulum verify masked packet mismatch",
        )?;
        require_equal(
            required_string_field(
                &ifac_python_verify,
                "ifac_python_verify.json",
                "unmasked_hex",
            )?,
            required_string_field(&ifac_fixture, "ifac_fixture_verify.json", "unmasked_hex")?,
            "IFAC Reticulum verify unmasked packet mismatch",
        )?;

        let mut oracle_environment = OracleEnvironment::new(
            required_string_field(&probe, "probe.json", "module")?.to_owned(),
            EXPECTED_RETICULUM_COMMIT,
            required_string_field(&probe, "probe.json", "cryptography")?.to_owned(),
            required_string_field(&probe, "probe.json", "pyserial")?.to_owned(),
        );
        if let Some(rns_version) = optional_string_field(&probe, "rns_version")? {
            oracle_environment = oracle_environment.with_rns_version(rns_version.to_owned());
        }

        Self::new(
            oracle_environment,
            vec![
                required_string_field(&hkdf, "hkdf_vector.json", "command")?.to_owned(),
                required_string_field(&token_fixture, "token_fixture_decrypt.json", "command")?
                    .to_owned(),
                required_string_field(
                    &identity_fixture,
                    "identity_fixture_decrypt.json",
                    "command",
                )?
                .to_owned(),
                required_string_field(&ifac_fixture, "ifac_fixture_verify.json", "command")?
                    .to_owned(),
            ],
            required_string_field(&token_generation, "token_generation.json", "command")?,
            required_string_field(&token_python, "token_python_decrypt.json", "command")?,
            required_string_field(&identity_generation, "identity_generation.json", "command")?,
            required_string_field(&identity_python, "identity_python_decrypt.json", "command")?,
            vec![
                required_string_field(&ifac_python_apply, "ifac_python_apply.json", "command")?
                    .to_owned(),
                required_string_field(&ifac_python_verify, "ifac_python_verify.json", "command")?
                    .to_owned(),
            ],
        )
    }

    pub fn oracle_environment(&self) -> &OracleEnvironment {
        &self.oracle_environment
    }

    fn validate_commands(&self) -> Result<(), FinalReportError> {
        if self.token_generation_command != "token-encrypt"
            || self.token_python_command != "token-decrypt"
            || self.identity_generation_command != "identity-encrypt"
            || self.identity_python_command != "identity-decrypt"
            || self.ifac_python_commands.as_slice() != ["ifac-apply", "ifac-verify"]
        {
            return Err(invalid_evidence(
                "Profile 2 final evidence has wrong oracle proof commands",
            ));
        }
        Ok(())
    }
}

pub fn profile_2_final_results(evidence: &Profile2FinalEvidence) -> Vec<ConformanceResult> {
    let mut results = profile_2_fixture_results();
    results.extend([
        passed_oracle_result(
            RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY,
            CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
            "fixture_replay",
            "fixture_replay",
            false,
            &evidence.fixture_replay_commands,
        ),
        passed_oracle_result(
            RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_TOKEN_GENERATION,
            CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
            "test_only_oracle_shim",
            "deterministic_generation",
            false,
            std::slice::from_ref(&evidence.token_generation_command),
        ),
        passed_oracle_result(
            RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_TOKEN,
            CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
            "python_reticulum",
            "reticulum_validation",
            true,
            std::slice::from_ref(&evidence.token_python_command),
        ),
        passed_oracle_result(
            RESULT_ID_RNS_ORACLE_TEST_ONLY_SHIM_IDENTITY_GENERATION,
            CATEGORY_RNS_ORACLE_TEST_ONLY_SHIM,
            "test_only_oracle_shim",
            "deterministic_generation",
            false,
            std::slice::from_ref(&evidence.identity_generation_command),
        ),
        passed_oracle_result(
            RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IDENTITY,
            CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
            "python_reticulum",
            "reticulum_validation",
            true,
            std::slice::from_ref(&evidence.identity_python_command),
        ),
        passed_oracle_result(
            RESULT_ID_RNS_ORACLE_PYTHON_RETICULUM_IFAC,
            CATEGORY_RNS_ORACLE_PYTHON_RETICULUM,
            "python_reticulum",
            "reticulum_validation",
            true,
            &evidence.ifac_python_commands,
        ),
    ]);
    results
}

fn passed_oracle_result(
    id: &str,
    category: &str,
    mode: &str,
    role: &str,
    proof: bool,
    commands: &[String],
) -> ConformanceResult {
    ConformanceResult {
        id: id.to_owned(),
        category: category.to_owned(),
        status: ConformanceStatus::Passed,
        detail: Some(oracle_detail(
            mode,
            role,
            proof,
            commands,
            EXPECTED_RETICULUM_COMMIT,
        )),
    }
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

pub fn profile_2_final_report(
    run_id: impl Into<String>,
    hyf_commit: impl Into<String>,
    started_at: impl Into<String>,
    environment: ConformanceEnvironment,
    evidence: &Profile2FinalEvidence,
) -> Result<ConformanceRun, FinalReportError> {
    let report = ConformanceRun::new_profile(
        PROFILE_2_CRYPTO_IFAC,
        run_id,
        hyf_commit,
        EXPECTED_RETICULUM_COMMIT,
        started_at,
        environment.with_oracle(evidence.oracle_environment().clone()),
        profile_2_final_results(evidence),
    );
    validate_profile_2_final_report(&report)?;
    Ok(report)
}

pub fn validate_profile_2_final_report(report: &ConformanceRun) -> Result<(), FinalReportError> {
    if report.profile != PROFILE_2_CRYPTO_IFAC {
        return Err(invalid_evidence("Profile 2 final report has wrong profile"));
    }
    if report.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
        return Err(invalid_evidence(
            "Profile 2 final report has wrong Reticulum commit",
        ));
    }
    let Some(oracle) = report.environment.oracle.as_ref() else {
        return Err(invalid_evidence(
            "Profile 2 final report is missing oracle environment metadata",
        ));
    };
    if oracle.reticulum_commit != EXPECTED_RETICULUM_COMMIT
        || oracle.reticulum_module_path.is_empty()
        || oracle.cryptography_version.is_empty()
        || oracle.pyserial_version.is_empty()
    {
        return Err(invalid_evidence(
            "Profile 2 final report has invalid oracle environment metadata",
        ));
    }
    validate_final_results(
        &report.results,
        PROFILE_2_FINAL_RESULTS,
        EXPECTED_RETICULUM_COMMIT,
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
