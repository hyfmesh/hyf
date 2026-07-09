use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use hyf_rns_crypto::{
    RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN, encrypt_for_identity_with_ephemeral_and_iv,
    public_identity_from_bytes, token_encrypt_with_iv,
};
use serde::Serialize;
use serde_json::Value;

use crate::final_report::{
    ExpectedFinalResult, ExpectedOracleDetail, FinalReportError, expect_bool_field, expect_capture,
    expect_string_field, invalid_evidence, load_capture, optional_string_field, oracle_detail,
    require_equal, required_string_field, validate_final_oracle_metadata, validate_final_results,
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
            evidence_role: "rust_output_reticulum_validation",
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
            evidence_role: "rust_output_reticulum_validation",
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

pub const PROFILE_2_RUST_PROOF_COMMAND: &str = "profile2-rust-proof-inputs";
pub const PROFILE_2_RUST_PROOF_MODE: &str = "rust_implementation";

const PROFILE_2_RUST_PROOF_PLAINTEXT: &[u8] = b"hello token";
const PROFILE_2_RUST_PROOF_TOKEN_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const PROFILE_2_RUST_PROOF_IV: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const PROFILE_2_RUST_PROOF_RECIPIENT_SECRET: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const PROFILE_2_RUST_PROOF_RECIPIENT_PUBLIC: [u8; 64] = [
    0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2, 0x14, 0xea, 0x76, 0x7a, 0x6e,
    0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b, 0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f,
    0x29, 0xac, 0xba, 0xe1, 0x41, 0xbc, 0xca, 0xf0, 0xb2, 0x2e, 0x1a, 0x94, 0xd3, 0x4d, 0x0b, 0xc7,
    0x36, 0x1e, 0x52, 0x6d, 0x0b, 0xfe, 0x12, 0xc8, 0x97, 0x94, 0xbc, 0x93, 0x22, 0x96, 0x6d, 0xd7,
];
const PROFILE_2_RUST_PROOF_EPHEMERAL_SECRET: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct Profile2RustProofInputs {
    pub command: &'static str,
    pub mode: &'static str,
    pub valid: bool,
    pub test_only_secret_material: bool,
    pub plaintext_hex: String,
    pub token_key_hex: String,
    pub token_hex: String,
    pub recipient_public_identity_hex: String,
    pub recipient_secret_identity_hex: String,
    pub ephemeral_secret_hex: String,
    pub iv_hex: String,
    pub identity_ciphertext_token_hex: String,
    pub ephemeral_public_hex: String,
}

impl fmt::Debug for Profile2RustProofInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Profile2RustProofInputs")
            .field("command", &self.command)
            .field("mode", &self.mode)
            .field("valid", &self.valid)
            .field("test_only_secret_material", &self.test_only_secret_material)
            .field("plaintext_hex", &"<redacted>")
            .field("token_key_hex", &"<redacted>")
            .field("token_hex", &"<redacted>")
            .field("recipient_public_identity_hex", &"<redacted>")
            .field("recipient_secret_identity_hex", &"<redacted>")
            .field("ephemeral_secret_hex", &"<redacted>")
            .field("iv_hex", &"<redacted>")
            .field("identity_ciphertext_token_hex", &"<redacted>")
            .field("ephemeral_public_hex", &"<redacted>")
            .finish()
    }
}

pub fn profile_2_rust_proof_inputs() -> Result<Profile2RustProofInputs, FinalReportError> {
    let mut token = [0; 128];
    let token_len = token_encrypt_with_iv(
        &PROFILE_2_RUST_PROOF_TOKEN_KEY,
        PROFILE_2_RUST_PROOF_PLAINTEXT,
        PROFILE_2_RUST_PROOF_IV,
        &mut token,
    )
    .map_err(|error| invalid_evidence(format!("Profile 2 Rust token proof failed: {error}")))?;

    let recipient =
        public_identity_from_bytes(&PROFILE_2_RUST_PROOF_RECIPIENT_PUBLIC).map_err(|error| {
            invalid_evidence(format!(
                "Profile 2 Rust public identity proof failed: {error}"
            ))
        })?;
    let mut identity_ciphertext = [0; 128];
    let identity_ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
        &recipient,
        PROFILE_2_RUST_PROOF_PLAINTEXT,
        PROFILE_2_RUST_PROOF_EPHEMERAL_SECRET,
        PROFILE_2_RUST_PROOF_IV,
        &mut identity_ciphertext,
    )
    .map_err(|error| invalid_evidence(format!("Profile 2 Rust identity proof failed: {error}")))?;

    let identity_ciphertext = &identity_ciphertext[..identity_ciphertext_len];
    Ok(Profile2RustProofInputs {
        command: PROFILE_2_RUST_PROOF_COMMAND,
        mode: PROFILE_2_RUST_PROOF_MODE,
        valid: true,
        test_only_secret_material: true,
        plaintext_hex: hex_lower(PROFILE_2_RUST_PROOF_PLAINTEXT),
        token_key_hex: hex_lower(&PROFILE_2_RUST_PROOF_TOKEN_KEY),
        token_hex: hex_lower(&token[..token_len]),
        recipient_public_identity_hex: hex_lower(&PROFILE_2_RUST_PROOF_RECIPIENT_PUBLIC),
        recipient_secret_identity_hex: hex_lower(&PROFILE_2_RUST_PROOF_RECIPIENT_SECRET),
        ephemeral_secret_hex: hex_lower(&PROFILE_2_RUST_PROOF_EPHEMERAL_SECRET),
        iv_hex: hex_lower(&PROFILE_2_RUST_PROOF_IV),
        identity_ciphertext_token_hex: hex_lower(identity_ciphertext),
        ephemeral_public_hex: hex_lower(
            &identity_ciphertext[..RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN],
        ),
    })
}

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
        let rust_proof_inputs = load_capture(capture_dir, "rust_proof_inputs.json")?;
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
        expect_string_field(
            &rust_proof_inputs,
            "rust_proof_inputs.json",
            "command",
            PROFILE_2_RUST_PROOF_COMMAND,
        )?;
        expect_string_field(
            &rust_proof_inputs,
            "rust_proof_inputs.json",
            "mode",
            PROFILE_2_RUST_PROOF_MODE,
        )?;
        expect_bool_field(&rust_proof_inputs, "rust_proof_inputs.json", "valid", true)?;
        expect_bool_field(
            &rust_proof_inputs,
            "rust_proof_inputs.json",
            "test_only_secret_material",
            true,
        )?;
        let rust_plaintext_hex = required_string_field(
            &rust_proof_inputs,
            "rust_proof_inputs.json",
            "plaintext_hex",
        )?;
        let rust_token_hex =
            required_string_field(&rust_proof_inputs, "rust_proof_inputs.json", "token_hex")?;
        let rust_identity_ciphertext_token_hex = required_string_field(
            &rust_proof_inputs,
            "rust_proof_inputs.json",
            "identity_ciphertext_token_hex",
        )?;
        let rust_ephemeral_public_hex = required_string_field(
            &rust_proof_inputs,
            "rust_proof_inputs.json",
            "ephemeral_public_hex",
        )?;
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
        require_equal(
            required_string_field(&token_generation, "token_generation.json", "plaintext_hex")?,
            rust_plaintext_hex,
            "token shim plaintext does not match Rust proof input",
        )?;
        require_equal(
            required_string_field(&token_generation, "token_generation.json", "token_hex")?,
            rust_token_hex,
            "token shim output does not match Rust proof input",
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
            required_string_field(&token_python, "token_python_decrypt.json", "token_hex")?,
            rust_token_hex,
            "Reticulum token decrypt input does not match Rust proof input",
        )?;
        require_equal(
            required_string_field(&token_python, "token_python_decrypt.json", "plaintext_hex")?,
            rust_plaintext_hex,
            "Reticulum token decrypt plaintext does not match Rust proof input",
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
        require_equal(
            required_string_field(
                &identity_generation,
                "identity_generation.json",
                "plaintext_hex",
            )?,
            rust_plaintext_hex,
            "identity shim plaintext does not match Rust proof input",
        )?;
        let ciphertext_token_hex = required_string_field(
            &identity_generation,
            "identity_generation.json",
            "ciphertext_token_hex",
        )?;
        require_equal(
            ciphertext_token_hex,
            rust_identity_ciphertext_token_hex,
            "identity shim output does not match Rust proof input",
        )?;
        let ephemeral_public_hex = required_string_field(
            &identity_generation,
            "identity_generation.json",
            "ephemeral_public_hex",
        )?;
        require_equal(
            ephemeral_public_hex,
            rust_ephemeral_public_hex,
            "identity shim ephemeral public key does not match Rust proof input",
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
                "ciphertext_token_hex",
            )?,
            rust_identity_ciphertext_token_hex,
            "Reticulum identity decrypt input does not match Rust proof input",
        )?;
        require_equal(
            required_string_field(
                &identity_python,
                "identity_python_decrypt.json",
                "plaintext_hex",
            )?,
            rust_plaintext_hex,
            "Reticulum identity decrypt plaintext does not match Rust proof input",
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

    pub fn with_oracle_module_path(mut self, reticulum_module_path: impl Into<String>) -> Self {
        self.oracle_environment.reticulum_module_path = reticulum_module_path.into();
        self
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
            "rust_output_reticulum_validation",
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
            "rust_output_reticulum_validation",
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

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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
    validate_final_oracle_metadata(oracle, None)?;
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
