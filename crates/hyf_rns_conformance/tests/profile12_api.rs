use std::collections::BTreeSet;

use hyf_rns_conformance::fixtures::{
    EXPECTED_RETICULUM_COMMIT, PROFILE_1_KISS_RNODE, PROFILE_2_CRYPTO_IFAC,
};
use hyf_rns_conformance::profile1::{
    Profile1FinalEvidence, REQUIRED_PROFILE_1_RESULTS, profile_1_final_report, profile_1_report,
    profile_1_results, validate_profile_1_final_report,
};
use hyf_rns_conformance::profile2::{
    Profile2FinalEvidence, REQUIRED_PROFILE_2_RESULTS, profile_2_final_report, profile_2_report,
    profile_2_results, profile_2_rust_proof_inputs, validate_profile_2_final_report,
};
use hyf_rns_conformance::report::{
    ConformanceEnvironment, ConformanceRun, ConformanceStatus, OracleEnvironment,
};

#[test]
fn profile_1_required_results_match_handoff2_contract() {
    assert_required_pairs(
        REQUIRED_PROFILE_1_RESULTS,
        &[
            ("profile_1_kiss_rnode.fixture_manifest", "fixture_manifest"),
            ("profile_1_kiss_rnode.kiss", "kiss"),
            ("profile_1_kiss_rnode.rnode_command", "rnode_command"),
            (
                "profile_1_kiss_rnode.rnode_config_validation",
                "rnode_config_validation",
            ),
            ("profile_1_kiss_rnode.rnode_stat", "rnode_stat"),
            (
                "profile_1_kiss_rnode.rns_oracle.fixture_replay",
                "rns_oracle_fixture_replay",
            ),
        ],
    );
}

#[test]
fn profile_2_required_results_match_handoff2_contract() {
    assert_required_pairs(
        REQUIRED_PROFILE_2_RESULTS,
        &[
            ("profile_2_crypto_ifac.fixture_manifest", "fixture_manifest"),
            ("profile_2_crypto_ifac.hkdf", "hkdf"),
            ("profile_2_crypto_ifac.token", "token"),
            ("profile_2_crypto_ifac.identity_encrypt", "identity_encrypt"),
            ("profile_2_crypto_ifac.identity_decrypt", "identity_decrypt"),
            ("profile_2_crypto_ifac.ifac", "ifac"),
            (
                "profile_2_crypto_ifac.rns_oracle.fixture_replay",
                "rns_oracle_fixture_replay",
            ),
            (
                "profile_2_crypto_ifac.rns_oracle.test_only_oracle_shim.token_generation",
                "rns_oracle_test_only_shim",
            ),
            (
                "profile_2_crypto_ifac.rns_oracle.python_reticulum.token",
                "rns_oracle_python_reticulum",
            ),
            (
                "profile_2_crypto_ifac.rns_oracle.test_only_oracle_shim.identity_generation",
                "rns_oracle_test_only_shim",
            ),
            (
                "profile_2_crypto_ifac.rns_oracle.python_reticulum.identity",
                "rns_oracle_python_reticulum",
            ),
            (
                "profile_2_crypto_ifac.rns_oracle.python_reticulum.ifac",
                "rns_oracle_python_reticulum",
            ),
        ],
    );
}

#[test]
fn profile_1_results_cover_required_rows_once() {
    let results = profile_1_results();

    assert_results_cover_required_pairs(&results, REQUIRED_PROFILE_1_RESULTS);
    assert!(hyf_rns_conformance::profile1::required_categories_are_present(&results));
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status == ConformanceStatus::Passed)
            .count(),
        5
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status == ConformanceStatus::InvalidEnvironment)
            .count(),
        1
    );
}

#[test]
fn profile_2_results_cover_required_rows_once() {
    let results = profile_2_results();

    assert_results_cover_required_pairs(&results, REQUIRED_PROFILE_2_RESULTS);
    assert!(hyf_rns_conformance::profile2::required_categories_are_present(&results));
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status == ConformanceStatus::Passed)
            .count(),
        6
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status == ConformanceStatus::InvalidEnvironment)
            .count(),
        6
    );
}

#[test]
fn profile_1_report_serializes_with_profile_identity() -> Result<(), serde_json::Error> {
    let report = profile_1_report(
        "profile1-local-0001",
        "1111111111111111111111111111111111111111",
        "2026-07-09T00:00:00Z",
        ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
    );
    let value = serde_json::to_value(&report)?;

    assert_eq!(report.profile, PROFILE_1_KISS_RNODE);
    assert_eq!(report.reticulum_commit, EXPECTED_RETICULUM_COMMIT);
    assert_eq!(value["profile"], PROFILE_1_KISS_RNODE);
    assert_eq!(value["results"].as_array().map(Vec::len), Some(6));
    Ok(())
}

#[test]
fn profile_2_report_serializes_with_profile_identity() -> Result<(), serde_json::Error> {
    let report = profile_2_report(
        "profile2-local-0001",
        "1111111111111111111111111111111111111111",
        "2026-07-09T00:00:00Z",
        ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
    );
    let value = serde_json::to_value(&report)?;

    assert_eq!(report.profile, PROFILE_2_CRYPTO_IFAC);
    assert_eq!(report.reticulum_commit, EXPECTED_RETICULUM_COMMIT);
    assert_eq!(value["profile"], PROFILE_2_CRYPTO_IFAC);
    assert_eq!(value["results"].as_array().map(Vec::len), Some(12));
    Ok(())
}

#[test]
fn profile_2_rust_proof_inputs_match_deterministic_vectors()
-> Result<(), Box<dyn std::error::Error>> {
    let proof = profile_2_rust_proof_inputs()?;

    assert_eq!(proof.command, "profile2-rust-proof-inputs");
    assert_eq!(proof.mode, "rust_implementation");
    assert!(proof.valid);
    assert!(proof.test_only_secret_material);
    assert_eq!(proof.plaintext_hex, "68656c6c6f20746f6b656e");
    assert_eq!(
        proof.token_hex,
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf111c0579413c7cd45de041e1e99e50a79a67288e721b62e303e18a6d4afcc34c75ff00a0919f0a0e67686886ede87f67"
    );
    assert_eq!(
        proof.identity_ciphertext_token_hex,
        "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51aa0a1a2a3a4a5a6a7a8a9aaabacadaeaf6cc9462adb376ef1d7fcbdcff3343d21c9b01f1777868e6926e4029bbd957182a1feeecebbc4f16256886bfff3e27de8"
    );
    assert!(
        proof
            .identity_ciphertext_token_hex
            .starts_with(&proof.ephemeral_public_hex)
    );
    Ok(())
}

#[test]
fn profile_2_rust_proof_inputs_debug_redacts_hex_material() -> Result<(), Box<dyn std::error::Error>>
{
    let proof = profile_2_rust_proof_inputs()?;
    let debug = format!("{proof:?}");

    assert!(debug.contains("Profile2RustProofInputs"));
    assert!(debug.contains("token_hex: \"<redacted>\""));
    assert!(debug.contains("identity_ciphertext_token_hex: \"<redacted>\""));
    assert!(!debug.contains(&proof.plaintext_hex));
    assert!(!debug.contains(&proof.token_key_hex));
    assert!(!debug.contains(&proof.token_hex));
    assert!(!debug.contains(&proof.recipient_secret_identity_hex));
    assert!(!debug.contains(&proof.ephemeral_secret_hex));
    assert!(!debug.contains(&proof.identity_ciphertext_token_hex));

    Ok(())
}

#[test]
fn profile_1_final_report_uses_strict_oracle_rows() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = Profile1FinalEvidence::new(vec![
        "kiss-encode".to_owned(),
        "kiss-decode".to_owned(),
        "rnode-command".to_owned(),
    ])?;
    let report = profile_1_final_report(
        "profile1-final-0001",
        "1111111111111111111111111111111111111111",
        "2026-07-09T00:00:00Z",
        ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
        &evidence,
    )?;

    validate_profile_1_final_report(&report)?;
    assert_eq!(report.profile, PROFILE_1_KISS_RNODE);
    assert!(report.environment.oracle.is_none());
    assert!(
        report
            .results
            .iter()
            .all(|result| result.status == ConformanceStatus::Passed)
    );
    assert_eq!(
        report.results[5].detail.as_deref(),
        Some(
            "oracle_mode=fixture_replay; evidence_role=fixture_replay; \
             compatibility_proof=false; commands=kiss-encode,kiss-decode,rnode-command; \
             reticulum_commit=422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
        )
    );
    Ok(())
}

#[test]
fn profile_1_final_report_rejects_wrong_oracle_detail() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = Profile1FinalEvidence::new(vec![
        "kiss-encode".to_owned(),
        "kiss-decode".to_owned(),
        "rnode-command".to_owned(),
    ])?;
    let mut report = profile_1_final_report(
        "profile1-final-0001",
        "1111111111111111111111111111111111111111",
        "2026-07-09T00:00:00Z",
        ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
        &evidence,
    )?;
    report.results[5].detail = Some(
        "oracle_mode=fixture_replay; evidence_role=fixture_replay; \
         compatibility_proof=true; commands=kiss-encode,kiss-decode,rnode-command; \
         reticulum_commit=422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
            .to_owned(),
    );

    assert!(validate_profile_1_final_report(&report).is_err());
    assert!(
        Profile1FinalEvidence::new(vec!["kiss-encode".to_owned(), "rnode-command".to_owned()])
            .is_err()
    );
    Ok(())
}

#[test]
fn profile_2_final_report_uses_strict_oracle_rows() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = profile_2_final_evidence()?;
    let report = profile_2_final_report(
        "profile2-final-0001",
        "1111111111111111111111111111111111111111",
        "2026-07-09T00:00:00Z",
        ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
        &evidence,
    )?;

    validate_profile_2_final_report(&report)?;
    assert_eq!(report.profile, PROFILE_2_CRYPTO_IFAC);
    assert_eq!(
        report
            .environment
            .oracle
            .as_ref()
            .map(|oracle| oracle.reticulum_module_path.as_str()),
        Some("refs/Reticulum/RNS/__init__.py")
    );
    assert_eq!(report.results.len(), REQUIRED_PROFILE_2_RESULTS.len());
    assert!(
        report
            .results
            .iter()
            .all(|result| result.status == ConformanceStatus::Passed)
    );
    assert_eq!(
        report.results[8].detail.as_deref(),
        Some(
            "oracle_mode=python_reticulum; evidence_role=rust_output_reticulum_validation; \
             compatibility_proof=true; commands=token-decrypt; \
             reticulum_commit=422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
        )
    );
    assert_eq!(
        report.results[10].detail.as_deref(),
        Some(
            "oracle_mode=python_reticulum; evidence_role=rust_output_reticulum_validation; \
             compatibility_proof=true; commands=identity-decrypt; \
             reticulum_commit=422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
        )
    );
    assert_eq!(
        report.results[11].detail.as_deref(),
        Some(
            "oracle_mode=python_reticulum; evidence_role=reticulum_validation; \
             compatibility_proof=true; commands=ifac-apply,ifac-verify; \
             reticulum_commit=422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
        )
    );
    Ok(())
}

#[test]
fn profile_2_final_report_rejects_missing_oracle_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = profile_2_final_evidence()?;
    let mut report = profile_2_final_report(
        "profile2-final-0001",
        "1111111111111111111111111111111111111111",
        "2026-07-09T00:00:00Z",
        ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
        &evidence,
    )?;
    report.environment.oracle = None;

    assert!(validate_profile_2_final_report(&report).is_err());
    Ok(())
}

#[test]
fn profile_2_final_report_rejects_invalid_oracle_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let report = profile_2_final_report_for_tests()?;

    let mut wrong_commit = report.clone();
    oracle_mut(&mut wrong_commit)?.reticulum_commit =
        "0000000000000000000000000000000000000000".to_owned();
    assert!(validate_profile_2_final_report(&wrong_commit).is_err());

    let mut missing_rns_version = report.clone();
    oracle_mut(&mut missing_rns_version)?.rns_version = None;
    assert!(validate_profile_2_final_report(&missing_rns_version).is_err());

    let mut wrong_cryptography = report.clone();
    oracle_mut(&mut wrong_cryptography)?.cryptography_version = "48.0.0".to_owned();
    assert!(validate_profile_2_final_report(&wrong_cryptography).is_err());

    let mut wrong_pyserial = report.clone();
    oracle_mut(&mut wrong_pyserial)?.pyserial_version = "3.4".to_owned();
    assert!(validate_profile_2_final_report(&wrong_pyserial).is_err());

    let mut absolute_path = report.clone();
    oracle_mut(&mut absolute_path)?.reticulum_module_path =
        "/tmp/Reticulum/RNS/__init__.py".to_owned();
    assert!(validate_profile_2_final_report(&absolute_path).is_err());

    let mut traversal_path = report;
    oracle_mut(&mut traversal_path)?.reticulum_module_path =
        "refs/Reticulum/../RNS/__init__.py".to_owned();
    assert!(validate_profile_2_final_report(&traversal_path).is_err());

    Ok(())
}

fn assert_required_pairs(actual: &[(&str, &str)], expected: &[(&str, &str)]) {
    assert_eq!(actual, expected);
    let unique_ids: BTreeSet<&str> = actual.iter().map(|(id, _)| *id).collect();
    assert_eq!(unique_ids.len(), actual.len());
}

fn assert_results_cover_required_pairs(
    results: &[hyf_rns_conformance::report::ConformanceResult],
    required: &[(&str, &str)],
) {
    assert_eq!(results.len(), required.len());
    let ids: BTreeSet<&str> = results.iter().map(|result| result.id.as_str()).collect();
    assert_eq!(ids.len(), required.len());
    let actual: Vec<(&str, &str)> = results
        .iter()
        .map(|result| (result.id.as_str(), result.category.as_str()))
        .collect();
    assert_eq!(actual, required);
}

fn profile_2_final_evidence() -> Result<Profile2FinalEvidence, Box<dyn std::error::Error>> {
    let oracle = OracleEnvironment::new(
        "refs/Reticulum/RNS/__init__.py",
        EXPECTED_RETICULUM_COMMIT,
        "49.0.0",
        "3.5",
    )
    .with_rns_version("1.3.5");
    Ok(Profile2FinalEvidence::new(
        oracle,
        vec![
            "hkdf-vector".to_owned(),
            "token-decrypt".to_owned(),
            "identity-decrypt".to_owned(),
            "ifac-verify".to_owned(),
        ],
        "token-encrypt",
        "token-decrypt",
        "identity-encrypt",
        "identity-decrypt",
        vec!["ifac-apply".to_owned(), "ifac-verify".to_owned()],
    )?)
}

fn profile_2_final_report_for_tests() -> Result<ConformanceRun, Box<dyn std::error::Error>> {
    let evidence = profile_2_final_evidence()?;
    Ok(profile_2_final_report(
        "profile2-final-0001",
        "1111111111111111111111111111111111111111",
        "2026-07-09T00:00:00Z",
        ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
        &evidence,
    )?)
}

fn oracle_mut(report: &mut ConformanceRun) -> Result<&mut OracleEnvironment, std::io::Error> {
    report
        .environment
        .oracle
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing oracle"))
}
