use std::collections::BTreeSet;

use hyf_rns_conformance::fixtures::{
    EXPECTED_RETICULUM_COMMIT, PROFILE_1_KISS_RNODE, PROFILE_2_CRYPTO_IFAC,
};
use hyf_rns_conformance::profile1::{
    REQUIRED_PROFILE_1_RESULTS, profile_1_report, profile_1_results,
};
use hyf_rns_conformance::profile2::{
    REQUIRED_PROFILE_2_RESULTS, profile_2_report, profile_2_results,
};
use hyf_rns_conformance::report::{ConformanceEnvironment, ConformanceStatus};

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
