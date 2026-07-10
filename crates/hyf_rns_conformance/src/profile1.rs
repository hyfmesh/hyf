use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::final_report::{
    ExpectedFinalResult, ExpectedOracleDetail, FinalReportError, expect_capture, invalid_evidence,
    load_capture, oracle_detail, required_string_field, validate_final_results,
};
use crate::fixtures::{
    EXPECTED_RETICULUM_COMMIT, ExpectedManifestEntry, FixtureCasesFile, FixtureError,
    PROFILE_1_KISS_RNODE, assert_exact_manifest_entries, parse_fixture_cases_for_profile,
    parse_manifest_for_profile,
};
use crate::report::{ConformanceEnvironment, ConformanceResult, ConformanceRun};
use crate::runner::{fixture_result, invalid_environment_result};

pub const CATEGORY_FIXTURE_MANIFEST: &str = "fixture_manifest";
pub const CATEGORY_KISS: &str = "kiss";
pub const CATEGORY_RNODE_COMMAND: &str = "rnode_command";
pub const CATEGORY_RNODE_CONFIG_VALIDATION: &str = "rnode_config_validation";
pub const CATEGORY_RNODE_STAT: &str = "rnode_stat";
pub const CATEGORY_RNS_ORACLE_FIXTURE_REPLAY: &str = "rns_oracle_fixture_replay";
const PROFILE_1_KISS_DECODE_CAPTURE_HEX: &str = "c000dbdcdbdd01c0";
const PROFILE_1_KISS_DECODE_KIND: &str = "data";
const PROFILE_1_KISS_DECODE_COMMAND_HEX: &str = "00";
const PROFILE_1_KISS_DECODE_PAYLOAD_HEX: &str = "c0db01";

pub const RESULT_ID_FIXTURE_MANIFEST: &str = "profile_1_kiss_rnode.fixture_manifest";
pub const RESULT_ID_KISS: &str = "profile_1_kiss_rnode.kiss";
pub const RESULT_ID_RNODE_COMMAND: &str = "profile_1_kiss_rnode.rnode_command";
pub const RESULT_ID_RNODE_CONFIG_VALIDATION: &str = "profile_1_kiss_rnode.rnode_config_validation";
pub const RESULT_ID_RNODE_STAT: &str = "profile_1_kiss_rnode.rnode_stat";
pub const RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY: &str =
    "profile_1_kiss_rnode.rns_oracle.fixture_replay";

pub const REQUIRED_PROFILE_1_RESULTS: &[(&str, &str)] = &[
    (RESULT_ID_FIXTURE_MANIFEST, CATEGORY_FIXTURE_MANIFEST),
    (RESULT_ID_KISS, CATEGORY_KISS),
    (RESULT_ID_RNODE_COMMAND, CATEGORY_RNODE_COMMAND),
    (
        RESULT_ID_RNODE_CONFIG_VALIDATION,
        CATEGORY_RNODE_CONFIG_VALIDATION,
    ),
    (RESULT_ID_RNODE_STAT, CATEGORY_RNODE_STAT),
    (
        RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY,
        CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
    ),
];

pub const REQUIRED_PROFILE_1_RESULT_CATEGORIES: &[&str] = &[
    CATEGORY_FIXTURE_MANIFEST,
    CATEGORY_KISS,
    CATEGORY_RNODE_COMMAND,
    CATEGORY_RNODE_CONFIG_VALIDATION,
    CATEGORY_RNODE_STAT,
    CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
];

pub const PROFILE_1_FINAL_RESULTS: &[ExpectedFinalResult<'_>] = &[
    ExpectedFinalResult {
        id: RESULT_ID_FIXTURE_MANIFEST,
        category: CATEGORY_FIXTURE_MANIFEST,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_KISS,
        category: CATEGORY_KISS,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNODE_COMMAND,
        category: CATEGORY_RNODE_COMMAND,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNODE_CONFIG_VALIDATION,
        category: CATEGORY_RNODE_CONFIG_VALIDATION,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNODE_STAT,
        category: CATEGORY_RNODE_STAT,
        detail: None,
    },
    ExpectedFinalResult {
        id: RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY,
        category: CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
        detail: Some(ExpectedOracleDetail {
            oracle_mode: "fixture_replay",
            evidence_role: "fixture_replay",
            compatibility_proof: false,
            commands: "kiss-encode,kiss-decode,rnode-command",
        }),
    },
];

const MANIFEST: &str = include_str!("../../../fixtures/rns/profile_1_kiss_rnode/manifest.json");
const KISS_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/kiss_vectors.json");
const KISS_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/kiss_negative_vectors.json");
const RNODE_COMMAND_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_command_vectors.json");
const RNODE_CONFIG_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_config_validation_vectors.json");
const RNODE_STAT_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_stat_vectors.json");

pub fn profile_1_results() -> Vec<ConformanceResult> {
    let mut results = profile_1_fixture_results();
    results.extend(profile_1_oracle_unavailable_results());
    results
}

pub fn profile_1_fixture_results() -> Vec<ConformanceResult> {
    vec![
        fixture_result(
            RESULT_ID_FIXTURE_MANIFEST,
            CATEGORY_FIXTURE_MANIFEST,
            validate_fixture_manifest(),
        ),
        fixture_result(RESULT_ID_KISS, CATEGORY_KISS, validate_kiss_fixtures()),
        fixture_result(
            RESULT_ID_RNODE_COMMAND,
            CATEGORY_RNODE_COMMAND,
            validate_fixture_cases(RNODE_COMMAND_FIXTURE, 10),
        ),
        fixture_result(
            RESULT_ID_RNODE_CONFIG_VALIDATION,
            CATEGORY_RNODE_CONFIG_VALIDATION,
            validate_fixture_cases(RNODE_CONFIG_FIXTURE, 7),
        ),
        fixture_result(
            RESULT_ID_RNODE_STAT,
            CATEGORY_RNODE_STAT,
            validate_fixture_cases(RNODE_STAT_FIXTURE, 11),
        ),
    ]
}

pub fn profile_1_oracle_unavailable_results() -> [ConformanceResult; 1] {
    [invalid_environment_result(
        RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY,
        CATEGORY_RNS_ORACLE_FIXTURE_REPLAY,
        "fixture replay captures are generated by private evidence tooling",
    )]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile1FinalEvidence {
    fixture_replay_commands: Vec<String>,
}

impl Profile1FinalEvidence {
    pub fn new(fixture_replay_commands: Vec<String>) -> Result<Self, FinalReportError> {
        if fixture_replay_commands.as_slice() != ["kiss-encode", "kiss-decode", "rnode-command"] {
            return Err(invalid_evidence(
                "Profile 1 final evidence requires kiss-encode,kiss-decode,rnode-command fixture replay",
            ));
        }
        Ok(Self {
            fixture_replay_commands,
        })
    }

    pub fn from_capture_dir(capture_dir: &Path) -> Result<Self, FinalReportError> {
        let kiss = load_capture(capture_dir, "kiss_encode.json")?;
        let kiss_decode = load_capture(capture_dir, "kiss_decode.json")?;
        let rnode = load_capture(capture_dir, "rnode_command.json")?;
        expect_capture(
            &kiss,
            "kiss_encode.json",
            "kiss-encode",
            "fixture_replay",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_capture(
            &kiss_decode,
            "kiss_decode.json",
            "kiss-decode",
            "fixture_replay",
            EXPECTED_RETICULUM_COMMIT,
        )?;
        expect_kiss_decode_capture(&kiss_decode)?;
        expect_capture(
            &rnode,
            "rnode_command.json",
            "rnode-command",
            "fixture_replay",
            EXPECTED_RETICULUM_COMMIT,
        )?;

        Self::new(vec![
            required_string_field(&kiss, "kiss_encode.json", "command")?.to_owned(),
            required_string_field(&kiss_decode, "kiss_decode.json", "command")?.to_owned(),
            required_string_field(&rnode, "rnode_command.json", "command")?.to_owned(),
        ])
    }
}

fn expect_kiss_decode_capture(document: &Value) -> Result<(), FinalReportError> {
    expect_string_value(
        document.get("encoded_hex"),
        "kiss_decode.json encoded_hex",
        PROFILE_1_KISS_DECODE_CAPTURE_HEX,
    )?;
    let Some(frames) = document.get("frames").and_then(Value::as_array) else {
        return Err(invalid_evidence("kiss_decode.json is missing frames array"));
    };
    if frames.len() != 1 {
        return Err(invalid_evidence(format!(
            "kiss_decode.json expected 1 decoded frame, got {}",
            frames.len()
        )));
    }
    let frame = &frames[0];
    expect_string_value(
        frame.get("kind"),
        "kiss_decode.json frames[0].kind",
        PROFILE_1_KISS_DECODE_KIND,
    )?;
    expect_string_value(
        frame.get("command_hex"),
        "kiss_decode.json frames[0].command_hex",
        PROFILE_1_KISS_DECODE_COMMAND_HEX,
    )?;
    expect_string_value(
        frame.get("payload_hex"),
        "kiss_decode.json frames[0].payload_hex",
        PROFILE_1_KISS_DECODE_PAYLOAD_HEX,
    )
}

fn expect_string_value(
    value: Option<&Value>,
    label: &str,
    expected: &str,
) -> Result<(), FinalReportError> {
    let Some(actual) = value.and_then(Value::as_str) else {
        return Err(invalid_evidence(format!(
            "{label} is missing or not a string"
        )));
    };
    if actual != expected {
        return Err(invalid_evidence(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

pub fn profile_1_final_results(evidence: &Profile1FinalEvidence) -> Vec<ConformanceResult> {
    let mut results = profile_1_fixture_results();
    results.push(ConformanceResult {
        id: RESULT_ID_RNS_ORACLE_FIXTURE_REPLAY.to_owned(),
        category: CATEGORY_RNS_ORACLE_FIXTURE_REPLAY.to_owned(),
        status: crate::report::ConformanceStatus::Passed,
        detail: Some(oracle_detail(
            "fixture_replay",
            "fixture_replay",
            false,
            &evidence.fixture_replay_commands,
            EXPECTED_RETICULUM_COMMIT,
        )),
    });
    results
}

pub fn profile_1_report(
    run_id: impl Into<String>,
    hyf_commit: impl Into<String>,
    started_at: impl Into<String>,
    environment: ConformanceEnvironment,
) -> ConformanceRun {
    ConformanceRun::new_profile(
        PROFILE_1_KISS_RNODE,
        run_id,
        hyf_commit,
        crate::fixtures::EXPECTED_RETICULUM_COMMIT,
        started_at,
        environment,
        profile_1_results(),
    )
}

pub fn profile_1_final_report(
    run_id: impl Into<String>,
    hyf_commit: impl Into<String>,
    started_at: impl Into<String>,
    environment: ConformanceEnvironment,
    evidence: &Profile1FinalEvidence,
) -> Result<ConformanceRun, FinalReportError> {
    let report = ConformanceRun::new_profile(
        PROFILE_1_KISS_RNODE,
        run_id,
        hyf_commit,
        EXPECTED_RETICULUM_COMMIT,
        started_at,
        environment,
        profile_1_final_results(evidence),
    );
    validate_profile_1_final_report(&report)?;
    Ok(report)
}

pub fn validate_profile_1_final_report(report: &ConformanceRun) -> Result<(), FinalReportError> {
    if report.profile != PROFILE_1_KISS_RNODE {
        return Err(invalid_evidence("Profile 1 final report has wrong profile"));
    }
    if report.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
        return Err(invalid_evidence(
            "Profile 1 final report has wrong Reticulum commit",
        ));
    }
    if report.environment.oracle.is_some() {
        return Err(invalid_evidence(
            "Profile 1 final report must not include oracle environment metadata",
        ));
    }
    validate_final_results(
        &report.results,
        PROFILE_1_FINAL_RESULTS,
        EXPECTED_RETICULUM_COMMIT,
    )
}

pub fn required_categories_are_present(results: &[ConformanceResult]) -> bool {
    let categories: BTreeSet<&str> = results
        .iter()
        .map(|result| result.category.as_str())
        .collect();
    REQUIRED_PROFILE_1_RESULT_CATEGORIES
        .iter()
        .all(|category| categories.contains(category))
}

fn validate_fixture_manifest() -> Result<(), FixtureError> {
    let manifest = parse_manifest_for_profile(MANIFEST, PROFILE_1_KISS_RNODE)?;

    assert_exact_manifest_entries(
        &manifest,
        &[
            ExpectedManifestEntry {
                file: "kiss_vectors.json",
                category: CATEGORY_KISS,
                case_count: 5,
                contents: KISS_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "kiss_negative_vectors.json",
                category: "kiss_negative",
                case_count: 4,
                contents: KISS_NEGATIVE_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_command_vectors.json",
                category: CATEGORY_RNODE_COMMAND,
                case_count: 10,
                contents: RNODE_COMMAND_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_config_validation_vectors.json",
                category: CATEGORY_RNODE_CONFIG_VALIDATION,
                case_count: 7,
                contents: RNODE_CONFIG_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_stat_vectors.json",
                category: CATEGORY_RNODE_STAT,
                case_count: 11,
                contents: RNODE_STAT_FIXTURE,
            },
        ],
    )
}

fn validate_kiss_fixtures() -> Result<(), FixtureError> {
    validate_fixture_cases(KISS_FIXTURE, 5)?;
    validate_fixture_cases(KISS_NEGATIVE_FIXTURE, 4)
}

fn validate_fixture_cases(contents: &str, expected_count: usize) -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<Value> =
        parse_fixture_cases_for_profile(contents, PROFILE_1_KISS_RNODE)?;
    if fixture.cases.len() == expected_count {
        return Ok(());
    }

    Err(FixtureError::UnexpectedFixtureValue {
        field: "case_count".to_owned(),
        value: fixture.cases.len().to_string(),
    })
}
