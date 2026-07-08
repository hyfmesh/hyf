use crate::fixtures::FixtureError;
use crate::report::{ConformanceResult, ConformanceStatus};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub invalid_environment: usize,
}

impl RunnerSummary {
    pub fn from_results(results: &[ConformanceResult]) -> Self {
        summarize_results(results)
    }

    pub const fn is_clean(&self) -> bool {
        self.failed == 0 && self.invalid_environment == 0
    }
}

pub fn summarize_results(results: &[ConformanceResult]) -> RunnerSummary {
    let mut summary = RunnerSummary {
        total: results.len(),
        ..RunnerSummary::default()
    };

    for result in results {
        match result.status {
            ConformanceStatus::Passed => summary.passed += 1,
            ConformanceStatus::Failed => summary.failed += 1,
            ConformanceStatus::InvalidEnvironment => summary.invalid_environment += 1,
        }
    }

    summary
}

pub fn passed_result(id: impl Into<String>, category: impl Into<String>) -> ConformanceResult {
    ConformanceResult::passed(id, category)
}

pub fn failed_result(
    id: impl Into<String>,
    category: impl Into<String>,
    detail: impl Into<String>,
) -> ConformanceResult {
    ConformanceResult::failed(id, category, detail)
}

pub fn invalid_environment_result(
    id: impl Into<String>,
    category: impl Into<String>,
    detail: impl Into<String>,
) -> ConformanceResult {
    ConformanceResult::invalid_environment(id, category, detail)
}

pub fn fixture_result(
    id: impl Into<String>,
    category: impl Into<String>,
    result: Result<(), FixtureError>,
) -> ConformanceResult {
    match result {
        Ok(()) => passed_result(id, category),
        Err(error) => failed_result(id, category, error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RunnerSummary, failed_result, fixture_result, invalid_environment_result, passed_result,
        summarize_results,
    };
    use crate::fixtures::FixtureError;
    use crate::report::ConformanceStatus;

    #[test]
    fn summary_counts_all_passed_results_as_clean() {
        let results = vec![
            passed_result("profile_0_packet_announce.identity", "identity_signature"),
            passed_result("profile_0_packet_announce.packet_header", "packet_header"),
        ];

        let summary = summarize_results(&results);

        assert_eq!(
            summary,
            RunnerSummary {
                total: 2,
                passed: 2,
                failed: 0,
                invalid_environment: 0,
            }
        );
        assert!(summary.is_clean());
    }

    #[test]
    fn summary_counts_failed_and_invalid_environment_results() {
        let results = vec![
            passed_result("profile_0_packet_announce.identity", "identity_signature"),
            failed_result(
                "profile_0_packet_announce.announce",
                "announce",
                "signature mismatch",
            ),
            invalid_environment_result(
                "profile_0_packet_announce.python_oracle.local",
                "python_oracle",
                "HYF_RETICULUM_PATH is not configured",
            ),
        ];

        let summary = RunnerSummary::from_results(&results);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.invalid_environment, 1);
        assert!(!summary.is_clean());
    }

    #[test]
    fn fixture_result_maps_typed_errors_to_failed_rows() {
        let passed = fixture_result("profile_0_packet_announce.fixture.valid", "fixture", Ok(()));
        let failed = fixture_result(
            "profile_0_packet_announce.fixture.invalid",
            "fixture",
            Err(FixtureError::InvalidHex),
        );

        assert_eq!(passed.status, ConformanceStatus::Passed);
        assert_eq!(passed.detail, None);
        assert_eq!(failed.status, ConformanceStatus::Failed);
        assert_eq!(failed.detail.as_deref(), Some("invalid hex"));
    }
}
