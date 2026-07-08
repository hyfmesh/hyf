use serde::{Deserialize, Serialize};

use crate::fixtures::{EXPECTED_PROFILE, EXPECTED_RETICULUM_COMMIT};

pub const CONFORMANCE_RUN_SCHEMA: &str = "hyf.rns.conformance_run.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceRun {
    pub schema: String,
    pub run_id: String,
    pub profile: String,
    pub hyf_commit: String,
    pub reticulum_commit: String,
    pub started_at: String,
    pub environment: ConformanceEnvironment,
    pub results: Vec<ConformanceResult>,
}

impl ConformanceRun {
    pub fn profile_0(
        run_id: impl Into<String>,
        hyf_commit: impl Into<String>,
        started_at: impl Into<String>,
        environment: ConformanceEnvironment,
        results: Vec<ConformanceResult>,
    ) -> Self {
        Self {
            schema: CONFORMANCE_RUN_SCHEMA.to_owned(),
            run_id: run_id.into(),
            profile: EXPECTED_PROFILE.to_owned(),
            hyf_commit: hyf_commit.into(),
            reticulum_commit: EXPECTED_RETICULUM_COMMIT.to_owned(),
            started_at: started_at.into(),
            environment,
            results,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceEnvironment {
    pub os: String,
    pub arch: String,
    pub rust_toolchain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle: Option<OracleEnvironment>,
}

impl ConformanceEnvironment {
    pub fn new(
        os: impl Into<String>,
        arch: impl Into<String>,
        rust_toolchain: impl Into<String>,
    ) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
            rust_toolchain: rust_toolchain.into(),
            oracle: None,
        }
    }

    pub fn with_oracle(mut self, oracle: OracleEnvironment) -> Self {
        self.oracle = Some(oracle);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleEnvironment {
    pub reticulum_module_path: String,
    pub reticulum_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rns_version: Option<String>,
    pub cryptography_version: String,
    pub pyserial_version: String,
}

impl OracleEnvironment {
    pub fn new(
        reticulum_module_path: impl Into<String>,
        reticulum_commit: impl Into<String>,
        cryptography_version: impl Into<String>,
        pyserial_version: impl Into<String>,
    ) -> Self {
        Self {
            reticulum_module_path: reticulum_module_path.into(),
            reticulum_commit: reticulum_commit.into(),
            rns_version: None,
            cryptography_version: cryptography_version.into(),
            pyserial_version: pyserial_version.into(),
        }
    }

    pub fn with_rns_version(mut self, rns_version: impl Into<String>) -> Self {
        self.rns_version = Some(rns_version.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceResult {
    pub id: String,
    pub category: String,
    pub status: ConformanceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ConformanceResult {
    pub fn passed(id: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            category: category.into(),
            status: ConformanceStatus::Passed,
            detail: None,
        }
    }

    pub fn failed(
        id: impl Into<String>,
        category: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category: category.into(),
            status: ConformanceStatus::Failed,
            detail: Some(detail.into()),
        }
    }

    pub fn invalid_environment(
        id: impl Into<String>,
        category: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category: category.into(),
            status: ConformanceStatus::InvalidEnvironment,
            detail: Some(detail.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStatus {
    Passed,
    Failed,
    InvalidEnvironment,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        CONFORMANCE_RUN_SCHEMA, ConformanceEnvironment, ConformanceResult, ConformanceRun,
        OracleEnvironment,
    };
    use crate::fixtures::{EXPECTED_PROFILE, EXPECTED_RETICULUM_COMMIT};

    #[test]
    fn sample_report_serializes_with_stable_profile_0_contract() -> Result<(), serde_json::Error> {
        let environment = ConformanceEnvironment::new("macos", "aarch64", "rustup 1.92.0")
            .with_oracle(
                OracleEnvironment::new(
                    ".oracle/Reticulum/RNS/__init__.py",
                    EXPECTED_RETICULUM_COMMIT,
                    "49.0.0",
                    "3.5",
                )
                .with_rns_version("0.9.4"),
            );
        let report = ConformanceRun::profile_0(
            "profile0-local-0001",
            "c05d4d5b6e6ba1a009890eb773fa78d3d1c0daeb",
            "2026-07-08T00:00:00Z",
            environment,
            vec![
                ConformanceResult::passed(
                    "profile_0_packet_announce.identity_signature.synthetic.0001",
                    "identity_signature",
                ),
                ConformanceResult::invalid_environment(
                    "profile_0_packet_announce.python_oracle.local",
                    "python_oracle",
                    "HYF_RETICULUM_PATH is not configured",
                ),
            ],
        );

        let value = serde_json::to_value(report)?;

        assert_eq!(value["schema"], CONFORMANCE_RUN_SCHEMA);
        assert_eq!(value["profile"], EXPECTED_PROFILE);
        assert_eq!(value["reticulum_commit"], EXPECTED_RETICULUM_COMMIT);
        assert_eq!(value["results"][0]["status"], "passed");
        assert_eq!(value["results"][1]["status"], "invalid_environment");
        assert_eq!(
            value["environment"]["oracle"]["reticulum_commit"],
            EXPECTED_RETICULUM_COMMIT
        );
        assert!(value["results"][0].get("detail").is_none());
        Ok(())
    }

    #[test]
    fn conformance_run_schema_records_expected_required_fields() -> Result<(), serde_json::Error> {
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/conformance_run.schema.json"))?;

        assert_eq!(
            schema["properties"]["schema"]["const"],
            CONFORMANCE_RUN_SCHEMA
        );
        assert_eq!(schema["properties"]["profile"]["const"], EXPECTED_PROFILE);
        assert_eq!(
            schema["properties"]["hyf_commit"]["pattern"],
            "^[0-9a-f]{40}$"
        );
        assert_eq!(
            schema["$defs"]["result"]["properties"]["status"]["enum"],
            json!(["passed", "failed", "invalid_environment"])
        );
        assert_eq!(schema["properties"]["results"]["minItems"], 1);
        Ok(())
    }
}
