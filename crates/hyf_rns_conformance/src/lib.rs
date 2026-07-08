#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

pub mod fixtures;
pub mod report;
pub mod runner;

#[cfg(feature = "python_oracle")]
use serde::Deserialize;
#[cfg(feature = "python_oracle")]
use std::path::{Path, PathBuf};
#[cfg(feature = "python_oracle")]
use std::process::Command;

#[cfg(feature = "python_oracle")]
pub const PINNED_RETICULUM_COMMIT: &str = "422dc05549bf28f45e9b9c5172336a1ba4df0ec0";

#[cfg(feature = "python_oracle")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleStatus {
    Passed,
    InvalidEnvironment,
}

#[cfg(feature = "python_oracle")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleInvalidEnvironment {
    MissingReticulumPath,
    ReticulumPathNotDirectory,
    OracleCommandUnavailable,
    OracleProbeFailed,
    OracleModulePathMismatch,
    ReticulumCommitMismatch,
}

#[cfg(feature = "python_oracle")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleReadiness {
    status: OracleStatus,
    reason: Option<OracleInvalidEnvironment>,
}

#[cfg(feature = "python_oracle")]
impl OracleReadiness {
    pub const fn passed() -> Self {
        Self {
            status: OracleStatus::Passed,
            reason: None,
        }
    }

    pub const fn invalid_environment(reason: OracleInvalidEnvironment) -> Self {
        Self {
            status: OracleStatus::InvalidEnvironment,
            reason: Some(reason),
        }
    }

    pub const fn status(&self) -> OracleStatus {
        self.status
    }

    pub const fn reason(&self) -> Option<OracleInvalidEnvironment> {
        self.reason
    }
}

#[cfg(feature = "python_oracle")]
pub fn check_oracle_environment(reticulum_path: Option<&Path>) -> OracleReadiness {
    check_oracle_environment_with_command(reticulum_path, "uv")
}

#[cfg(feature = "python_oracle")]
pub fn check_oracle_environment_with_command(
    reticulum_path: Option<&Path>,
    uv_command: &str,
) -> OracleReadiness {
    let Some(reticulum_path) = reticulum_path else {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::MissingReticulumPath,
        );
    };

    let Some(reticulum_path) = resolve_reticulum_path(reticulum_path) else {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::ReticulumPathNotDirectory,
        );
    };

    let output = Command::new(uv_command)
        .arg("run")
        .arg("--with")
        .arg("cryptography")
        .arg("--with")
        .arg("pyserial")
        .arg("python")
        .arg("-c")
        .arg(ORACLE_READINESS_SCRIPT)
        .env("PYTHONPATH", &reticulum_path)
        .output();

    let Ok(output) = output else {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::OracleCommandUnavailable,
        );
    };

    if !output.status.success() {
        return OracleReadiness::invalid_environment(OracleInvalidEnvironment::OracleProbeFailed);
    }

    if let Err(reason) = validate_oracle_probe_output(&output.stdout, reticulum_path.as_path()) {
        return OracleReadiness::invalid_environment(reason);
    }

    if !reticulum_commit_is_pinned(reticulum_path.as_path()) {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::ReticulumCommitMismatch,
        );
    }

    OracleReadiness::passed()
}

#[cfg(feature = "python_oracle")]
pub fn check_oracle_environment_from_env() -> OracleReadiness {
    let Some(path) = std::env::var_os("HYF_RETICULUM_PATH").map(PathBuf::from) else {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::MissingReticulumPath,
        );
    };

    check_oracle_environment(Some(path.as_path()))
}

#[cfg(feature = "python_oracle")]
fn resolve_reticulum_path(reticulum_path: &Path) -> Option<PathBuf> {
    if reticulum_path.is_dir() {
        return Some(reticulum_path.to_path_buf());
    }

    if reticulum_path.is_absolute() {
        return None;
    }

    let from_current_dir = std::env::current_dir()
        .ok()
        .map(|current_dir| current_dir.join(reticulum_path));
    if let Some(path) = from_current_dir
        && path.is_dir()
    {
        return Some(path);
    }

    let from_workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(reticulum_path);
    if from_workspace_root.is_dir() {
        return Some(from_workspace_root);
    }

    None
}

#[cfg(feature = "python_oracle")]
#[derive(Deserialize)]
struct OracleProbeOutput {
    module: String,
    status: String,
}

#[cfg(feature = "python_oracle")]
fn validate_oracle_probe_output(
    stdout: &[u8],
    reticulum_path: &Path,
) -> Result<(), OracleInvalidEnvironment> {
    let probe: OracleProbeOutput =
        serde_json::from_slice(stdout).map_err(|_| OracleInvalidEnvironment::OracleProbeFailed)?;

    if probe.status != "passed" {
        return Err(OracleInvalidEnvironment::OracleProbeFailed);
    }

    if !module_path_is_under_reticulum_path(Path::new(&probe.module), reticulum_path) {
        return Err(OracleInvalidEnvironment::OracleModulePathMismatch);
    }

    Ok(())
}

#[cfg(feature = "python_oracle")]
fn module_path_is_under_reticulum_path(module_path: &Path, reticulum_path: &Path) -> bool {
    let Ok(module_path) = module_path.canonicalize() else {
        return false;
    };
    let Ok(reticulum_path) = reticulum_path.canonicalize() else {
        return false;
    };

    module_path.starts_with(reticulum_path)
}

#[cfg(feature = "python_oracle")]
fn reticulum_commit_is_pinned(reticulum_path: &Path) -> bool {
    let output = Command::new("git")
        .arg("-C")
        .arg(reticulum_path)
        .arg("rev-parse")
        .arg("HEAD")
        .output();

    let Ok(output) = output else {
        return false;
    };

    output.status.success() && reticulum_commit_output_is_pinned(&output.stdout)
}

#[cfg(feature = "python_oracle")]
fn reticulum_commit_output_is_pinned(stdout: &[u8]) -> bool {
    String::from_utf8_lossy(stdout).trim() == PINNED_RETICULUM_COMMIT
}

#[cfg(feature = "python_oracle")]
const ORACLE_READINESS_SCRIPT: &str = r#"
import json

import RNS
import cryptography
import serial

print(json.dumps({
    "cryptography": cryptography.__version__,
    "module": RNS.__file__,
    "pyserial": serial.VERSION,
    "status": "passed",
}, sort_keys=True))
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}

#[cfg(all(test, feature = "python_oracle"))]
mod python_oracle_tests {
    use std::path::Path;

    use super::{
        OracleInvalidEnvironment, OracleReadiness, OracleStatus, check_oracle_environment,
        check_oracle_environment_with_command, reticulum_commit_output_is_pinned,
        validate_oracle_probe_output,
    };

    #[test]
    fn missing_reticulum_path_reports_invalid_environment() {
        let readiness = check_oracle_environment(None);

        assert_eq!(readiness.status(), OracleStatus::InvalidEnvironment);
        assert_eq!(
            readiness.reason(),
            Some(OracleInvalidEnvironment::MissingReticulumPath)
        );
    }

    #[test]
    fn non_directory_reticulum_path_reports_invalid_environment() {
        let readiness = check_oracle_environment(Some(Path::new("definitely-not-a-directory")));

        assert_eq!(readiness.status(), OracleStatus::InvalidEnvironment);
        assert_eq!(
            readiness.reason(),
            Some(OracleInvalidEnvironment::ReticulumPathNotDirectory)
        );
    }

    #[test]
    fn existing_directory_with_missing_oracle_command_reports_invalid_environment() {
        let readiness = check_oracle_environment_with_command(
            Some(Path::new(".")),
            "definitely-not-a-hyf-oracle-command",
        );

        assert_eq!(readiness.status(), OracleStatus::InvalidEnvironment);
        assert_eq!(
            readiness.reason(),
            Some(OracleInvalidEnvironment::OracleCommandUnavailable)
        );
    }

    #[test]
    fn configured_reticulum_path_imports_python_oracle_dependencies() {
        let readiness = check_oracle_environment_from_env_if_configured();

        if let Some(readiness) = readiness {
            assert_eq!(readiness, OracleReadiness::passed());
        }
    }

    #[test]
    fn parsed_oracle_probe_accepts_module_under_reticulum_path() -> Result<(), serde_json::Error> {
        let payload = serde_json::json!({
            "module": Path::new("src/lib.rs").to_string_lossy(),
            "status": "passed",
        });
        let stdout = serde_json::to_vec(&payload)?;

        assert_eq!(
            validate_oracle_probe_output(&stdout, Path::new(".")),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn parsed_oracle_probe_rejects_module_outside_reticulum_path() -> Result<(), serde_json::Error>
    {
        let payload = serde_json::json!({
            "module": Path::new("Cargo.toml").to_string_lossy(),
            "status": "passed",
        });
        let stdout = serde_json::to_vec(&payload)?;

        assert_eq!(
            validate_oracle_probe_output(&stdout, Path::new("src")),
            Err(OracleInvalidEnvironment::OracleModulePathMismatch)
        );
        Ok(())
    }

    #[test]
    fn parsed_oracle_probe_rejects_non_passing_status() -> Result<(), serde_json::Error> {
        let payload = serde_json::json!({
            "module": Path::new("src/lib.rs").to_string_lossy(),
            "status": "failed",
        });
        let stdout = serde_json::to_vec(&payload)?;

        assert_eq!(
            validate_oracle_probe_output(&stdout, Path::new(".")),
            Err(OracleInvalidEnvironment::OracleProbeFailed)
        );
        Ok(())
    }

    #[test]
    fn reticulum_commit_parser_accepts_only_the_pinned_commit() {
        assert!(reticulum_commit_output_is_pinned(
            b"422dc05549bf28f45e9b9c5172336a1ba4df0ec0\n"
        ));
        assert!(!reticulum_commit_output_is_pinned(
            b"0000000000000000000000000000000000000000\n"
        ));
    }

    fn check_oracle_environment_from_env_if_configured() -> Option<OracleReadiness> {
        std::env::var_os("HYF_RETICULUM_PATH")
            .map(std::path::PathBuf::from)
            .map(|path| check_oracle_environment(Some(path.as_path())))
    }
}
