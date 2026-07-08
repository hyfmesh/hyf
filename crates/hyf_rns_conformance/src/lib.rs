#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

#[cfg(feature = "python_oracle")]
use std::path::{Path, PathBuf};
#[cfg(feature = "python_oracle")]
use std::process::Command;

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
        .env("PYTHONPATH", reticulum_path)
        .output();

    let Ok(output) = output else {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::OracleCommandUnavailable,
        );
    };

    if !output.status.success() {
        return OracleReadiness::invalid_environment(OracleInvalidEnvironment::OracleProbeFailed);
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
        check_oracle_environment_with_command,
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

    fn check_oracle_environment_from_env_if_configured() -> Option<OracleReadiness> {
        std::env::var_os("HYF_RETICULUM_PATH")
            .map(std::path::PathBuf::from)
            .map(|path| check_oracle_environment(Some(path.as_path())))
    }
}
