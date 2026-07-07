#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

#[cfg(feature = "python_oracle")]
use std::path::{Path, PathBuf};

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
    let Some(reticulum_path) = reticulum_path else {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::MissingReticulumPath,
        );
    };

    if !reticulum_path.is_dir() {
        return OracleReadiness::invalid_environment(
            OracleInvalidEnvironment::ReticulumPathNotDirectory,
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
    fn existing_directory_passes_readiness() {
        let readiness = check_oracle_environment(Some(Path::new(".")));

        assert_eq!(readiness, OracleReadiness::passed());
    }
}
