#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

pub mod benchmark_inputs;
pub mod fixtures;
pub mod profile0;
pub mod profile1;
pub mod profile2;
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
pub const PINNED_CRYPTOGRAPHY_VERSION: &str = "49.0.0";
#[cfg(feature = "python_oracle")]
pub const PINNED_PYSERIAL_VERSION: &str = "3.5";
#[cfg(feature = "python_oracle")]
pub const PINNED_CRYPTOGRAPHY_PACKAGE: &str = "cryptography==49.0.0";
#[cfg(feature = "python_oracle")]
pub const PINNED_PYSERIAL_PACKAGE: &str = "pyserial==3.5";

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
    ReticulumWorktreeDirty,
    ReticulumWorktreeStatusUnavailable,
    OraclePackageVersionMismatch,
}

#[cfg(feature = "python_oracle")]
impl std::fmt::Display for OracleInvalidEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingReticulumPath => formatter.write_str("missing Reticulum path"),
            Self::ReticulumPathNotDirectory => {
                formatter.write_str("Reticulum path is not a directory")
            }
            Self::OracleCommandUnavailable => formatter.write_str("oracle command unavailable"),
            Self::OracleProbeFailed => formatter.write_str("oracle probe failed"),
            Self::OracleModulePathMismatch => formatter.write_str("oracle module path mismatch"),
            Self::ReticulumCommitMismatch => formatter.write_str("Reticulum commit mismatch"),
            Self::ReticulumWorktreeDirty => {
                formatter.write_str("Reticulum tracked or untracked worktree is dirty")
            }
            Self::ReticulumWorktreeStatusUnavailable => {
                formatter.write_str("Reticulum worktree status unavailable")
            }
            Self::OraclePackageVersionMismatch => {
                formatter.write_str("oracle package version mismatch")
            }
        }
    }
}

#[cfg(feature = "python_oracle")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleEnvironmentMetadata {
    pub reticulum_module_path: String,
    pub reticulum_commit: String,
    pub rns_version: Option<String>,
    pub cryptography_version: String,
    pub pyserial_version: String,
}

#[cfg(feature = "python_oracle")]
impl From<OracleEnvironmentMetadata> for crate::report::OracleEnvironment {
    fn from(metadata: OracleEnvironmentMetadata) -> Self {
        let mut oracle = Self::new(
            metadata.reticulum_module_path,
            metadata.reticulum_commit,
            metadata.cryptography_version,
            metadata.pyserial_version,
        );

        if let Some(rns_version) = metadata.rns_version {
            oracle = oracle.with_rns_version(rns_version);
        }

        oracle
    }
}

#[cfg(feature = "python_oracle")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleReadiness {
    status: OracleStatus,
    reason: Option<OracleInvalidEnvironment>,
    metadata: Option<OracleEnvironmentMetadata>,
}

#[cfg(feature = "python_oracle")]
impl OracleReadiness {
    pub fn passed(metadata: OracleEnvironmentMetadata) -> Self {
        Self {
            status: OracleStatus::Passed,
            reason: None,
            metadata: Some(metadata),
        }
    }

    pub const fn invalid_environment(reason: OracleInvalidEnvironment) -> Self {
        Self {
            status: OracleStatus::InvalidEnvironment,
            reason: Some(reason),
            metadata: None,
        }
    }

    pub const fn status(&self) -> OracleStatus {
        self.status
    }

    pub const fn reason(&self) -> Option<OracleInvalidEnvironment> {
        self.reason
    }

    pub const fn metadata(&self) -> Option<&OracleEnvironmentMetadata> {
        self.metadata.as_ref()
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
        .arg(PINNED_CRYPTOGRAPHY_PACKAGE)
        .arg("--with")
        .arg(PINNED_PYSERIAL_PACKAGE)
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

    let probe_metadata =
        match validate_oracle_probe_output(&output.stdout, reticulum_path.as_path()) {
            Ok(probe_metadata) => probe_metadata,
            Err(reason) => return OracleReadiness::invalid_environment(reason),
        };

    let reticulum_commit = match validate_reticulum_git_state(reticulum_path.as_path()) {
        Ok(commit) => commit,
        Err(reason) => return OracleReadiness::invalid_environment(reason),
    };

    OracleReadiness::passed(probe_metadata.with_reticulum_commit(reticulum_commit))
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
    cryptography: String,
    module: String,
    pyserial: String,
    rns_version: Option<String>,
    status: String,
}

#[cfg(feature = "python_oracle")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct OracleProbeMetadata {
    reticulum_module_path: String,
    rns_version: Option<String>,
    cryptography_version: String,
    pyserial_version: String,
}

#[cfg(feature = "python_oracle")]
impl OracleProbeMetadata {
    fn with_reticulum_commit(self, reticulum_commit: String) -> OracleEnvironmentMetadata {
        OracleEnvironmentMetadata {
            reticulum_module_path: self.reticulum_module_path,
            reticulum_commit,
            rns_version: self.rns_version,
            cryptography_version: self.cryptography_version,
            pyserial_version: self.pyserial_version,
        }
    }
}

#[cfg(feature = "python_oracle")]
fn validate_oracle_probe_output(
    stdout: &[u8],
    reticulum_path: &Path,
) -> Result<OracleProbeMetadata, OracleInvalidEnvironment> {
    let probe: OracleProbeOutput =
        serde_json::from_slice(stdout).map_err(|_| OracleInvalidEnvironment::OracleProbeFailed)?;

    if probe.status != "passed" {
        return Err(OracleInvalidEnvironment::OracleProbeFailed);
    }

    if probe.cryptography.is_empty()
        || probe.pyserial.is_empty()
        || probe.rns_version.as_deref() == Some("")
    {
        return Err(OracleInvalidEnvironment::OracleProbeFailed);
    }

    if probe.cryptography != PINNED_CRYPTOGRAPHY_VERSION
        || probe.pyserial != PINNED_PYSERIAL_VERSION
    {
        return Err(OracleInvalidEnvironment::OraclePackageVersionMismatch);
    }

    if !module_path_is_under_reticulum_path(Path::new(&probe.module), reticulum_path) {
        return Err(OracleInvalidEnvironment::OracleModulePathMismatch);
    }

    Ok(OracleProbeMetadata {
        reticulum_module_path: probe.module,
        rns_version: probe.rns_version,
        cryptography_version: probe.cryptography,
        pyserial_version: probe.pyserial,
    })
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
fn reticulum_commit(reticulum_path: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(reticulum_path)
        .arg("rev-parse")
        .arg("HEAD")
        .output();

    let Ok(output) = output else {
        return None;
    };

    if !output.status.success() {
        return None;
    }

    reticulum_commit_from_output(&output.stdout)
}

#[cfg(feature = "python_oracle")]
fn validate_reticulum_git_state(reticulum_path: &Path) -> Result<String, OracleInvalidEnvironment> {
    validate_reticulum_git_state_with_expected(reticulum_path, PINNED_RETICULUM_COMMIT)
}

#[cfg(feature = "python_oracle")]
fn validate_reticulum_git_state_with_expected(
    reticulum_path: &Path,
    expected_commit: &str,
) -> Result<String, OracleInvalidEnvironment> {
    let Some(reticulum_commit) = reticulum_commit(reticulum_path) else {
        return Err(OracleInvalidEnvironment::ReticulumCommitMismatch);
    };

    if reticulum_commit != expected_commit {
        return Err(OracleInvalidEnvironment::ReticulumCommitMismatch);
    }

    let Some(reticulum_worktree_is_clean) = reticulum_worktree_is_clean(reticulum_path) else {
        return Err(OracleInvalidEnvironment::ReticulumWorktreeStatusUnavailable);
    };
    if !reticulum_worktree_is_clean {
        return Err(OracleInvalidEnvironment::ReticulumWorktreeDirty);
    }

    Ok(reticulum_commit)
}

#[cfg(feature = "python_oracle")]
fn reticulum_worktree_is_clean(reticulum_path: &Path) -> Option<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(reticulum_path)
        .arg("status")
        .arg("--porcelain")
        .arg("--untracked-files=all")
        .output();

    let Ok(output) = output else {
        return None;
    };

    if !output.status.success() {
        return None;
    }

    Some(output.stdout.is_empty())
}

#[cfg(all(test, feature = "python_oracle"))]
fn reticulum_commit_output_is_pinned(stdout: &[u8]) -> bool {
    reticulum_commit_from_output(stdout).as_deref() == Some(PINNED_RETICULUM_COMMIT)
}

#[cfg(feature = "python_oracle")]
fn reticulum_commit_from_output(stdout: &[u8]) -> Option<String> {
    let commit = String::from_utf8_lossy(stdout).trim().to_owned();
    if crate::fixtures::reticulum_commit_is_valid(&commit) {
        return Some(commit);
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
    "rns_version": getattr(RNS, "__version__", None),
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
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        OracleEnvironmentMetadata, OracleInvalidEnvironment, OracleProbeMetadata, OracleReadiness,
        OracleStatus, PINNED_CRYPTOGRAPHY_VERSION, PINNED_PYSERIAL_VERSION,
        PINNED_RETICULUM_COMMIT, check_oracle_environment, check_oracle_environment_with_command,
        reticulum_commit, reticulum_commit_output_is_pinned, reticulum_worktree_is_clean,
        validate_oracle_probe_output, validate_reticulum_git_state,
        validate_reticulum_git_state_with_expected,
    };

    static TEST_REPO_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn missing_reticulum_path_reports_invalid_environment() {
        let readiness = check_oracle_environment(None);

        assert_eq!(readiness.status(), OracleStatus::InvalidEnvironment);
        assert_eq!(
            readiness.reason(),
            Some(OracleInvalidEnvironment::MissingReticulumPath)
        );
        assert!(readiness.metadata().is_none());
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
    fn oracle_invalid_environment_has_stable_display_text() {
        assert_eq!(
            OracleInvalidEnvironment::OracleModulePathMismatch.to_string(),
            "oracle module path mismatch"
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
            assert_eq!(readiness.status(), OracleStatus::Passed);
            assert_eq!(readiness.reason(), None);
            assert!(readiness.metadata().is_some());
            if let Some(metadata) = readiness.metadata() {
                assert_eq!(metadata.reticulum_commit, PINNED_RETICULUM_COMMIT);
                assert!(!metadata.reticulum_module_path.is_empty());
                assert_eq!(metadata.cryptography_version, PINNED_CRYPTOGRAPHY_VERSION);
                assert_eq!(metadata.pyserial_version, PINNED_PYSERIAL_VERSION);
            }
        }
    }

    #[test]
    fn parsed_oracle_probe_accepts_module_under_reticulum_path() -> Result<(), serde_json::Error> {
        let payload = serde_json::json!({
            "cryptography": PINNED_CRYPTOGRAPHY_VERSION,
            "module": Path::new("src/lib.rs").to_string_lossy(),
            "pyserial": PINNED_PYSERIAL_VERSION,
            "rns_version": "0.9.4",
            "status": "passed",
        });
        let stdout = serde_json::to_vec(&payload)?;

        assert_eq!(
            validate_oracle_probe_output(&stdout, Path::new(".")),
            Ok(OracleProbeMetadata {
                reticulum_module_path: Path::new("src/lib.rs").to_string_lossy().to_string(),
                rns_version: Some("0.9.4".to_owned()),
                cryptography_version: PINNED_CRYPTOGRAPHY_VERSION.to_owned(),
                pyserial_version: PINNED_PYSERIAL_VERSION.to_owned(),
            })
        );
        Ok(())
    }

    #[test]
    fn parsed_oracle_probe_rejects_module_outside_reticulum_path() -> Result<(), serde_json::Error>
    {
        let payload = serde_json::json!({
            "cryptography": PINNED_CRYPTOGRAPHY_VERSION,
            "module": Path::new("Cargo.toml").to_string_lossy(),
            "pyserial": PINNED_PYSERIAL_VERSION,
            "rns_version": null,
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
            "cryptography": PINNED_CRYPTOGRAPHY_VERSION,
            "module": Path::new("src/lib.rs").to_string_lossy(),
            "pyserial": PINNED_PYSERIAL_VERSION,
            "rns_version": null,
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

    #[test]
    fn reticulum_git_state_rejects_commit_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestGitRepo::create()?;

        assert_eq!(
            validate_reticulum_git_state(repo.path()),
            Err(OracleInvalidEnvironment::ReticulumCommitMismatch)
        );
        Ok(())
    }

    #[test]
    fn reticulum_git_state_accepts_clean_matching_commit() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestGitRepo::create()?;
        let commit = reticulum_commit(repo.path()).ok_or("missing test commit")?;

        assert_eq!(
            validate_reticulum_git_state_with_expected(repo.path(), &commit),
            Ok(commit)
        );
        Ok(())
    }

    #[test]
    fn reticulum_git_state_rejects_dirty_tracked_changes() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestGitRepo::create()?;
        let commit = reticulum_commit(repo.path()).ok_or("missing test commit")?;
        std::fs::write(repo.path().join("tracked.txt"), "changed\n")?;

        assert_eq!(
            validate_reticulum_git_state_with_expected(repo.path(), &commit),
            Err(OracleInvalidEnvironment::ReticulumWorktreeDirty)
        );
        Ok(())
    }

    #[test]
    fn reticulum_worktree_cleanliness_accepts_clean_repo() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestGitRepo::create()?;

        assert_eq!(reticulum_worktree_is_clean(repo.path()), Some(true));
        Ok(())
    }

    #[test]
    fn reticulum_worktree_cleanliness_rejects_tracked_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestGitRepo::create()?;
        std::fs::write(repo.path().join("tracked.txt"), "changed\n")?;

        assert_eq!(reticulum_worktree_is_clean(repo.path()), Some(false));
        Ok(())
    }

    #[test]
    fn reticulum_worktree_cleanliness_rejects_untracked_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestGitRepo::create()?;
        std::fs::write(repo.path().join("untracked.txt"), "local only\n")?;

        assert_eq!(reticulum_worktree_is_clean(repo.path()), Some(false));
        Ok(())
    }

    #[test]
    fn passed_readiness_metadata_converts_to_report_oracle_environment() {
        let metadata = OracleEnvironmentMetadata {
            reticulum_module_path: "RNS/__init__.py".to_owned(),
            reticulum_commit: PINNED_RETICULUM_COMMIT.to_owned(),
            rns_version: Some("0.9.4".to_owned()),
            cryptography_version: PINNED_CRYPTOGRAPHY_VERSION.to_owned(),
            pyserial_version: PINNED_PYSERIAL_VERSION.to_owned(),
        };

        let readiness = OracleReadiness::passed(metadata.clone());
        let report_oracle: crate::report::OracleEnvironment = metadata.into();

        assert_eq!(readiness.status(), OracleStatus::Passed);
        assert!(readiness.metadata().is_some());
        assert_eq!(report_oracle.reticulum_commit, PINNED_RETICULUM_COMMIT);
        assert_eq!(report_oracle.rns_version.as_deref(), Some("0.9.4"));
    }

    fn check_oracle_environment_from_env_if_configured() -> Option<OracleReadiness> {
        std::env::var_os("HYF_RETICULUM_PATH")
            .map(std::path::PathBuf::from)
            .map(|path| check_oracle_environment(Some(path.as_path())))
    }

    struct TestGitRepo {
        path: PathBuf,
    }

    impl TestGitRepo {
        fn create() -> Result<Self, Box<dyn std::error::Error>> {
            let path = unique_test_path()?;
            std::fs::create_dir_all(&path)?;
            run_git(path.as_path(), &["init"])?;
            run_git(path.as_path(), &["config", "user.name", "HYF Test"])?;
            run_git(
                path.as_path(),
                &["config", "user.email", "hyf-test@example.invalid"],
            )?;
            std::fs::write(path.join("tracked.txt"), "initial\n")?;
            run_git(path.as_path(), &["add", "tracked.txt"])?;
            run_git(path.as_path(), &["commit", "-m", "initial"])?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            self.path.as_path()
        }
    }

    impl Drop for TestGitRepo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn unique_test_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = TEST_REPO_COUNTER.fetch_add(1, Ordering::Relaxed);
        Ok(std::env::temp_dir().join(format!(
            "hyf-reticulum-git-state-{}-{nanos}-{counter}",
            std::process::id()
        )))
    }

    fn run_git(repo_path: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args(args)
            .status()?;
        if !status.success() {
            return Err("git test command failed".into());
        }
        Ok(())
    }
}
