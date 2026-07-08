#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use hyf_rns_conformance::fixtures::{EXPECTED_PROFILE, EXPECTED_RETICULUM_COMMIT};
#[cfg(feature = "python_oracle")]
use hyf_rns_conformance::profile0::profile_0_report_with_required_oracle;
use hyf_rns_conformance::profile0::{profile_0_report, required_categories_are_present};
use hyf_rns_conformance::report::{
    CONFORMANCE_RUN_SCHEMA, ConformanceEnvironment, ConformanceRun, ConformanceStatus,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), CliError> {
    match CliCommand::parse(std::env::args().skip(1))? {
        CliCommand::Generate(args) => run_generate(*args),
        CliCommand::Validate(args) => run_validate(&args),
    }
}

fn run_generate(args: Args) -> Result<(), CliError> {
    let hyf_commit = derive_hyf_commit(
        args.hyf_repo_path.as_path(),
        args.expected_hyf_commit.as_deref(),
    )?;
    let environment = ConformanceEnvironment::new(
        args.os.clone(),
        args.arch.clone(),
        args.rust_toolchain.clone(),
    );
    let mut report = build_report(&args, environment, hyf_commit)?;
    apply_report_overrides(&mut report, &args)?;
    let json = serde_json::to_vec_pretty(&report)?;

    write_output(&args.output, &json)?;
    Ok(())
}

fn run_validate(args: &ValidateArgs) -> Result<(), CliError> {
    let input = std::fs::read(args.input.as_path())?;
    validate_report_bytes(&input, args.require_final_profile0)
}

fn validate_report_bytes(input: &[u8], require_final_profile0: bool) -> Result<(), CliError> {
    let report: ConformanceRun = serde_json::from_slice(input)?;
    if require_final_profile0 {
        validate_final_profile0_report(&report)?;
    }
    Ok(())
}

fn validate_final_profile0_report(report: &ConformanceRun) -> Result<(), CliError> {
    if report.schema != CONFORMANCE_RUN_SCHEMA {
        return Err(CliError::FinalReportInvalid("schema mismatch"));
    }
    if report.profile != EXPECTED_PROFILE {
        return Err(CliError::FinalReportInvalid("profile mismatch"));
    }
    if !is_full_lower_hex_commit(&report.hyf_commit) {
        return Err(CliError::FinalReportInvalid("invalid hyf commit"));
    }
    if report.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
        return Err(CliError::FinalReportInvalid("reticulum commit mismatch"));
    }
    if !required_categories_are_present(&report.results) {
        return Err(CliError::FinalReportInvalid(
            "missing required Profile 0 result category",
        ));
    }
    if report
        .results
        .iter()
        .any(|result| result.status == ConformanceStatus::Failed)
    {
        return Err(CliError::FinalReportInvalid("failed result present"));
    }
    if report
        .results
        .iter()
        .any(|result| result.status == ConformanceStatus::InvalidEnvironment)
    {
        return Err(CliError::FinalReportInvalid(
            "invalid environment result present",
        ));
    }

    let Some(oracle) = report.environment.oracle.as_ref() else {
        return Err(CliError::FinalReportInvalid("missing oracle metadata"));
    };
    if oracle.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
        return Err(CliError::FinalReportInvalid(
            "oracle reticulum commit mismatch",
        ));
    }

    Ok(())
}

fn build_report(
    args: &Args,
    environment: ConformanceEnvironment,
    hyf_commit: String,
) -> Result<ConformanceRun, CliError> {
    #[cfg(feature = "python_oracle")]
    {
        if args.require_oracle {
            let Some(reticulum_path) = args.reticulum_path.as_ref() else {
                return Err(CliError::MissingRequired("--reticulum-path"));
            };
            return Ok(profile_0_report_with_required_oracle(
                args.run_id.clone(),
                hyf_commit,
                args.started_at.clone(),
                environment,
                reticulum_path.as_path(),
            )?);
        }
        if args.reticulum_path.is_some() {
            return Err(CliError::OraclePathRequiresOracle);
        }
    }

    #[cfg(not(feature = "python_oracle"))]
    {
        if args.require_oracle || args.reticulum_path.is_some() {
            return Err(CliError::PythonOracleFeatureDisabled);
        }
    }

    Ok(profile_0_report(
        args.run_id.clone(),
        hyf_commit,
        args.started_at.clone(),
        environment,
    ))
}

fn derive_hyf_commit(
    hyf_repo_path: &Path,
    expected_hyf_commit: Option<&str>,
) -> Result<String, CliError> {
    let commit = git_stdout(hyf_repo_path, &["rev-parse", "HEAD"])?;
    if !is_full_lower_hex_commit(&commit) {
        return Err(CliError::InvalidHyfCommit(commit));
    }

    let status = git_stdout(
        hyf_repo_path,
        &["status", "--porcelain", "--untracked-files=no"],
    )?;
    if !status.is_empty() {
        return Err(CliError::DirtyHyfWorktree);
    }

    if let Some(expected_hyf_commit) = expected_hyf_commit
        && expected_hyf_commit != commit
    {
        return Err(CliError::ExpectedHyfCommitMismatch {
            expected: expected_hyf_commit.to_owned(),
            actual: commit,
        });
    }

    Ok(commit)
}

fn git_stdout(repo_path: &Path, args: &[&str]) -> Result<String, CliError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .map_err(CliError::GitCommandUnavailable)?;

    if !output.status.success() {
        return Err(CliError::GitCommandFailed);
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn is_full_lower_hex_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Eq, PartialEq)]
enum CliCommand {
    Generate(Box<Args>),
    Validate(ValidateArgs),
}

impl CliCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: Iterator<Item = String>,
    {
        let args: Vec<String> = args.collect();
        if args.first().map(String::as_str) == Some("validate") {
            return Ok(Self::Validate(ValidateArgs::parse(
                args.into_iter().skip(1),
            )?));
        }

        Ok(Self::Generate(Box::new(Args::parse(args.into_iter())?)))
    }
}

fn apply_report_overrides(report: &mut ConformanceRun, args: &Args) -> Result<(), CliError> {
    if args.require_oracle && args.report_path_root.is_none() {
        return Err(CliError::MissingRequired("--report-path-root"));
    }

    if let Some(report_path_root) = args.report_path_root.as_ref() {
        let Some(oracle) = report.environment.oracle.as_mut() else {
            return Err(CliError::ReportPathRootRequiresOracle);
        };
        oracle.reticulum_module_path =
            report_relative_path(&oracle.reticulum_module_path, report_path_root)?;
    }

    Ok(())
}

fn report_relative_path(module_path: &str, report_path_root: &Path) -> Result<String, CliError> {
    let module_path = Path::new(module_path);
    let module_path = module_path
        .canonicalize()
        .map_err(|error| CliError::PathCanonicalize {
            path: module_path.to_path_buf(),
            error,
        })?;
    let report_path_root =
        report_path_root
            .canonicalize()
            .map_err(|error| CliError::PathCanonicalize {
                path: report_path_root.to_path_buf(),
                error,
            })?;
    let relative_path = module_path
        .strip_prefix(&report_path_root)
        .map_err(|_| CliError::ReportPathRootMismatch)?;
    path_to_report_string(relative_path)
}

fn path_to_report_string(path: &Path) -> Result<String, CliError> {
    let Some(path) = path.to_str() else {
        return Err(CliError::NonUtf8Path);
    };

    Ok(path.replace(std::path::MAIN_SEPARATOR, "/"))
}

fn write_output(output: &str, json: &[u8]) -> Result<(), CliError> {
    if output == "-" {
        let mut stdout = io::stdout().lock();
        stdout.write_all(json)?;
        stdout.write_all(b"\n")?;
        return Ok(());
    }

    let mut file = File::create(PathBuf::from(output))?;
    file.write_all(json)?;
    file.write_all(b"\n")?;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct Args {
    run_id: String,
    hyf_repo_path: PathBuf,
    expected_hyf_commit: Option<String>,
    started_at: String,
    rust_toolchain: String,
    os: String,
    arch: String,
    output: String,
    reticulum_path: Option<PathBuf>,
    report_path_root: Option<PathBuf>,
    require_oracle: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct ValidateArgs {
    input: PathBuf,
    require_final_profile0: bool,
}

impl ValidateArgs {
    fn parse<I>(mut args: I) -> Result<Self, CliError>
    where
        I: Iterator<Item = String>,
    {
        let mut input = None;
        let mut require_final_profile0 = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input" => input = Some(PathBuf::from(next_value(&mut args, "--input")?)),
                "--require-final-profile0" => require_final_profile0 = true,
                "--help" | "-h" => return Err(CliError::Usage),
                _ => return Err(CliError::UnknownArgument(arg)),
            }
        }

        Ok(Self {
            input: required_path(input, "--input")?,
            require_final_profile0,
        })
    }
}

impl Args {
    fn parse<I>(mut args: I) -> Result<Self, CliError>
    where
        I: Iterator<Item = String>,
    {
        let mut run_id = None;
        let mut hyf_repo_path = None;
        let mut expected_hyf_commit = None;
        let mut started_at = None;
        let mut rust_toolchain = None;
        let mut os = std::env::consts::OS.to_owned();
        let mut arch = std::env::consts::ARCH.to_owned();
        let mut output = None;
        let mut reticulum_path = None;
        let mut report_path_root = None;
        let mut require_oracle = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--run-id" => run_id = Some(next_value(&mut args, "--run-id")?),
                "--hyf-repo-path" => {
                    hyf_repo_path = Some(PathBuf::from(next_value(&mut args, "--hyf-repo-path")?))
                }
                "--expected-hyf-commit" => {
                    expected_hyf_commit = Some(next_value(&mut args, "--expected-hyf-commit")?)
                }
                "--started-at" => started_at = Some(next_value(&mut args, "--started-at")?),
                "--rust-toolchain" => {
                    rust_toolchain = Some(next_value(&mut args, "--rust-toolchain")?)
                }
                "--os" => os = next_value(&mut args, "--os")?,
                "--arch" => arch = next_value(&mut args, "--arch")?,
                "--output" => output = Some(next_value(&mut args, "--output")?),
                "--reticulum-path" => {
                    reticulum_path = Some(PathBuf::from(next_value(&mut args, "--reticulum-path")?))
                }
                "--report-path-root" => {
                    report_path_root =
                        Some(PathBuf::from(next_value(&mut args, "--report-path-root")?))
                }
                "--require-oracle" => require_oracle = true,
                "--help" | "-h" => return Err(CliError::Usage),
                _ => return Err(CliError::UnknownArgument(arg)),
            }
        }

        Ok(Self {
            run_id: required(run_id, "--run-id")?,
            hyf_repo_path: required_path(hyf_repo_path, "--hyf-repo-path")?,
            expected_hyf_commit,
            started_at: required(started_at, "--started-at")?,
            rust_toolchain: required(rust_toolchain, "--rust-toolchain")?,
            os,
            arch,
            output: required(output, "--output")?,
            reticulum_path,
            report_path_root,
            require_oracle,
        })
    }
}

fn next_value<I>(args: &mut I, flag: &'static str) -> Result<String, CliError>
where
    I: Iterator<Item = String>,
{
    let Some(value) = args.next() else {
        return Err(CliError::MissingValue(flag));
    };

    if value.starts_with("--") {
        return Err(CliError::MissingValue(flag));
    }

    Ok(value)
}

fn required(value: Option<String>, flag: &'static str) -> Result<String, CliError> {
    let Some(value) = value else {
        return Err(CliError::MissingRequired(flag));
    };

    Ok(value)
}

fn required_path(value: Option<PathBuf>, flag: &'static str) -> Result<PathBuf, CliError> {
    let Some(value) = value else {
        return Err(CliError::MissingRequired(flag));
    };

    Ok(value)
}

#[derive(Debug)]
enum CliError {
    Usage,
    UnknownArgument(String),
    MissingValue(&'static str),
    MissingRequired(&'static str),
    GitCommandUnavailable(io::Error),
    GitCommandFailed,
    DirtyHyfWorktree,
    InvalidHyfCommit(String),
    ExpectedHyfCommitMismatch {
        expected: String,
        actual: String,
    },
    FinalReportInvalid(&'static str),
    #[cfg(feature = "python_oracle")]
    OraclePathRequiresOracle,
    ReportPathRootRequiresOracle,
    ReportPathRootMismatch,
    PathCanonicalize {
        path: PathBuf,
        error: io::Error,
    },
    NonUtf8Path,
    #[cfg(not(feature = "python_oracle"))]
    PythonOracleFeatureDisabled,
    #[cfg(feature = "python_oracle")]
    Oracle(hyf_rns_conformance::profile0::Profile0OracleError),
    Io(io::Error),
    Json(serde_json::Error),
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[cfg(feature = "python_oracle")]
impl From<hyf_rns_conformance::profile0::Profile0OracleError> for CliError {
    fn from(error: hyf_rns_conformance::profile0::Profile0OracleError) -> Self {
        Self::Oracle(error)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => formatter.write_str(USAGE),
            Self::UnknownArgument(arg) => write!(formatter, "unknown argument: {arg}\n\n{USAGE}"),
            Self::MissingValue(flag) => write!(formatter, "missing value for {flag}\n\n{USAGE}"),
            Self::MissingRequired(flag) => {
                write!(formatter, "missing required argument {flag}\n\n{USAGE}")
            }
            Self::GitCommandUnavailable(error) => write!(formatter, "git command failed: {error}"),
            Self::GitCommandFailed => formatter.write_str("git command returned a failure status"),
            Self::DirtyHyfWorktree => formatter.write_str("hyf repo has tracked worktree changes"),
            Self::InvalidHyfCommit(commit) => {
                write!(
                    formatter,
                    "derived hyf commit is not a full git hash: {commit}"
                )
            }
            Self::ExpectedHyfCommitMismatch { expected, actual } => {
                write!(
                    formatter,
                    "expected hyf commit {expected}, but git HEAD is {actual}"
                )
            }
            Self::FinalReportInvalid(reason) => write!(formatter, "final report invalid: {reason}"),
            #[cfg(feature = "python_oracle")]
            Self::OraclePathRequiresOracle => {
                write!(
                    formatter,
                    "--reticulum-path requires --require-oracle for final evidence\n\n{USAGE}"
                )
            }
            Self::ReportPathRootRequiresOracle => {
                write!(
                    formatter,
                    "--report-path-root requires an oracle report environment\n\n{USAGE}"
                )
            }
            Self::ReportPathRootMismatch => {
                write!(
                    formatter,
                    "verified oracle module path is outside --report-path-root\n\n{USAGE}"
                )
            }
            Self::PathCanonicalize { path, error } => {
                write!(
                    formatter,
                    "could not canonicalize {}: {error}",
                    path.display()
                )
            }
            Self::NonUtf8Path => formatter.write_str("report path contains non-UTF-8 data"),
            #[cfg(not(feature = "python_oracle"))]
            Self::PythonOracleFeatureDisabled => {
                write!(
                    formatter,
                    "python_oracle feature is required for oracle report generation\n\n{USAGE}"
                )
            }
            #[cfg(feature = "python_oracle")]
            Self::Oracle(error) => write!(formatter, "oracle report error: {error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
        }
    }
}

impl std::error::Error for CliError {}

const USAGE: &str = "\
usage:
  hyf-rns-conformance-report \\
  --run-id <id> \\
  --hyf-repo-path <path> \\
  --started-at <date-time> \\
  --rust-toolchain <toolchain> \\
  --output <path|-> \\
  [--expected-hyf-commit <commit>] \\
  [--reticulum-path <path> --require-oracle] \\
  [--report-path-root <path>] \\
  [--os <os>] \\
  [--arch <arch>]

  hyf-rns-conformance-report validate \\
  --input <path> \\
  [--require-final-profile0]";

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use hyf_rns_conformance::profile0::{REQUIRED_PROFILE_0_RESULT_CATEGORIES, profile_0_report};
    use hyf_rns_conformance::report::{
        ConformanceEnvironment, ConformanceResult, ConformanceRun, OracleEnvironment,
    };

    use super::{
        Args, CliError, ValidateArgs, apply_report_overrides, derive_hyf_commit,
        report_relative_path, validate_report_bytes,
    };

    static TEST_REPO_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn parser_requires_core_report_arguments() {
        let error = Args::parse(Vec::<String>::new().into_iter());

        assert!(matches!(error, Err(CliError::MissingRequired("--run-id"))));
    }

    #[test]
    fn parser_accepts_required_arguments_and_defaults_platform() -> Result<(), CliError> {
        let args = Args::parse(
            [
                "--run-id",
                "profile0-local-0001",
                "--hyf-repo-path",
                ".",
                "--expected-hyf-commit",
                "cb12ed144273bc3b41a1991c8e432cb18b429eac",
                "--started-at",
                "2026-07-08T00:00:00Z",
                "--rust-toolchain",
                "rustc 1.92.0",
                "--output",
                "-",
                "--require-oracle",
                "--reticulum-path",
                "../refs/Reticulum",
                "--report-path-root",
                "..",
            ]
            .into_iter()
            .map(str::to_owned),
        )?;

        assert_eq!(args.run_id, "profile0-local-0001");
        assert_eq!(args.hyf_repo_path, PathBuf::from("."));
        assert_eq!(
            args.expected_hyf_commit.as_deref(),
            Some("cb12ed144273bc3b41a1991c8e432cb18b429eac")
        );
        assert_eq!(args.output, "-");
        assert!(args.require_oracle);
        assert_eq!(
            args.reticulum_path,
            Some(PathBuf::from("../refs/Reticulum"))
        );
        assert_eq!(args.report_path_root, Some(PathBuf::from("..")));
        assert!(!args.os.is_empty());
        assert!(!args.arch.is_empty());
        Ok(())
    }

    #[test]
    fn validate_parser_accepts_final_profile0_mode() -> Result<(), CliError> {
        let args = ValidateArgs::parse(
            ["--input", "report.json", "--require-final-profile0"]
                .into_iter()
                .map(str::to_owned),
        )?;

        assert_eq!(args.input, PathBuf::from("report.json"));
        assert!(args.require_final_profile0);
        Ok(())
    }

    #[test]
    fn final_profile0_validator_accepts_complete_report() -> Result<(), CliError> {
        let report = valid_final_report();
        let input = serde_json::to_vec(&report)?;

        validate_report_bytes(&input, true)
    }

    #[test]
    fn final_profile0_validator_rejects_missing_category() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        let _ = report.results.pop();
        let input = serde_json::to_vec(&report)?;

        assert!(matches!(
            validate_report_bytes(&input, true),
            Err(CliError::FinalReportInvalid(
                "missing required Profile 0 result category"
            ))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_failed_result() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        replace_first_result(
            &mut report,
            ConformanceResult::failed("profile_0_packet_announce.failed", "fixture_manifest", "x"),
        );
        let input = serde_json::to_vec(&report)?;

        assert!(matches!(
            validate_report_bytes(&input, true),
            Err(CliError::FinalReportInvalid("failed result present"))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_invalid_environment_result() -> Result<(), serde_json::Error>
    {
        let mut report = valid_final_report();
        replace_first_result(
            &mut report,
            ConformanceResult::invalid_environment(
                "profile_0_packet_announce.invalid_environment",
                "fixture_manifest",
                "x",
            ),
        );
        let input = serde_json::to_vec(&report)?;

        assert!(matches!(
            validate_report_bytes(&input, true),
            Err(CliError::FinalReportInvalid(
                "invalid environment result present"
            ))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_missing_oracle() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.environment.oracle = None;
        let input = serde_json::to_vec(&report)?;

        assert!(matches!(
            validate_report_bytes(&input, true),
            Err(CliError::FinalReportInvalid("missing oracle metadata"))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_reticulum_mismatch() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.reticulum_commit = "0000000000000000000000000000000000000000".to_owned();
        let input = serde_json::to_vec(&report)?;

        assert!(matches!(
            validate_report_bytes(&input, true),
            Err(CliError::FinalReportInvalid("reticulum commit mismatch"))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_malformed_json() {
        assert!(matches!(
            validate_report_bytes(b"{", true),
            Err(CliError::Json(_))
        ));
    }

    #[test]
    fn derived_hyf_commit_rejects_expected_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestGitRepo::create()?;

        assert!(matches!(
            derive_hyf_commit(
                repo.path(),
                Some("0000000000000000000000000000000000000000")
            ),
            Err(CliError::ExpectedHyfCommitMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn derived_hyf_commit_rejects_dirty_tracked_worktree() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestGitRepo::create()?;
        std::fs::write(repo.path().join("tracked.txt"), "changed\n")?;

        assert!(matches!(
            derive_hyf_commit(repo.path(), None),
            Err(CliError::DirtyHyfWorktree)
        ));
        Ok(())
    }

    #[test]
    fn derived_hyf_commit_accepts_clean_repo_head() -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestGitRepo::create()?;
        let commit = derive_hyf_commit(repo.path(), None)?;

        assert_eq!(commit.len(), 40);
        Ok(())
    }

    #[test]
    fn report_path_root_requires_oracle_environment() {
        let mut report = profile_0_report(
            "profile0-local-0001",
            "c7895f0",
            "2026-07-08T00:00:00Z",
            ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0"),
        );
        let args = test_args_with_report_path_root(PathBuf::from(env!("CARGO_MANIFEST_DIR")));

        assert!(matches!(
            apply_report_overrides(&mut report, &args),
            Err(CliError::ReportPathRootRequiresOracle)
        ));
    }

    #[test]
    fn report_path_root_relativizes_verified_report_environment() -> Result<(), CliError> {
        let module_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bin/hyf-rns-conformance-report.rs");
        let environment = ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0")
            .with_oracle(OracleEnvironment::new(
                module_path.to_string_lossy().to_string(),
                "422dc05549bf28f45e9b9c5172336a1ba4df0ec0",
                "49.0.0",
                "3.5",
            ));
        let mut report = profile_0_report(
            "profile0-local-0001",
            "c7895f0",
            "2026-07-08T00:00:00Z",
            environment,
        );
        let args = test_args_with_report_path_root(PathBuf::from(env!("CARGO_MANIFEST_DIR")));

        apply_report_overrides(&mut report, &args)?;

        assert_eq!(
            report
                .environment
                .oracle
                .as_ref()
                .map(|oracle| oracle.reticulum_module_path.as_str()),
            Some("src/bin/hyf-rns-conformance-report.rs")
        );
        Ok(())
    }

    #[test]
    fn report_path_root_rejects_unrelated_verified_module_path() {
        let module_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let module_path = module_path.to_string_lossy();

        assert!(matches!(
            report_relative_path(&module_path, root_path.as_path()),
            Err(CliError::ReportPathRootMismatch)
        ));
    }

    fn test_args_with_report_path_root(report_path_root: PathBuf) -> Args {
        Args {
            run_id: "profile0-local-0001".to_owned(),
            hyf_repo_path: PathBuf::from("."),
            expected_hyf_commit: None,
            started_at: "2026-07-08T00:00:00Z".to_owned(),
            rust_toolchain: "rustc 1.92.0".to_owned(),
            os: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            output: "-".to_owned(),
            reticulum_path: None,
            report_path_root: Some(report_path_root),
            require_oracle: false,
        }
    }

    fn valid_final_report() -> ConformanceRun {
        let environment = ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0")
            .with_oracle(OracleEnvironment::new(
                "refs/Reticulum/RNS/__init__.py",
                "422dc05549bf28f45e9b9c5172336a1ba4df0ec0",
                "49.0.0",
                "3.5",
            ));
        let results = REQUIRED_PROFILE_0_RESULT_CATEGORIES
            .iter()
            .map(|category| {
                ConformanceResult::passed(
                    format!("profile_0_packet_announce.{category}"),
                    *category,
                )
            })
            .collect();

        ConformanceRun::profile_0(
            "profile0-local-0001",
            "0123456789abcdef0123456789abcdef01234567",
            "2026-07-08T00:00:00Z",
            environment,
            results,
        )
    }

    fn replace_first_result(report: &mut ConformanceRun, result: ConformanceResult) {
        if let Some(slot) = report.results.first_mut() {
            *slot = result;
            return;
        }

        report.results.push(result);
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
            "hyf-conformance-report-{}-{nanos}-{counter}",
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
