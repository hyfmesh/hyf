#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use hyf_rns_conformance::fixtures::{
    EXPECTED_PROFILE, EXPECTED_RETICULUM_COMMIT, PROFILE_1_KISS_RNODE, PROFILE_2_CRYPTO_IFAC,
};
#[cfg(feature = "python_oracle")]
use hyf_rns_conformance::profile0::profile_0_report_with_required_oracle;
use hyf_rns_conformance::profile0::{REQUIRED_PROFILE_0_RESULTS, profile_0_report};
use hyf_rns_conformance::profile1::{
    Profile1FinalEvidence, profile_1_final_report, profile_1_report,
    validate_profile_1_final_report,
};
use hyf_rns_conformance::profile2::{
    Profile2FinalEvidence, profile_2_final_report, profile_2_report,
    validate_profile_2_final_report,
};
use hyf_rns_conformance::report::{
    CONFORMANCE_RUN_SCHEMA, ConformanceEnvironment, ConformanceResult, ConformanceRun,
    ConformanceStatus, OracleEnvironment,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

const EXPECTED_ORACLE_RNS_VERSION: &str = "1.3.5";
const EXPECTED_ORACLE_CRYPTOGRAPHY_VERSION: &str = "49.0.0";
const EXPECTED_ORACLE_PYSERIAL_VERSION: &str = "3.5";

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
    if !args.require_final_provenance
        && (args.hyf_repo_path.is_some() || args.reticulum_path.is_some())
    {
        return Err(CliError::RepoPathRequiresFinalProvenance);
    }

    let input = std::fs::read(args.input.as_path())?;
    let require_final_profile = args
        .require_final_profile
        .or(args
            .require_final_profile0
            .then_some(ReportProfile::Profile0))
        .or(args
            .require_final_provenance
            .then_some(ReportProfile::Profile0))
        .or(args
            .expected_oracle_module_path
            .is_some()
            .then_some(ReportProfile::Profile0));
    let report = validate_report_bytes(
        &input,
        require_final_profile,
        args.expected_oracle_module_path.as_deref(),
    )?;
    if args.require_final_provenance {
        validate_final_report_provenance(&report, args)?;
    }

    Ok(())
}

fn validate_report_bytes(
    input: &[u8],
    require_final_profile: impl Into<FinalProfileRequirement>,
    expected_oracle_module_path: Option<&str>,
) -> Result<ConformanceRun, CliError> {
    let report: ConformanceRun = serde_json::from_slice(input)?;
    match require_final_profile.into() {
        FinalProfileRequirement::Some(ReportProfile::Profile0) => {
            validate_final_profile0_report(&report, expected_oracle_module_path)?
        }
        FinalProfileRequirement::Some(ReportProfile::Profile1) => {
            validate_profile_1_final_report(&report)?
        }
        FinalProfileRequirement::Some(ReportProfile::Profile2) => {
            validate_profile_2_final_report(&report)?;
            if let Some(expected_oracle_module_path) = expected_oracle_module_path {
                validate_profile2_oracle_path(&report, expected_oracle_module_path)?;
            }
        }
        FinalProfileRequirement::None => {}
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalProfileRequirement {
    None,
    Some(ReportProfile),
}

impl From<Option<ReportProfile>> for FinalProfileRequirement {
    fn from(value: Option<ReportProfile>) -> Self {
        match value {
            Some(profile) => Self::Some(profile),
            None => Self::None,
        }
    }
}

impl From<bool> for FinalProfileRequirement {
    fn from(value: bool) -> Self {
        if value {
            Self::Some(ReportProfile::Profile0)
        } else {
            Self::None
        }
    }
}

fn validate_final_profile0_report(
    report: &ConformanceRun,
    expected_oracle_module_path: Option<&str>,
) -> Result<(), CliError> {
    if report.schema != CONFORMANCE_RUN_SCHEMA {
        return Err(CliError::FinalReportInvalid("schema mismatch"));
    }
    if report.profile != EXPECTED_PROFILE {
        return Err(CliError::FinalReportInvalid("profile mismatch"));
    }
    if !required_string_is_populated(&report.run_id) {
        return Err(CliError::FinalReportInvalid("empty run id"));
    }
    if !is_full_lower_hex_commit(&report.hyf_commit) {
        return Err(CliError::FinalReportInvalid("invalid hyf commit"));
    }
    if report.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
        return Err(CliError::FinalReportInvalid("reticulum commit mismatch"));
    }
    if !is_final_started_at(&report.started_at) {
        return Err(CliError::FinalReportInvalid("invalid started_at"));
    }
    if !final_environment_required_strings_are_populated(&report.environment) {
        return Err(CliError::FinalReportInvalid("empty environment field"));
    }
    if !final_results_required_strings_are_populated(&report.results) {
        return Err(CliError::FinalReportInvalid("empty result field"));
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
    validate_final_profile0_results(&report.results)?;

    let Some(oracle) = report.environment.oracle.as_ref() else {
        return Err(CliError::FinalReportInvalid("missing oracle metadata"));
    };
    if !final_oracle_required_strings_are_populated(oracle) {
        return Err(CliError::FinalReportInvalid("empty oracle field"));
    }
    validate_final_oracle_metadata(oracle, expected_oracle_module_path)?;

    Ok(())
}

fn validate_final_report_provenance(
    report: &ConformanceRun,
    args: &ValidateArgs,
) -> Result<(), CliError> {
    let Some(hyf_repo_path) = args.hyf_repo_path.as_ref() else {
        return Err(CliError::MissingRequired("--hyf-repo-path"));
    };
    validate_git_source_state(
        hyf_repo_path.as_path(),
        Some(&report.hyf_commit),
        GitSource::Hyf,
    )?;

    let Some(reticulum_path) = args.reticulum_path.as_ref() else {
        return Err(CliError::MissingRequired("--reticulum-path"));
    };
    validate_git_source_state(
        reticulum_path.as_path(),
        Some(&report.reticulum_commit),
        GitSource::Reticulum,
    )?;

    let Some(expected_oracle_module_path) = args.expected_oracle_module_path.as_deref() else {
        return Err(CliError::MissingRequired("--expected-oracle-module-path"));
    };
    let Some(oracle) = report.environment.oracle.as_ref() else {
        return Err(CliError::FinalReportInvalid("missing oracle metadata"));
    };
    if oracle.reticulum_module_path != expected_oracle_module_path {
        return Err(CliError::ExpectedOracleModulePathMismatch {
            expected: expected_oracle_module_path.to_owned(),
            actual: oracle.reticulum_module_path.clone(),
        });
    }

    Ok(())
}

fn validate_profile2_oracle_path(
    report: &ConformanceRun,
    expected_oracle_module_path: &str,
) -> Result<(), CliError> {
    let Some(oracle) = report.environment.oracle.as_ref() else {
        return Err(CliError::FinalReportInvalid("missing oracle metadata"));
    };
    if oracle.reticulum_module_path != expected_oracle_module_path {
        return Err(CliError::FinalReportInvalid(
            "oracle Reticulum module path mismatch",
        ));
    }
    Ok(())
}

fn build_report(
    args: &Args,
    environment: ConformanceEnvironment,
    hyf_commit: String,
) -> Result<ConformanceRun, CliError> {
    match args.profile {
        ReportProfile::Profile0 => build_profile0_report(args, environment, hyf_commit),
        ReportProfile::Profile1 => {
            if args.require_oracle || args.reticulum_path.is_some() {
                return Err(CliError::OracleNotSupportedForProfile(args.profile));
            }
            let Some(capture_dir) = args.capture_dir.as_ref() else {
                return Ok(profile_1_report(
                    args.run_id.clone(),
                    hyf_commit,
                    args.started_at.clone(),
                    environment,
                ));
            };
            let evidence = Profile1FinalEvidence::from_capture_dir(capture_dir.as_path())?;
            Ok(profile_1_final_report(
                args.run_id.clone(),
                hyf_commit,
                args.started_at.clone(),
                environment,
                &evidence,
            )?)
        }
        ReportProfile::Profile2 => {
            if args.require_oracle || args.reticulum_path.is_some() {
                return Err(CliError::OracleNotSupportedForProfile(args.profile));
            }
            let Some(capture_dir) = args.capture_dir.as_ref() else {
                return Ok(profile_2_report(
                    args.run_id.clone(),
                    hyf_commit,
                    args.started_at.clone(),
                    environment,
                ));
            };
            let evidence = Profile2FinalEvidence::from_capture_dir(capture_dir.as_path())?;
            Ok(profile_2_final_report(
                args.run_id.clone(),
                hyf_commit,
                args.started_at.clone(),
                environment,
                &evidence,
            )?)
        }
    }
}

fn build_profile0_report(
    args: &Args,
    environment: ConformanceEnvironment,
    hyf_commit: String,
) -> Result<ConformanceRun, CliError> {
    if args.capture_dir.is_some() {
        return Err(CliError::CaptureDirUnsupportedForProfile(args.profile));
    }
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
    validate_git_source_state(hyf_repo_path, expected_hyf_commit, GitSource::Hyf)
}

fn validate_git_source_state(
    repo_path: &Path,
    expected_commit: Option<&str>,
    source: GitSource,
) -> Result<String, CliError> {
    let commit = git_stdout(repo_path, &["rev-parse", "HEAD"])?;
    if !is_full_lower_hex_commit(&commit) {
        return Err(source.invalid_commit_error(commit));
    }

    let status = git_stdout(
        repo_path,
        &["status", "--porcelain", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(source.dirty_worktree_error());
    }

    if let Some(expected_commit) = expected_commit
        && expected_commit != commit
    {
        return Err(source.expected_commit_mismatch_error(expected_commit, commit));
    }

    Ok(commit)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitSource {
    Hyf,
    Reticulum,
}

impl GitSource {
    fn dirty_worktree_error(self) -> CliError {
        match self {
            Self::Hyf => CliError::DirtyHyfWorktree,
            Self::Reticulum => CliError::DirtyReticulumWorktree,
        }
    }

    fn invalid_commit_error(self, commit: String) -> CliError {
        match self {
            Self::Hyf => CliError::InvalidHyfCommit(commit),
            Self::Reticulum => CliError::InvalidReticulumCommit(commit),
        }
    }

    fn expected_commit_mismatch_error(self, expected: &str, actual: String) -> CliError {
        match self {
            Self::Hyf => CliError::ExpectedHyfCommitMismatch {
                expected: expected.to_owned(),
                actual,
            },
            Self::Reticulum => CliError::ExpectedReticulumCommitMismatch {
                expected: expected.to_owned(),
                actual,
            },
        }
    }
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

fn is_final_started_at(timestamp: &str) -> bool {
    let bytes = timestamp.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }

    let digit_positions = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if digit_positions
        .iter()
        .any(|position| !bytes[*position].is_ascii_digit())
    {
        return false;
    }

    let Some(year) = parse_four_digits(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = parse_two_digits(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = parse_two_digits(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = parse_two_digits(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = parse_two_digits(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = parse_two_digits(&bytes[17..19]) else {
        return false;
    };

    let Some(max_day) = days_in_month(year, month) else {
        return false;
    };

    (1..=max_day).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

fn parse_four_digits(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }

    Some(
        u16::from(bytes[0] - b'0') * 1000
            + u16::from(bytes[1] - b'0') * 100
            + u16::from(bytes[2] - b'0') * 10
            + u16::from(bytes[3] - b'0'),
    )
}

fn parse_two_digits(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }

    Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

fn days_in_month(year: u16, month: u8) -> Option<u8> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

const fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn required_string_is_populated(value: &str) -> bool {
    !value.is_empty()
}

fn optional_string_is_populated(value: Option<&str>) -> bool {
    match value {
        Some(value) => required_string_is_populated(value),
        None => true,
    }
}

fn final_environment_required_strings_are_populated(environment: &ConformanceEnvironment) -> bool {
    required_string_is_populated(&environment.os)
        && required_string_is_populated(&environment.arch)
        && required_string_is_populated(&environment.rust_toolchain)
}

fn final_results_required_strings_are_populated(results: &[ConformanceResult]) -> bool {
    results.iter().all(|result| {
        required_string_is_populated(&result.id)
            && required_string_is_populated(&result.category)
            && optional_string_is_populated(result.detail.as_deref())
    })
}

fn final_oracle_required_strings_are_populated(oracle: &OracleEnvironment) -> bool {
    required_string_is_populated(&oracle.reticulum_module_path)
        && required_string_is_populated(&oracle.reticulum_commit)
        && optional_string_is_populated(oracle.rns_version.as_deref())
        && required_string_is_populated(&oracle.cryptography_version)
        && required_string_is_populated(&oracle.pyserial_version)
}

fn validate_final_profile0_results(results: &[ConformanceResult]) -> Result<(), CliError> {
    if results.len() != REQUIRED_PROFILE_0_RESULTS.len() {
        return Err(CliError::FinalReportInvalid(
            "Profile 0 result count mismatch",
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut seen_categories = BTreeSet::new();
    for result in results {
        if !seen_ids.insert(result.id.as_str()) {
            return Err(CliError::FinalReportInvalid(
                "duplicate Profile 0 result id",
            ));
        }
        if !seen_categories.insert(result.category.as_str()) {
            return Err(CliError::FinalReportInvalid(
                "duplicate Profile 0 result category",
            ));
        }
    }

    for result in results {
        let Some((_, expected_category)) = REQUIRED_PROFILE_0_RESULTS
            .iter()
            .find(|(expected_id, _)| *expected_id == result.id.as_str())
        else {
            return Err(CliError::FinalReportInvalid(
                "unexpected Profile 0 result id",
            ));
        };

        if result.category.as_str() != *expected_category {
            return Err(CliError::FinalReportInvalid(
                "Profile 0 result category mismatch",
            ));
        }
    }

    for &(expected_id, _) in REQUIRED_PROFILE_0_RESULTS {
        if !seen_ids.contains(expected_id) {
            return Err(CliError::FinalReportInvalid(
                "missing required Profile 0 result id",
            ));
        }
    }

    Ok(())
}

fn validate_final_oracle_metadata(
    oracle: &OracleEnvironment,
    expected_oracle_module_path: Option<&str>,
) -> Result<(), CliError> {
    if let Some(expected_oracle_module_path) = expected_oracle_module_path
        && oracle.reticulum_module_path != expected_oracle_module_path
    {
        return Err(CliError::FinalReportInvalid(
            "oracle Reticulum module path mismatch",
        ));
    }
    if oracle.reticulum_commit != EXPECTED_RETICULUM_COMMIT {
        return Err(CliError::FinalReportInvalid(
            "oracle reticulum commit mismatch",
        ));
    }
    if oracle.rns_version.as_deref() != Some(EXPECTED_ORACLE_RNS_VERSION) {
        return Err(CliError::FinalReportInvalid("oracle RNS version mismatch"));
    }
    if oracle.cryptography_version != EXPECTED_ORACLE_CRYPTOGRAPHY_VERSION {
        return Err(CliError::FinalReportInvalid(
            "oracle cryptography version mismatch",
        ));
    }
    if oracle.pyserial_version != EXPECTED_ORACLE_PYSERIAL_VERSION {
        return Err(CliError::FinalReportInvalid(
            "oracle pyserial version mismatch",
        ));
    }

    Ok(())
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
    if (args.require_oracle
        || args.profile == ReportProfile::Profile2 && args.capture_dir.is_some())
        && args.report_path_root.is_none()
    {
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
    profile: ReportProfile,
    run_id: String,
    hyf_repo_path: PathBuf,
    expected_hyf_commit: Option<String>,
    started_at: String,
    rust_toolchain: String,
    os: String,
    arch: String,
    output: String,
    reticulum_path: Option<PathBuf>,
    capture_dir: Option<PathBuf>,
    report_path_root: Option<PathBuf>,
    require_oracle: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct ValidateArgs {
    input: PathBuf,
    require_final_profile0: bool,
    require_final_profile: Option<ReportProfile>,
    require_final_provenance: bool,
    hyf_repo_path: Option<PathBuf>,
    reticulum_path: Option<PathBuf>,
    expected_oracle_module_path: Option<String>,
}

impl ValidateArgs {
    fn parse<I>(mut args: I) -> Result<Self, CliError>
    where
        I: Iterator<Item = String>,
    {
        let mut input = None;
        let mut require_final_profile0 = false;
        let mut require_final_profile = None;
        let mut require_final_provenance = false;
        let mut hyf_repo_path = None;
        let mut reticulum_path = None;
        let mut expected_oracle_module_path = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input" => input = Some(PathBuf::from(next_value(&mut args, "--input")?)),
                "--require-final-profile0" => require_final_profile0 = true,
                "--require-final-profile" => {
                    require_final_profile = Some(ReportProfile::parse(&next_value(
                        &mut args,
                        "--require-final-profile",
                    )?)?)
                }
                "--require-final-provenance" => require_final_provenance = true,
                "--hyf-repo-path" => {
                    hyf_repo_path = Some(PathBuf::from(next_value(&mut args, "--hyf-repo-path")?))
                }
                "--reticulum-path" => {
                    reticulum_path = Some(PathBuf::from(next_value(&mut args, "--reticulum-path")?))
                }
                "--expected-oracle-module-path" => {
                    expected_oracle_module_path =
                        Some(next_value(&mut args, "--expected-oracle-module-path")?)
                }
                "--help" | "-h" => return Err(CliError::Usage),
                _ => return Err(CliError::UnknownArgument(arg)),
            }
        }

        Ok(Self {
            input: required_path(input, "--input")?,
            require_final_profile0,
            require_final_profile,
            require_final_provenance,
            hyf_repo_path,
            reticulum_path,
            expected_oracle_module_path,
        })
    }
}

impl Args {
    fn parse<I>(mut args: I) -> Result<Self, CliError>
    where
        I: Iterator<Item = String>,
    {
        let mut run_id = None;
        let mut profile = ReportProfile::Profile0;
        let mut hyf_repo_path = None;
        let mut expected_hyf_commit = None;
        let mut started_at = None;
        let mut rust_toolchain = None;
        let mut os = std::env::consts::OS.to_owned();
        let mut arch = std::env::consts::ARCH.to_owned();
        let mut output = None;
        let mut reticulum_path = None;
        let mut capture_dir = None;
        let mut report_path_root = None;
        let mut require_oracle = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--profile" => {
                    profile = ReportProfile::parse(&next_value(&mut args, "--profile")?)?
                }
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
                "--capture-dir" => {
                    capture_dir = Some(PathBuf::from(next_value(&mut args, "--capture-dir")?))
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
            profile,
            run_id: required(run_id, "--run-id")?,
            hyf_repo_path: required_path(hyf_repo_path, "--hyf-repo-path")?,
            expected_hyf_commit,
            started_at: required(started_at, "--started-at")?,
            rust_toolchain: required(rust_toolchain, "--rust-toolchain")?,
            os,
            arch,
            output: required(output, "--output")?,
            reticulum_path,
            capture_dir,
            report_path_root,
            require_oracle,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportProfile {
    Profile0,
    Profile1,
    Profile2,
}

impl ReportProfile {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            EXPECTED_PROFILE => Ok(Self::Profile0),
            PROFILE_1_KISS_RNODE => Ok(Self::Profile1),
            PROFILE_2_CRYPTO_IFAC => Ok(Self::Profile2),
            _ => Err(CliError::UnknownProfile(value.to_owned())),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Profile0 => EXPECTED_PROFILE,
            Self::Profile1 => PROFILE_1_KISS_RNODE,
            Self::Profile2 => PROFILE_2_CRYPTO_IFAC,
        }
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
    UnknownProfile(String),
    MissingValue(&'static str),
    MissingRequired(&'static str),
    GitCommandUnavailable(io::Error),
    GitCommandFailed,
    DirtyHyfWorktree,
    DirtyReticulumWorktree,
    InvalidHyfCommit(String),
    InvalidReticulumCommit(String),
    ExpectedHyfCommitMismatch {
        expected: String,
        actual: String,
    },
    ExpectedReticulumCommitMismatch {
        expected: String,
        actual: String,
    },
    ExpectedOracleModulePathMismatch {
        expected: String,
        actual: String,
    },
    RepoPathRequiresFinalProvenance,
    CaptureDirUnsupportedForProfile(ReportProfile),
    OracleNotSupportedForProfile(ReportProfile),
    FinalReportInvalid(&'static str),
    FinalReport(hyf_rns_conformance::final_report::FinalReportError),
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

impl From<hyf_rns_conformance::final_report::FinalReportError> for CliError {
    fn from(error: hyf_rns_conformance::final_report::FinalReportError) -> Self {
        Self::FinalReport(error)
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
            Self::UnknownProfile(profile) => {
                write!(
                    formatter,
                    "unknown conformance profile: {profile}\n\n{USAGE}"
                )
            }
            Self::MissingValue(flag) => write!(formatter, "missing value for {flag}\n\n{USAGE}"),
            Self::MissingRequired(flag) => {
                write!(formatter, "missing required argument {flag}\n\n{USAGE}")
            }
            Self::GitCommandUnavailable(error) => write!(formatter, "git command failed: {error}"),
            Self::GitCommandFailed => formatter.write_str("git command returned a failure status"),
            Self::DirtyHyfWorktree => {
                formatter.write_str("hyf repo has tracked or untracked worktree changes")
            }
            Self::DirtyReticulumWorktree => {
                formatter.write_str("Reticulum repo has tracked or untracked worktree changes")
            }
            Self::InvalidHyfCommit(commit) => {
                write!(
                    formatter,
                    "derived hyf commit is not a full git hash: {commit}"
                )
            }
            Self::InvalidReticulumCommit(commit) => {
                write!(
                    formatter,
                    "derived Reticulum commit is not a full git hash: {commit}"
                )
            }
            Self::ExpectedHyfCommitMismatch { expected, actual } => {
                write!(
                    formatter,
                    "expected hyf commit {expected}, but git HEAD is {actual}"
                )
            }
            Self::ExpectedReticulumCommitMismatch { expected, actual } => {
                write!(
                    formatter,
                    "expected Reticulum commit {expected}, but git HEAD is {actual}"
                )
            }
            Self::ExpectedOracleModulePathMismatch { expected, actual } => {
                write!(
                    formatter,
                    "expected oracle module path {expected}, but report records {actual}"
                )
            }
            Self::RepoPathRequiresFinalProvenance => {
                write!(
                    formatter,
                    "--hyf-repo-path and --reticulum-path are validate-only provenance inputs and require --require-final-provenance\n\n{USAGE}"
                )
            }
            Self::CaptureDirUnsupportedForProfile(profile) => {
                write!(
                    formatter,
                    "--capture-dir is not supported for {}\n\n{USAGE}",
                    profile.as_str()
                )
            }
            Self::OracleNotSupportedForProfile(profile) => {
                write!(
                    formatter,
                    "--require-oracle and --reticulum-path are only supported for Profile 0 generation, not {}\n\n{USAGE}",
                    profile.as_str()
                )
            }
            Self::FinalReportInvalid(reason) => write!(formatter, "final report invalid: {reason}"),
            Self::FinalReport(error) => write!(formatter, "final report error: {error}"),
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
  [--profile <profile_0_packet_announce|profile_1_kiss_rnode|profile_2_crypto_ifac>] \\
  --run-id <id> \\
  --hyf-repo-path <path> \\
  --started-at <date-time> \\
  --rust-toolchain <toolchain> \\
  --output <path|-> \\
  [--expected-hyf-commit <commit>] \\
  [--capture-dir <path>] \\
  [--reticulum-path <path> --require-oracle] \\
  [--report-path-root <path>] \\
  [--os <os>] \\
  [--arch <arch>]

  hyf-rns-conformance-report validate \\
  --input <path> \\
  [--require-final-profile0] \\
  [--require-final-profile <profile>] \\
  [--expected-oracle-module-path <path>] \\
  [--require-final-provenance \\
   --hyf-repo-path <path> \\
   --reticulum-path <path> \\
   --expected-oracle-module-path <path>]";

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use hyf_rns_conformance::profile0::{REQUIRED_PROFILE_0_RESULTS, profile_0_report};
    use hyf_rns_conformance::report::{
        ConformanceEnvironment, ConformanceResult, ConformanceRun, OracleEnvironment,
    };

    use super::{
        Args, CliError, ReportProfile, ValidateArgs, apply_report_overrides, derive_hyf_commit,
        git_stdout, report_relative_path, run_validate, validate_final_report_provenance,
        validate_report_bytes,
    };
    use serde_json::json;

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
        assert_eq!(args.profile, ReportProfile::Profile0);
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
        assert_eq!(args.capture_dir, None);
        assert_eq!(args.report_path_root, Some(PathBuf::from("..")));
        assert!(!args.os.is_empty());
        assert!(!args.arch.is_empty());
        Ok(())
    }

    #[test]
    fn parser_accepts_profile_and_capture_dir() -> Result<(), CliError> {
        let args = Args::parse(
            [
                "--profile",
                "profile_2_crypto_ifac",
                "--run-id",
                "profile2-final-0001",
                "--hyf-repo-path",
                ".",
                "--started-at",
                "2026-07-09T00:00:00Z",
                "--rust-toolchain",
                "rustc 1.92.0",
                "--output",
                "report.json",
                "--capture-dir",
                "captures/profile2",
                "--report-path-root",
                "..",
            ]
            .into_iter()
            .map(str::to_owned),
        )?;

        assert_eq!(args.profile, ReportProfile::Profile2);
        assert_eq!(args.capture_dir, Some(PathBuf::from("captures/profile2")));
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
        assert_eq!(args.require_final_profile, None);
        assert!(!args.require_final_provenance);
        assert!(args.hyf_repo_path.is_none());
        assert!(args.reticulum_path.is_none());
        assert!(args.expected_oracle_module_path.is_none());
        Ok(())
    }

    #[test]
    fn validate_parser_accepts_named_final_profile() -> Result<(), CliError> {
        let args = ValidateArgs::parse(
            [
                "--input",
                "report.json",
                "--require-final-profile",
                "profile_2_crypto_ifac",
                "--expected-oracle-module-path",
                "refs/Reticulum/RNS/__init__.py",
            ]
            .into_iter()
            .map(str::to_owned),
        )?;

        assert_eq!(args.require_final_profile, Some(ReportProfile::Profile2));
        assert_eq!(
            args.expected_oracle_module_path.as_deref(),
            Some("refs/Reticulum/RNS/__init__.py")
        );
        Ok(())
    }

    #[test]
    fn validate_parser_accepts_final_provenance_mode() -> Result<(), CliError> {
        let args = ValidateArgs::parse(
            [
                "--input",
                "report.json",
                "--require-final-provenance",
                "--hyf-repo-path",
                ".",
                "--reticulum-path",
                "../refs/Reticulum",
                "--expected-oracle-module-path",
                "refs/Reticulum/RNS/__init__.py",
            ]
            .into_iter()
            .map(str::to_owned),
        )?;

        assert_eq!(args.input, PathBuf::from("report.json"));
        assert!(!args.require_final_profile0);
        assert_eq!(args.require_final_profile, None);
        assert!(args.require_final_provenance);
        assert_eq!(args.hyf_repo_path, Some(PathBuf::from(".")));
        assert_eq!(
            args.reticulum_path,
            Some(PathBuf::from("../refs/Reticulum"))
        );
        assert_eq!(
            args.expected_oracle_module_path.as_deref(),
            Some("refs/Reticulum/RNS/__init__.py")
        );
        Ok(())
    }

    #[test]
    fn final_profile0_validator_accepts_complete_report() -> Result<(), CliError> {
        let report = valid_final_report();
        let input = serde_json::to_vec(&report)?;

        validate_report_bytes(&input, true, None).map(|_| ())
    }

    #[test]
    fn final_profile0_validator_accepts_alternate_oracle_path_without_policy()
    -> Result<(), CliError> {
        let mut report = valid_final_report();
        if let Some(oracle) = report.environment.oracle.as_mut() {
            oracle.reticulum_module_path = "RNS/__init__.py".to_owned();
        }
        let input = serde_json::to_vec(&report)?;

        validate_report_bytes(&input, true, None).map(|_| ())
    }

    #[test]
    fn final_profile0_validator_applies_explicit_oracle_path_policy()
    -> Result<(), serde_json::Error> {
        let report = valid_final_report();
        let input = serde_json::to_vec(&report)?;

        assert!(
            validate_report_bytes(&input, true, Some("refs/Reticulum/RNS/__init__.py")).is_ok()
        );
        assert!(matches!(
            validate_report_bytes(&input, true, Some("RNS/__init__.py")),
            Err(CliError::FinalReportInvalid(
                "oracle Reticulum module path mismatch"
            ))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_unknown_fields() -> Result<(), serde_json::Error> {
        let mut report = serde_json::to_value(valid_final_report())?;
        report["unexpected"] = json!(true);
        let input = serde_json::to_vec(&report)?;

        assert!(matches!(
            validate_report_bytes(&input, true, None),
            Err(CliError::Json(_))
        ));

        let mut report = serde_json::to_value(valid_final_report())?;
        report["results"][0]["unexpected"] = json!(true);
        let input = serde_json::to_vec(&report)?;

        assert!(matches!(
            validate_report_bytes(&input, true, None),
            Err(CliError::Json(_))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_short_hyf_commit() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.hyf_commit = "0123456".to_owned();

        assert_final_report_invalid(&report, "invalid hyf commit")
    }

    #[test]
    fn final_profile0_validator_rejects_uppercase_hyf_commit() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.hyf_commit = "0123456789abcdef0123456789abcdef0123456A".to_owned();

        assert_final_report_invalid(&report, "invalid hyf commit")
    }

    #[test]
    fn final_profile0_validator_rejects_malformed_started_at() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.started_at = "2026-07-08 00:00:00".to_owned();

        assert_final_report_invalid(&report, "invalid started_at")
    }

    #[test]
    fn final_profile0_validator_rejects_impossible_started_at_dates()
    -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.started_at = "2026-02-31T00:00:00Z".to_owned();
        assert_final_report_invalid(&report, "invalid started_at")?;

        let mut report = valid_final_report();
        report.started_at = "2026-02-29T00:00:00Z".to_owned();
        assert_final_report_invalid(&report, "invalid started_at")?;

        let mut report = valid_final_report();
        report.started_at = "2026-04-31T00:00:00Z".to_owned();
        assert_final_report_invalid(&report, "invalid started_at")
    }

    #[test]
    fn final_profile0_validator_accepts_leap_day_started_at() -> Result<(), CliError> {
        let mut report = valid_final_report();
        report.started_at = "2024-02-29T00:00:00Z".to_owned();
        let input = serde_json::to_vec(&report)?;

        validate_report_bytes(&input, true, None).map(|_| ())
    }

    #[test]
    fn final_profile0_validator_rejects_non_utc_started_at() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.started_at = "2026-07-08T00:00:00+00:00".to_owned();

        assert_final_report_invalid(&report, "invalid started_at")
    }

    #[test]
    fn final_profile0_validator_rejects_empty_required_strings() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.run_id.clear();
        assert_final_report_invalid(&report, "empty run id")?;

        let mut report = valid_final_report();
        report.environment.os.clear();
        assert_final_report_invalid(&report, "empty environment field")?;

        let mut report = valid_final_report();
        if let Some(result) = report.results.first_mut() {
            result.id.clear();
        }
        assert_final_report_invalid(&report, "empty result field")?;

        let mut report = valid_final_report();
        if let Some(oracle) = report.environment.oracle.as_mut() {
            oracle.reticulum_module_path.clear();
        }
        assert_final_report_invalid(&report, "empty oracle field")
    }

    #[test]
    fn final_profile0_validator_rejects_missing_result() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        let _ = report.results.pop();

        assert_final_report_invalid(&report, "Profile 0 result count mismatch")
    }

    #[test]
    fn final_profile0_validator_rejects_extra_result() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.results.push(ConformanceResult::passed(
            "profile_0_packet_announce.extra",
            "extra",
        ));

        assert_final_report_invalid(&report, "Profile 0 result count mismatch")
    }

    #[test]
    fn final_profile0_validator_rejects_duplicate_result_id() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        let duplicate_id = report.results[0].id.clone();
        report.results[1].id = duplicate_id;

        assert_final_report_invalid(&report, "duplicate Profile 0 result id")
    }

    #[test]
    fn final_profile0_validator_rejects_duplicate_result_category() -> Result<(), serde_json::Error>
    {
        let mut report = valid_final_report();
        let duplicate_category = report.results[0].category.clone();
        report.results[1].category = duplicate_category;

        assert_final_report_invalid(&report, "duplicate Profile 0 result category")
    }

    #[test]
    fn final_profile0_validator_rejects_unexpected_result_id() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        report.results[0].id = "profile_0_packet_announce.unexpected".to_owned();

        assert_final_report_invalid(&report, "unexpected Profile 0 result id")
    }

    #[test]
    fn final_profile0_validator_rejects_wrong_result_pairing() -> Result<(), serde_json::Error> {
        let mut report = valid_final_report();
        let first_category = report.results[0].category.clone();
        report.results[0].category = report.results[1].category.clone();
        report.results[1].category = first_category;

        assert_final_report_invalid(&report, "Profile 0 result category mismatch")
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
            validate_report_bytes(&input, true, None),
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
            validate_report_bytes(&input, true, None),
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
            validate_report_bytes(&input, true, None),
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
            validate_report_bytes(&input, true, None),
            Err(CliError::FinalReportInvalid("reticulum commit mismatch"))
        ));
        Ok(())
    }

    #[test]
    fn final_profile0_validator_rejects_oracle_metadata_mismatch() -> Result<(), serde_json::Error>
    {
        let mut report = valid_final_report();
        if let Some(oracle) = report.environment.oracle.as_mut() {
            oracle.reticulum_commit = "0000000000000000000000000000000000000000".to_owned();
        }
        assert_final_report_invalid(&report, "oracle reticulum commit mismatch")?;

        let mut report = valid_final_report();
        if let Some(oracle) = report.environment.oracle.as_mut() {
            oracle.rns_version = Some("1.3.4".to_owned());
        }
        assert_final_report_invalid(&report, "oracle RNS version mismatch")?;

        let mut report = valid_final_report();
        if let Some(oracle) = report.environment.oracle.as_mut() {
            oracle.cryptography_version = "48.0.0".to_owned();
        }
        assert_final_report_invalid(&report, "oracle cryptography version mismatch")?;

        let mut report = valid_final_report();
        if let Some(oracle) = report.environment.oracle.as_mut() {
            oracle.pyserial_version = "3.4".to_owned();
        }
        assert_final_report_invalid(&report, "oracle pyserial version mismatch")
    }

    #[test]
    fn final_profile0_validator_rejects_malformed_json() {
        assert!(matches!(
            validate_report_bytes(b"{", true, None),
            Err(CliError::Json(_))
        ));
    }

    #[test]
    fn validate_rejects_repo_paths_without_final_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let report = valid_final_report();
        let input = unique_test_path()?;
        std::fs::write(&input, serde_json::to_vec(&report)?)?;
        let args = ValidateArgs {
            input,
            require_final_profile0: true,
            require_final_profile: None,
            require_final_provenance: false,
            hyf_repo_path: Some(PathBuf::from(".")),
            reticulum_path: None,
            expected_oracle_module_path: None,
        };

        assert!(matches!(
            run_validate(&args),
            Err(CliError::RepoPathRequiresFinalProvenance)
        ));
        Ok(())
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
    fn derived_hyf_commit_rejects_untracked_worktree_file() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestGitRepo::create()?;
        std::fs::write(repo.path().join("untracked.txt"), "local only\n")?;

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
    fn final_provenance_accepts_clean_matching_repos() -> Result<(), Box<dyn std::error::Error>> {
        let hyf_repo = TestGitRepo::create()?;
        let reticulum_repo = TestGitRepo::create()?;
        let report = valid_final_report_for_repos(&hyf_repo, &reticulum_repo)?;
        let args = provenance_args(&hyf_repo, &reticulum_repo);

        validate_final_report_provenance(&report, &args)?;
        Ok(())
    }

    #[test]
    fn final_provenance_rejects_forged_hyf_commit() -> Result<(), Box<dyn std::error::Error>> {
        let hyf_repo = TestGitRepo::create()?;
        let reticulum_repo = TestGitRepo::create()?;
        let mut report = valid_final_report_for_repos(&hyf_repo, &reticulum_repo)?;
        report.hyf_commit = "0000000000000000000000000000000000000000".to_owned();
        let args = provenance_args(&hyf_repo, &reticulum_repo);

        assert!(matches!(
            validate_final_report_provenance(&report, &args),
            Err(CliError::ExpectedHyfCommitMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn final_provenance_rejects_reticulum_untracked_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let hyf_repo = TestGitRepo::create()?;
        let reticulum_repo = TestGitRepo::create()?;
        let report = valid_final_report_for_repos(&hyf_repo, &reticulum_repo)?;
        std::fs::write(
            reticulum_repo.path().join("sitecustomize.py"),
            "raise SystemExit\n",
        )?;
        let args = provenance_args(&hyf_repo, &reticulum_repo);

        assert!(matches!(
            validate_final_report_provenance(&report, &args),
            Err(CliError::DirtyReticulumWorktree)
        ));
        Ok(())
    }

    #[test]
    fn final_provenance_requires_explicit_oracle_path_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let hyf_repo = TestGitRepo::create()?;
        let reticulum_repo = TestGitRepo::create()?;
        let report = valid_final_report_for_repos(&hyf_repo, &reticulum_repo)?;
        let mut args = provenance_args(&hyf_repo, &reticulum_repo);
        args.expected_oracle_module_path = None;

        assert!(matches!(
            validate_final_report_provenance(&report, &args),
            Err(CliError::MissingRequired("--expected-oracle-module-path"))
        ));
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
            profile: ReportProfile::Profile0,
            run_id: "profile0-local-0001".to_owned(),
            hyf_repo_path: PathBuf::from("."),
            expected_hyf_commit: None,
            started_at: "2026-07-08T00:00:00Z".to_owned(),
            rust_toolchain: "rustc 1.92.0".to_owned(),
            os: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            output: "-".to_owned(),
            reticulum_path: None,
            capture_dir: None,
            report_path_root: Some(report_path_root),
            require_oracle: false,
        }
    }

    fn valid_final_report() -> ConformanceRun {
        let environment = ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0")
            .with_oracle(
                OracleEnvironment::new(
                    "refs/Reticulum/RNS/__init__.py",
                    "422dc05549bf28f45e9b9c5172336a1ba4df0ec0",
                    "49.0.0",
                    "3.5",
                )
                .with_rns_version("1.3.5"),
            );
        let results = REQUIRED_PROFILE_0_RESULTS
            .iter()
            .map(|(id, category)| ConformanceResult::passed(*id, *category))
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

    fn valid_final_report_for_repos(
        hyf_repo: &TestGitRepo,
        reticulum_repo: &TestGitRepo,
    ) -> Result<ConformanceRun, CliError> {
        let mut report = valid_final_report();
        report.hyf_commit = hyf_repo.commit()?;
        report.reticulum_commit = reticulum_repo.commit()?;
        if let Some(oracle) = report.environment.oracle.as_mut() {
            oracle.reticulum_commit = report.reticulum_commit.clone();
            oracle.reticulum_module_path = "RNS/__init__.py".to_owned();
        }
        Ok(report)
    }

    fn provenance_args(hyf_repo: &TestGitRepo, reticulum_repo: &TestGitRepo) -> ValidateArgs {
        ValidateArgs {
            input: PathBuf::from("report.json"),
            require_final_profile0: true,
            require_final_profile: None,
            require_final_provenance: true,
            hyf_repo_path: Some(hyf_repo.path().to_path_buf()),
            reticulum_path: Some(reticulum_repo.path().to_path_buf()),
            expected_oracle_module_path: Some("RNS/__init__.py".to_owned()),
        }
    }

    fn assert_final_report_invalid(
        report: &ConformanceRun,
        reason: &'static str,
    ) -> Result<(), serde_json::Error> {
        let input = serde_json::to_vec(report)?;

        assert!(matches!(
            validate_report_bytes(&input, true, None),
            Err(CliError::FinalReportInvalid(actual)) if actual == reason
        ));
        Ok(())
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

        fn commit(&self) -> Result<String, CliError> {
            git_stdout(self.path(), &["rev-parse", "HEAD"])
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
