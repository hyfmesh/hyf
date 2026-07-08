#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use hyf_rns_conformance::profile0::profile_0_report;
#[cfg(feature = "python_oracle")]
use hyf_rns_conformance::profile0::profile_0_report_with_required_oracle;
use hyf_rns_conformance::report::{ConformanceEnvironment, ConformanceRun};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), CliError> {
    let args = Args::parse(std::env::args().skip(1))?;
    let environment = ConformanceEnvironment::new(
        args.os.clone(),
        args.arch.clone(),
        args.rust_toolchain.clone(),
    );
    let mut report = build_report(&args, environment)?;
    apply_report_overrides(&mut report, &args)?;
    let json = serde_json::to_vec_pretty(&report)?;

    write_output(&args.output, &json)?;
    Ok(())
}

fn build_report(
    args: &Args,
    environment: ConformanceEnvironment,
) -> Result<ConformanceRun, CliError> {
    #[cfg(feature = "python_oracle")]
    {
        if args.require_oracle {
            let Some(reticulum_path) = args.reticulum_path.as_ref() else {
                return Err(CliError::MissingRequired("--reticulum-path"));
            };
            return Ok(profile_0_report_with_required_oracle(
                args.run_id.clone(),
                args.hyf_commit.clone(),
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
        args.hyf_commit.clone(),
        args.started_at.clone(),
        environment,
    ))
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
    hyf_commit: String,
    started_at: String,
    rust_toolchain: String,
    os: String,
    arch: String,
    output: String,
    reticulum_path: Option<PathBuf>,
    report_path_root: Option<PathBuf>,
    require_oracle: bool,
}

impl Args {
    fn parse<I>(mut args: I) -> Result<Self, CliError>
    where
        I: Iterator<Item = String>,
    {
        let mut run_id = None;
        let mut hyf_commit = None;
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
                "--hyf-commit" => hyf_commit = Some(next_value(&mut args, "--hyf-commit")?),
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
            hyf_commit: required(hyf_commit, "--hyf-commit")?,
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

#[derive(Debug)]
enum CliError {
    Usage,
    UnknownArgument(String),
    MissingValue(&'static str),
    MissingRequired(&'static str),
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
usage: hyf-rns-conformance-report \\
  --run-id <id> \\
  --hyf-commit <commit> \\
  --started-at <date-time> \\
  --rust-toolchain <toolchain> \\
  --output <path|-> \\
  [--reticulum-path <path> --require-oracle] \\
  [--report-path-root <path>] \\
  [--os <os>] \\
  [--arch <arch>]";

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use hyf_rns_conformance::profile0::profile_0_report;
    use hyf_rns_conformance::report::{ConformanceEnvironment, OracleEnvironment};

    use super::{Args, CliError, apply_report_overrides, report_relative_path};

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
                "--hyf-commit",
                "c7895f0",
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
        assert_eq!(args.hyf_commit, "c7895f0");
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
            hyf_commit: "c7895f0".to_owned(),
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
}
