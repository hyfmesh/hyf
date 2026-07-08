#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use hyf_rns_conformance::profile0::profile_0_report;
#[cfg(feature = "python_oracle")]
use hyf_rns_conformance::profile0::profile_0_report_with_required_oracle;
use hyf_rns_conformance::report::ConformanceEnvironment;

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
    let report = build_report(&args, environment)?;
    let json = serde_json::to_vec_pretty(&report)?;

    write_output(&args.output, &json)?;
    Ok(())
}

fn build_report(
    args: &Args,
    environment: ConformanceEnvironment,
) -> Result<hyf_rns_conformance::report::ConformanceRun, CliError> {
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
  [--os <os>] \\
  [--arch <arch>]";

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Args, CliError};

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
        assert!(!args.os.is_empty());
        assert!(!args.arch.is_empty());
        Ok(())
    }
}
