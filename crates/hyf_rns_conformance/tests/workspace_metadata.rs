use std::path::Path;
use std::process::Command;

use serde::Deserialize;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKSPACE_PACKAGES: &[&str] = &[
    "hyf_core",
    "hyf_crypto",
    "hyf_wire",
    "hyf_link",
    "hyf_link_kiss",
    "hyf_link_rnode",
    "hyf_rns_core",
    "hyf_rns_crypto",
    "hyf_rns_wire",
    "hyf_rns_conformance",
];

const FUZZ_PACKAGES: &[&str] = &["hyf-fuzz"];
const DEFAULT_FEATURE_EXCEPTIONS: &[DefaultFeatureException] = &[DefaultFeatureException {
    package: "hyf-fuzz",
    dependency: "libfuzzer-sys",
    kind: "normal",
}];

struct DefaultFeatureException {
    package: &'static str,
    dependency: &'static str,
    kind: &'static str,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Deserialize)]
struct Dependency {
    name: String,
    kind: Option<String>,
    uses_default_features: bool,
}

#[test]
fn workspace_direct_dependencies_disable_default_features() -> TestResult {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = metadata_for_manifest(&workspace_root.join("Cargo.toml"))?;
    assert_direct_dependencies_disable_defaults(&metadata, WORKSPACE_PACKAGES)
}

#[test]
fn fuzz_direct_dependencies_disable_default_features() -> TestResult {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = metadata_for_manifest(&workspace_root.join("fuzz/Cargo.toml"))?;
    assert_direct_dependencies_disable_defaults(&metadata, FUZZ_PACKAGES)
}

fn metadata_for_manifest(manifest_path: &Path) -> TestResult<Metadata> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "cargo metadata failed for {}: {}",
            manifest_path.display(),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

fn assert_direct_dependencies_disable_defaults(
    metadata: &Metadata,
    package_names: &[&str],
) -> TestResult {
    let violations = default_feature_violations(metadata, package_names);

    if !violations.is_empty() {
        return Err(std::io::Error::other(format!(
            "direct dependencies inherit default features without exception: {}",
            violations.join(", ")
        ))
        .into());
    }

    Ok(())
}

fn default_feature_violations(metadata: &Metadata, package_names: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| package_names.contains(&package.name.as_str()))
    {
        for dependency in package
            .dependencies
            .iter()
            .filter(|dependency| dependency.uses_default_features)
        {
            let kind = dependency_kind(dependency);
            if !allows_default_features(&package.name, &dependency.name, kind) {
                violations.push(format!("{} -> {} ({kind})", package.name, dependency.name));
            }
        }
    }
    violations
}

fn dependency_kind(dependency: &Dependency) -> &str {
    dependency.kind.as_deref().unwrap_or("normal")
}

fn allows_default_features(package: &str, dependency: &str, kind: &str) -> bool {
    DEFAULT_FEATURE_EXCEPTIONS.iter().any(|exception| {
        exception.package == package && exception.dependency == dependency && exception.kind == kind
    })
}
