use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
    workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Package {
    id: String,
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
    let packages = workspace_packages(&metadata)?;
    assert_direct_dependencies_disable_defaults(&packages)
}

#[test]
fn fuzz_direct_dependencies_disable_default_features() -> TestResult {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = metadata_for_manifest(&workspace_root.join("fuzz/Cargo.toml"))?;
    let packages = packages_by_name(&metadata, FUZZ_PACKAGES)?;
    assert_direct_dependencies_disable_defaults(&packages)
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

fn workspace_packages(metadata: &Metadata) -> TestResult<Vec<&Package>> {
    let member_ids = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if member_ids.is_empty() {
        return Err(std::io::Error::other("cargo metadata returned no workspace members").into());
    }

    let mut packages = Vec::new();
    for member_id in member_ids {
        let Some(package) = metadata
            .packages
            .iter()
            .find(|package| package.id == member_id)
        else {
            return Err(std::io::Error::other(format!(
                "workspace member {member_id} was not present in cargo metadata packages"
            ))
            .into());
        };
        packages.push(package);
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(packages)
}

fn packages_by_name<'a>(
    metadata: &'a Metadata,
    package_names: &[&str],
) -> TestResult<Vec<&'a Package>> {
    let mut packages = Vec::new();
    for package_name in package_names {
        let Some(package) = metadata
            .packages
            .iter()
            .find(|package| package.name == *package_name)
        else {
            return Err(std::io::Error::other(format!(
                "expected package {package_name} was not present in cargo metadata packages"
            ))
            .into());
        };
        packages.push(package);
    }
    Ok(packages)
}

fn assert_direct_dependencies_disable_defaults(packages: &[&Package]) -> TestResult {
    let violations = default_feature_violations(packages);

    if !violations.is_empty() {
        return Err(std::io::Error::other(format!(
            "direct dependencies inherit default features without exception: {}",
            violations.join(", ")
        ))
        .into());
    }

    Ok(())
}

fn default_feature_violations(packages: &[&Package]) -> Vec<String> {
    let mut violations = Vec::new();
    for package in packages {
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

#[test]
fn workspace_package_coverage_is_derived_from_metadata_members() -> TestResult {
    let metadata = Metadata {
        workspace_members: vec!["path+file:///repo/member-b#0.1.0".to_owned()],
        packages: vec![
            Package {
                id: "path+file:///repo/member-a#0.1.0".to_owned(),
                name: "member_a".to_owned(),
                dependencies: Vec::new(),
            },
            Package {
                id: "path+file:///repo/member-b#0.1.0".to_owned(),
                name: "member_b".to_owned(),
                dependencies: Vec::new(),
            },
        ],
    };
    let packages = workspace_packages(&metadata)?;

    assert_eq!(
        packages
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>(),
        ["member_b"]
    );
    Ok(())
}

#[test]
fn explicit_package_coverage_rejects_missing_packages() {
    let metadata = Metadata {
        workspace_members: Vec::new(),
        packages: vec![Package {
            id: "path+file:///repo/present#0.1.0".to_owned(),
            name: "present".to_owned(),
            dependencies: Vec::new(),
        }],
    };

    let result = packages_by_name(&metadata, &["missing"]);

    assert!(result.is_err());
}
