use std::path::Path;
use std::process::Command;

use serde::Deserialize;

const FIRST_PARTY_PACKAGES: &[&str] = &[
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

const PRODUCTION_PACKAGES: &[&str] = &[
    "hyf_core",
    "hyf_crypto",
    "hyf_wire",
    "hyf_link",
    "hyf_link_kiss",
    "hyf_link_rnode",
    "hyf_rns_core",
    "hyf_rns_crypto",
    "hyf_rns_wire",
];

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
    source: Option<String>,
    kind: Option<String>,
    uses_default_features: bool,
}

#[test]
fn production_first_party_dependencies_disable_default_features()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--manifest-path")
        .arg(workspace_root.join("Cargo.toml"))
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }

    let metadata: Metadata = serde_json::from_slice(&output.stdout)?;
    let mut violations = Vec::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| PRODUCTION_PACKAGES.contains(&package.name.as_str()))
    {
        for dependency in package.dependencies.iter().filter(|dependency| {
            dependency.source.is_none()
                && dependency.kind.is_none()
                && FIRST_PARTY_PACKAGES.contains(&dependency.name.as_str())
                && dependency.uses_default_features
        }) {
            violations.push(format!("{} -> {}", package.name, dependency.name));
        }
    }

    if !violations.is_empty() {
        return Err(std::io::Error::other(format!(
            "first-party production dependencies inherit default features: {}",
            violations.join(", ")
        ))
        .into());
    }

    Ok(())
}
