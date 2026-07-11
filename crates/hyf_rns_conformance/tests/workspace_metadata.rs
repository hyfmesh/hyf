use std::collections::{BTreeMap, BTreeSet};
use std::fs;
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
const COMMON_FEATURES: &[FeatureSpec] = &[
    FeatureSpec {
        name: "alloc",
        enables: &[],
    },
    FeatureSpec {
        name: "default",
        enables: &[],
    },
    FeatureSpec {
        name: "std",
        enables: &["alloc"],
    },
];
const EXPECTED_FEATURE_SURFACE: &[FeatureSurface] = &[
    common_features("hyf_core"),
    common_features("hyf_crypto"),
    common_features("hyf_wire"),
    common_features("hyf_link"),
    common_features("hyf_store"),
    common_features("hyf_router"),
    common_features("hyf_link_loopback"),
    common_features("hyf_config"),
    FeatureSurface {
        package: "hyf_gateway",
        features: &[
            FeatureSpec {
                name: "default",
                enables: &[],
            },
            FeatureSpec {
                name: "std",
                enables: &[],
            },
        ],
    },
    common_features("hyf_link_kiss"),
    FeatureSurface {
        package: "hyf_link_rnode",
        features: &[
            FeatureSpec {
                name: "alloc",
                enables: &[],
            },
            FeatureSpec {
                name: "default",
                enables: &[],
            },
            FeatureSpec {
                name: "hil_std",
                enables: &["dep:serialport", "std"],
            },
            FeatureSpec {
                name: "rnode",
                enables: &[],
            },
            FeatureSpec {
                name: "std",
                enables: &["alloc"],
            },
        ],
    },
    common_features("hyf_rns_core"),
    FeatureSurface {
        package: "hyf_rns_crypto",
        features: &[
            FeatureSpec {
                name: "alloc",
                enables: &[],
            },
            FeatureSpec {
                name: "crypto_hkdf",
                enables: &["dep:hkdf", "dep:hmac", "dep:sha2"],
            },
            FeatureSpec {
                name: "crypto_token",
                enables: &["crypto_hkdf", "dep:aes", "dep:cbc", "dep:rand_core"],
            },
            FeatureSpec {
                name: "crypto_x25519",
                enables: &["crypto_token", "dep:x25519-dalek"],
            },
            FeatureSpec {
                name: "default",
                enables: &[],
            },
            FeatureSpec {
                name: "std",
                enables: &["alloc"],
            },
            FeatureSpec {
                name: "test_vectors",
                enables: &[],
            },
        ],
    },
    FeatureSurface {
        package: "hyf_rns_wire",
        features: &[
            FeatureSpec {
                name: "alloc",
                enables: &[],
            },
            FeatureSpec {
                name: "default",
                enables: &[],
            },
            FeatureSpec {
                name: "ifac",
                enables: &["hyf_rns_crypto/crypto_hkdf"],
            },
            FeatureSpec {
                name: "std",
                enables: &["alloc"],
            },
        ],
    },
    FeatureSurface {
        package: "hyf_rns_conformance",
        features: &[
            FeatureSpec {
                name: "default",
                enables: &[],
            },
            FeatureSpec {
                name: "python_oracle",
                enables: &[],
            },
        ],
    },
];
const HANDOFF_3_GATEWAY_PACKAGES: &[&str] = &[
    "hyf_core",
    "hyf_wire",
    "hyf_link",
    "hyf_store",
    "hyf_router",
    "hyf_link_loopback",
    "hyf_config",
    "hyf_gateway",
];
const FUTURE_ADAPTER_DEPENDENCY_MARKERS: &[&str] = &[
    "bitchat",
    "fips",
    "lxmf",
    "nostr",
    "pyo3",
    "python",
    "reticulum",
    "rnode",
    "serialport",
];

const fn common_features(package: &'static str) -> FeatureSurface {
    FeatureSurface {
        package,
        features: COMMON_FEATURES,
    }
}

struct DefaultFeatureException {
    package: &'static str,
    dependency: &'static str,
    kind: &'static str,
}

struct FeatureSurface {
    package: &'static str,
    features: &'static [FeatureSpec],
}

struct FeatureSpec {
    name: &'static str,
    enables: &'static [&'static str],
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
    features: BTreeMap<String, Vec<String>>,
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

#[test]
fn first_party_feature_surface_is_explicit() -> TestResult {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = metadata_for_manifest(&workspace_root.join("Cargo.toml"))?;
    let packages = workspace_packages(&metadata)?;

    for expected in EXPECTED_FEATURE_SURFACE {
        let package = package_by_name(&packages, expected.package)?;
        assert_feature_surface(package, expected)?;
    }
    assert_feature_surface_covers_workspace(&packages)?;

    Ok(())
}

#[test]
fn crypto_hkdf_is_intentional_dependency_isolation_feature() -> TestResult {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = metadata_for_manifest(&workspace_root.join("Cargo.toml"))?;
    let packages = workspace_packages(&metadata)?;
    let crypto = package_by_name(&packages, "hyf_rns_crypto")?;
    let wire = package_by_name(&packages, "hyf_rns_wire")?;

    assert_feature_enables(crypto, "crypto_hkdf", &["dep:hkdf", "dep:hmac", "dep:sha2"])?;
    assert_feature_omits(
        crypto,
        "crypto_hkdf",
        &[
            "crypto_token",
            "crypto_x25519",
            "dep:aes",
            "dep:cbc",
            "dep:rand_core",
            "dep:x25519-dalek",
        ],
    )?;
    assert_feature_enables(wire, "ifac", &["hyf_rns_crypto/crypto_hkdf"])?;
    assert_feature_omits(
        wire,
        "ifac",
        &[
            "hyf_rns_crypto/crypto_token",
            "hyf_rns_crypto/crypto_x25519",
        ],
    )?;

    Ok(())
}

#[test]
fn handoff_3_gateway_dependencies_preserve_clean_boundaries() -> TestResult {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = metadata_for_manifest(&workspace_root.join("Cargo.toml"))?;
    let packages = workspace_packages(&metadata)?;

    assert_direct_dependency_names(
        package_by_name(&packages, "hyf_store")?,
        &["hyf_core", "hyf_wire"],
    )?;
    assert_direct_dependency_names(
        package_by_name(&packages, "hyf_router")?,
        &["hyf_core", "hyf_link", "hyf_wire"],
    )?;
    assert_direct_dependency_names(
        package_by_name(&packages, "hyf_link_loopback")?,
        &["hyf_core", "hyf_link"],
    )?;
    assert_direct_dependency_names(
        package_by_name(&packages, "hyf_config")?,
        &["hyf_core", "hyf_link", "hyf_router", "hyf_store"],
    )?;
    assert_direct_dependency_names(
        package_by_name(&packages, "hyf_gateway")?,
        &[
            "hyf_config",
            "hyf_core",
            "hyf_link",
            "hyf_link_loopback",
            "hyf_router",
            "hyf_store",
            "hyf_wire",
        ],
    )?;
    assert_packages_omit_dependency_markers(
        &packages,
        HANDOFF_3_GATEWAY_PACKAGES,
        FUTURE_ADAPTER_DEPENDENCY_MARKERS,
    )
}

#[test]
fn text_hex_fuzz_corpus_targets_decode_seed_input() -> TestResult {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text_hex_targets = text_hex_corpus_targets(&workspace_root.join("fuzz/corpus"))?;
    if text_hex_targets.is_empty() {
        return Err(std::io::Error::other("no text-hex fuzz corpus seeds were found").into());
    }

    for target in text_hex_targets {
        let target_path = workspace_root
            .join("fuzz/fuzz_targets")
            .join(format!("{target}.rs"));
        let source = fs::read_to_string(&target_path)?;
        if !source.contains("hyf_fuzz::seed_input::input_bytes(") {
            return Err(std::io::Error::other(format!(
                "text-hex corpus target {target} does not use shared seed_input in {}",
                target_path.display()
            ))
            .into());
        }
    }

    Ok(())
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

fn text_hex_corpus_targets(corpus_root: &Path) -> TestResult<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    for target_entry in fs::read_dir(corpus_root)? {
        let target_entry = target_entry?;
        if !target_entry.file_type()?.is_dir() {
            continue;
        }
        let target_name = target_entry.file_name().into_string().map_err(|name| {
            std::io::Error::other(format!("non-UTF-8 corpus directory: {name:?}"))
        })?;

        for seed_entry in fs::read_dir(target_entry.path())? {
            let seed_entry = seed_entry?;
            if !seed_entry.file_type()?.is_file() {
                continue;
            }
            let seed = fs::read(seed_entry.path())?;
            if is_lower_text_hex_seed(&seed) {
                targets.insert(target_name.clone());
            }
        }
    }
    Ok(targets)
}

fn is_lower_text_hex_seed(seed: &[u8]) -> bool {
    let trimmed = trim_ascii_whitespace(seed);
    !trimmed.is_empty()
        && trimmed.len().is_multiple_of(2)
        && trimmed
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn trim_ascii_whitespace(input: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = input.len();

    while start < end && input[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && input[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    &input[start..end]
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

fn package_by_name<'a>(packages: &'a [&Package], package_name: &str) -> TestResult<&'a Package> {
    packages
        .iter()
        .copied()
        .find(|package| package.name == package_name)
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "expected package {package_name} was not present in package set"
            ))
            .into()
        })
}

fn assert_feature_surface(package: &Package, expected: &FeatureSurface) -> TestResult {
    let actual = normalized_features(&package.features);
    let expected = expected_feature_map(expected.features);
    if actual == expected {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "feature surface mismatch for {}: actual {:?}, expected {:?}",
        package.name, actual, expected
    ))
    .into())
}

fn assert_feature_surface_covers_workspace(packages: &[&Package]) -> TestResult {
    let actual = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_FEATURE_SURFACE
        .iter()
        .map(|feature_surface| feature_surface.package)
        .collect::<BTreeSet<_>>();

    if actual == expected {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "expected feature surface package set {:?}, actual workspace package set {:?}",
        expected, actual
    ))
    .into())
}

fn normalized_features(features: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    features
        .iter()
        .map(|(name, enables)| (name.to_owned(), sorted_strings(enables)))
        .collect()
}

fn expected_feature_map(features: &[FeatureSpec]) -> BTreeMap<String, Vec<String>> {
    features
        .iter()
        .map(|feature| {
            (
                feature.name.to_owned(),
                feature
                    .enables
                    .iter()
                    .map(|enabled| (*enabled).to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_owned();
    values.sort();
    values
}

fn assert_feature_enables(package: &Package, feature_name: &str, expected: &[&str]) -> TestResult {
    let actual = feature_enables(package, feature_name)?;
    let expected = expected
        .iter()
        .map(|enabled| (*enabled).to_owned())
        .collect::<Vec<_>>();
    if actual == expected {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "{} feature {feature_name} enables {:?}, expected {:?}",
        package.name, actual, expected
    ))
    .into())
}

fn assert_feature_omits(package: &Package, feature_name: &str, omitted: &[&str]) -> TestResult {
    let actual = feature_enables(package, feature_name)?;
    let unexpected = omitted
        .iter()
        .filter(|omitted| actual.iter().any(|enabled| enabled == *omitted))
        .copied()
        .collect::<Vec<_>>();
    if unexpected.is_empty() {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "{} feature {feature_name} enables forbidden entries: {}",
        package.name,
        unexpected.join(", ")
    ))
    .into())
}

fn feature_enables(package: &Package, feature_name: &str) -> TestResult<Vec<String>> {
    package
        .features
        .get(feature_name)
        .map(|features| sorted_strings(features))
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "{} does not define expected feature {feature_name}",
                package.name
            ))
            .into()
        })
}

fn assert_direct_dependency_names(package: &Package, expected: &[&str]) -> TestResult {
    let actual = direct_dependency_names(package);
    let expected = expected
        .iter()
        .map(|dependency| (*dependency).to_owned())
        .collect::<Vec<_>>();
    if actual == expected {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "{} direct dependencies {:?}, expected {:?}",
        package.name, actual, expected
    ))
    .into())
}

fn assert_packages_omit_dependency_markers(
    packages: &[&Package],
    package_names: &[&str],
    forbidden_markers: &[&str],
) -> TestResult {
    let mut violations = Vec::new();
    for package_name in package_names {
        let package = package_by_name(packages, package_name)?;
        for dependency in &package.dependencies {
            let dependency_name = dependency.name.to_ascii_lowercase();
            for marker in forbidden_markers {
                if dependency_name.contains(marker) {
                    violations.push(format!(
                        "{} -> {} ({})",
                        package.name,
                        dependency.name,
                        dependency_kind(dependency)
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "Handoff 3 gateway packages depend on forbidden future-adapter crates: {}",
        violations.join(", ")
    ))
    .into())
}

fn direct_dependency_names(package: &Package) -> Vec<String> {
    let mut names = package
        .dependencies
        .iter()
        .map(|dependency| dependency.name.to_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
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
                features: BTreeMap::new(),
            },
            Package {
                id: "path+file:///repo/member-b#0.1.0".to_owned(),
                name: "member_b".to_owned(),
                dependencies: Vec::new(),
                features: BTreeMap::new(),
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
            features: BTreeMap::new(),
        }],
    };

    let result = packages_by_name(&metadata, &["missing"]);

    assert!(result.is_err());
}
