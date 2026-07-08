mod support;

use hyf_rns_core::{
    RNS_NAME_HASH_LEN, RNS_TRUNCATED_HASH_LEN, RnsIdentityHash, destination_hash,
    destination_name_hash,
};
use serde::Deserialize;
use support::{
    FixtureError, assert_manifest_entry, decode_hex_exact, decode_optional_hex_exact,
    parse_fixture_cases, parse_manifest,
};

const FIXTURE: &str = include_str!("../../../fixtures/rns/destination_hash_vectors.json");
const MANIFEST: &str = include_str!("../../../fixtures/rns/manifest.json");

#[derive(Debug, Deserialize)]
struct DestinationHashCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    inputs: DestinationHashInputs,
    expected: DestinationHashExpected,
}

#[derive(Debug, Deserialize)]
struct DestinationHashInputs {
    app_name: String,
    aspects: Vec<String>,
    identity_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DestinationHashExpected {
    expanded_name: String,
    name_hash: String,
    destination_hash: String,
}

#[test]
fn destination_hash_fixtures_match_reticulum_oracle() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<DestinationHashCase>(FIXTURE)?;
    let mut plain_cases = 0;
    let mut identity_bound_cases = 0;

    assert_eq!(fixture.cases.len(), 6);
    for case in fixture.cases {
        assert!(
            case.id
                .starts_with("profile_0_packet_announce.destination_hash.synthetic.")
        );
        assert_eq!(case.category, "destination_hash");
        assert!(case.deterministic);
        assert!(!case.private_test_material);
        assert_eq!(
            expanded_destination_name(&case.inputs.app_name, &case.inputs.aspects),
            case.expected.expanded_name
        );

        let aspects: Vec<&str> = case.inputs.aspects.iter().map(String::as_str).collect();
        let expected_name_hash = decode_hex_exact::<RNS_NAME_HASH_LEN>(&case.expected.name_hash)?;
        let expected_destination_hash =
            decode_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.destination_hash)?;
        let identity_hash =
            decode_optional_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.inputs.identity_hash)?
                .map(RnsIdentityHash::new);

        if identity_hash.is_some() {
            identity_bound_cases += 1;
        } else {
            plain_cases += 1;
        }

        let name_hash = destination_name_hash(&case.inputs.app_name, &aspects)?;
        assert_eq!(name_hash.as_bytes(), &expected_name_hash);
        assert_eq!(
            destination_hash(name_hash, identity_hash).as_bytes(),
            &expected_destination_hash
        );
    }

    assert_eq!(plain_cases, 3);
    assert_eq!(identity_bound_cases, 3);
    Ok(())
}

#[test]
fn fixture_manifest_tracks_destination_hash_vectors() -> Result<(), FixtureError> {
    let manifest = parse_manifest(MANIFEST)?;

    assert_manifest_entry(
        &manifest,
        "destination_hash_vectors.json",
        "destination_hash",
        6,
        FIXTURE,
    )?;
    Ok(())
}

fn expanded_destination_name(app_name: &str, aspects: &[String]) -> String {
    let mut name = app_name.to_owned();
    for aspect in aspects {
        name.push('.');
        name.push_str(aspect);
    }
    name
}
