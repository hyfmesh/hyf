use hyf_rns_conformance::fixtures::{
    FixtureError, assert_manifest_entry, decode_hex, decode_hex_exact, decode_optional_hex_exact,
    parse_fixture_cases, parse_manifest,
};
use hyf_rns_core::{RNS_MTU, RNS_NAME_HASH_LEN, RNS_TRUNCATED_HASH_LEN};
use hyf_rns_crypto::RNS_PUBLIC_IDENTITY_LEN;
use hyf_rns_wire::{
    RNS_ANNOUNCE_RANDOM_HASH_LEN, RNS_ANNOUNCE_RATCHET_LEN, RNS_ANNOUNCE_SIGNATURE_LEN,
    RnsWireError, build_announce_signed_data, decode_packet, validate_announce_packet,
};
use serde::Deserialize;

const ANNOUNCE_FIXTURE: &str = include_str!("../../../fixtures/rns/announce_vectors.json");
const ANNOUNCE_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/announce_negative_vectors.json");
const MANIFEST: &str = include_str!("../../../fixtures/rns/manifest.json");

#[derive(Debug, Deserialize)]
struct AnnounceCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    inputs: AnnounceInputs,
    expected: AnnounceExpected,
}

#[derive(Debug, Deserialize)]
struct AnnounceInputs {
    secret_identity: String,
    app_name: String,
    aspects: Vec<String>,
    app_data: String,
    random_hash: String,
}

#[derive(Debug, Deserialize)]
struct AnnounceExpected {
    raw_packet: String,
    destination_hash: String,
    public_identity: String,
    name_hash: String,
    random_hash: String,
    ratchet: Option<String>,
    signature: String,
    app_data: String,
    context_flag: u8,
}

#[derive(Debug, Deserialize)]
struct AnnounceNegativeCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    mutation: String,
    expected_error: String,
    raw_packet: String,
}

#[test]
fn announce_fixtures_validate_against_reticulum_oracle() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<AnnounceCase>(ANNOUNCE_FIXTURE)?;

    assert_eq!(fixture.cases.len(), 2);
    for case in fixture.cases {
        assert!(
            case.id
                .starts_with("profile_0_packet_announce.announce.synthetic.")
        );
        assert_eq!(case.category, "announce");
        assert!(case.deterministic);
        assert!(case.private_test_material);
        assert_eq!(
            decode_hex(&case.inputs.secret_identity)?,
            (0u8..64).collect::<Vec<_>>()
        );
        assert_eq!(case.inputs.app_name, "hyf");
        assert_eq!(case.inputs.aspects, vec!["announce".to_owned()]);
        assert_eq!(case.inputs.app_data, case.expected.app_data);
        assert_eq!(case.inputs.random_hash, case.expected.random_hash);

        let raw_packet = decode_hex(&case.expected.raw_packet)?;
        let packet = decode_packet(&raw_packet)?;
        let announce = validate_announce_packet(packet)?;
        let expected_destination_hash =
            decode_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.destination_hash)?;
        let expected_public_identity =
            decode_hex_exact::<RNS_PUBLIC_IDENTITY_LEN>(&case.expected.public_identity)?;
        let expected_name_hash = decode_hex_exact::<RNS_NAME_HASH_LEN>(&case.expected.name_hash)?;
        let expected_random_hash =
            decode_hex_exact::<RNS_ANNOUNCE_RANDOM_HASH_LEN>(&case.expected.random_hash)?;
        let expected_ratchet =
            decode_optional_hex_exact::<RNS_ANNOUNCE_RATCHET_LEN>(&case.expected.ratchet)?;
        let expected_signature =
            decode_hex_exact::<RNS_ANNOUNCE_SIGNATURE_LEN>(&case.expected.signature)?;
        let expected_app_data = decode_hex(&case.expected.app_data)?;
        let mut signed_data = [0; RNS_MTU];
        let signed_data_len = build_announce_signed_data(&announce, &mut signed_data)?;
        let signed_app_data_start = signed_data_len
            .checked_sub(expected_app_data.len())
            .ok_or_else(|| FixtureError::UnexpectedFixtureValue {
                field: "signed_data_len".to_owned(),
                value: signed_data_len.to_string(),
            })?;
        let signed_app_data = signed_data
            .get(signed_app_data_start..signed_data_len)
            .ok_or_else(|| FixtureError::UnexpectedFixtureValue {
                field: "signed_data_app_data".to_owned(),
                value: signed_data_len.to_string(),
            })?;

        assert_eq!(packet.flags.context_flag as u8, case.expected.context_flag);
        assert_eq!(
            announce.destination_hash.as_bytes(),
            &expected_destination_hash
        );
        assert_eq!(announce.public_identity, expected_public_identity);
        assert_eq!(announce.name_hash.as_bytes(), &expected_name_hash);
        assert_eq!(announce.random_hash, expected_random_hash);
        assert_eq!(announce.ratchet, expected_ratchet);
        assert_eq!(announce.signature, expected_signature);
        assert_eq!(announce.app_data, expected_app_data.as_slice());
        assert_eq!(
            &signed_data[..RNS_TRUNCATED_HASH_LEN],
            announce.destination_hash.as_bytes()
        );
        assert_eq!(signed_app_data, expected_app_data.as_slice());
    }

    Ok(())
}

#[test]
fn announce_negative_fixtures_reject_expected_mutations() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<AnnounceNegativeCase>(ANNOUNCE_NEGATIVE_FIXTURE)?;

    assert_eq!(fixture.cases.len(), 7);
    for case in fixture.cases {
        assert!(
            case.id
                .starts_with("profile_0_packet_announce.announce_negative.synthetic.")
        );
        assert_eq!(case.category, "announce_negative");
        assert!(case.deterministic);
        assert!(case.private_test_material);
        assert!(
            [
                "destination",
                "public_identity",
                "name_hash",
                "random_hash",
                "signature",
                "app_data",
                "context_flag",
            ]
            .contains(&case.mutation.as_str())
        );

        let raw_packet = decode_hex(&case.raw_packet)?;
        let packet = decode_packet(&raw_packet)?;

        assert_eq!(
            validate_announce_packet(packet),
            Err(expected_wire_error(&case.expected_error)?)
        );
    }

    Ok(())
}

#[test]
fn fixture_manifest_tracks_announce_vectors() -> Result<(), FixtureError> {
    let manifest = parse_manifest(MANIFEST)?;

    assert_manifest_entry(
        &manifest,
        "announce_vectors.json",
        "announce",
        2,
        ANNOUNCE_FIXTURE,
    )?;
    assert_manifest_entry(
        &manifest,
        "announce_negative_vectors.json",
        "announce_negative",
        7,
        ANNOUNCE_NEGATIVE_FIXTURE,
    )?;
    Ok(())
}

fn expected_wire_error(error: &str) -> Result<RnsWireError, FixtureError> {
    match error {
        "DestinationMismatch" => Ok(RnsWireError::DestinationMismatch),
        "InvalidSignature" => Ok(RnsWireError::InvalidSignature),
        "MalformedAnnounce" => Ok(RnsWireError::MalformedAnnounce),
        _ => Err(FixtureError::UnexpectedFixtureValue {
            field: "expected_error".to_owned(),
            value: error.to_owned(),
        }),
    }
}
