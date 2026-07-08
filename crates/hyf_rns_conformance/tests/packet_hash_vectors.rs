use hyf_rns_conformance::fixtures::{
    FixtureError, assert_manifest_entry, decode_hex, decode_hex_exact, decode_optional_hex_exact,
    parse_fixture_cases, parse_manifest,
};
use hyf_rns_core::{RNS_MTU, RNS_TRUNCATED_HASH_LEN};
use hyf_rns_wire::{packet_hash, packet_truncated_hash, write_packet_hashable_part};
use serde::Deserialize;

const FIXTURE: &str = include_str!("../../../fixtures/rns/packet_hash_vectors.json");
const MANIFEST: &str = include_str!("../../../fixtures/rns/manifest.json");

#[derive(Debug, Deserialize)]
struct PacketHashCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    inputs: PacketHashInputs,
    expected: PacketHashExpected,
}

#[derive(Debug, Deserialize)]
struct PacketHashInputs {
    description: String,
}

#[derive(Debug, Deserialize)]
struct PacketHashExpected {
    raw_packet: String,
    hashable_part: String,
    full_hash: String,
    truncated_hash: String,
    transport_id: Option<String>,
}

#[test]
fn packet_hash_fixtures_match_reticulum_oracle() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<PacketHashCase>(FIXTURE)?;
    let mut header_2_transport_proof: Option<Header2TransportProof> = None;

    assert_eq!(fixture.cases.len(), 3);
    for case in fixture.cases {
        assert!(
            case.id
                .starts_with("profile_0_packet_announce.packet_hash.synthetic.")
        );
        assert_eq!(case.category, "packet_hash");
        assert!(case.deterministic);
        assert!(!case.private_test_material);
        assert_eq!(
            case.inputs.description,
            "synthetic Reticulum Packet hash vector"
        );

        let raw_packet = decode_hex(&case.expected.raw_packet)?;
        let expected_hashable_part = decode_hex(&case.expected.hashable_part)?;
        let expected_full_hash = decode_hex_exact::<32>(&case.expected.full_hash)?;
        let expected_truncated_hash =
            decode_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.truncated_hash)?;
        let expected_transport_id =
            decode_optional_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.transport_id)?;
        let mut hashable_part = [0; RNS_MTU];
        let hashable_len = write_packet_hashable_part(&raw_packet, &mut hashable_part)?;

        assert_eq!(&hashable_part[..hashable_len], expected_hashable_part);
        assert_eq!(packet_hash(&raw_packet)?.into_bytes(), expected_full_hash);
        assert_eq!(
            packet_truncated_hash(&raw_packet)?.into_bytes(),
            expected_truncated_hash
        );

        if let Some(transport_id) = expected_transport_id {
            let proof = Header2TransportProof {
                transport_id,
                hashable_part: expected_hashable_part,
                full_hash: expected_full_hash,
                truncated_hash: expected_truncated_hash,
            };
            if let Some(previous) = &header_2_transport_proof {
                assert_ne!(previous.transport_id, proof.transport_id);
                assert_eq!(previous.hashable_part, proof.hashable_part);
                assert_eq!(previous.full_hash, proof.full_hash);
                assert_eq!(previous.truncated_hash, proof.truncated_hash);
            } else {
                header_2_transport_proof = Some(proof);
            }
        }
    }

    Ok(())
}

#[test]
fn fixture_manifest_tracks_packet_hash_vectors() -> Result<(), FixtureError> {
    let manifest = parse_manifest(MANIFEST)?;

    assert_manifest_entry(
        &manifest,
        "packet_hash_vectors.json",
        "packet_hash",
        3,
        FIXTURE,
    )?;
    Ok(())
}

struct Header2TransportProof {
    transport_id: [u8; RNS_TRUNCATED_HASH_LEN],
    hashable_part: Vec<u8>,
    full_hash: [u8; 32],
    truncated_hash: [u8; RNS_TRUNCATED_HASH_LEN],
}
