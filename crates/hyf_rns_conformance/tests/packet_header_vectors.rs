use hyf_rns_conformance::fixtures::{
    FixtureError, assert_manifest_entry, decode_hex, decode_hex_exact, parse_fixture_cases,
    parse_manifest,
};
use hyf_rns_core::{RNS_MTU, RNS_TRUNCATED_HASH_LEN};
use hyf_rns_wire::{decode_packet, encode_flags, encode_packet};
use serde::Deserialize;

const FIXTURE: &str = include_str!("../../../fixtures/rns/packet_header_vectors.json");
const MANIFEST: &str = include_str!("../../../fixtures/rns/manifest.json");

#[derive(Debug, Deserialize)]
struct PacketHeaderCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    inputs: PacketHeaderInputs,
    expected: PacketHeaderExpected,
}

#[derive(Debug, Deserialize)]
struct PacketHeaderInputs {
    description: String,
}

#[derive(Debug, Deserialize)]
struct PacketHeaderExpected {
    raw_packet: String,
    flags: String,
    hops: u8,
    header_type: u8,
    context_flag: u8,
    transport_type: u8,
    destination_type: u8,
    packet_type: u8,
    transport_id: Option<String>,
    destination_hash: String,
    context: String,
    data: String,
}

#[test]
fn packet_header_fixtures_match_reticulum_oracle() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<PacketHeaderCase>(FIXTURE)?;

    assert_eq!(fixture.cases.len(), 2);
    for case in fixture.cases {
        assert!(
            case.id
                .starts_with("profile_0_packet_announce.packet_header.synthetic.")
        );
        assert_eq!(case.category, "packet_header");
        assert!(case.deterministic);
        assert!(!case.private_test_material);
        assert_eq!(
            case.inputs.description,
            "synthetic Reticulum Packet.pack() header vector"
        );

        let raw_packet = decode_hex(&case.expected.raw_packet)?;
        let packet = decode_packet(&raw_packet)?;
        let expected_flags = decode_hex_exact::<1>(&case.expected.flags)?[0];
        let expected_context = decode_hex_exact::<1>(&case.expected.context)?[0];
        let expected_destination_hash =
            decode_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.destination_hash)?;
        let expected_data = decode_hex(&case.expected.data)?;
        let expected_transport_id = decode_optional_transport_id(&case.expected.transport_id)?;

        assert_eq!(raw_packet[0], expected_flags);
        assert_eq!(encode_flags(packet.flags), expected_flags);
        assert_eq!(packet.hops, case.expected.hops);
        assert_eq!(
            packet.flags.header_type.to_bits(),
            case.expected.header_type
        );
        assert_eq!(packet.flags.context_flag as u8, case.expected.context_flag);
        assert_eq!(
            packet.flags.transport_type.to_bits(),
            case.expected.transport_type
        );
        assert_eq!(
            packet.flags.destination_type.to_bits(),
            case.expected.destination_type
        );
        assert_eq!(
            packet.flags.packet_type.to_bits(),
            case.expected.packet_type
        );
        assert_eq!(packet.transport_id, expected_transport_id);
        assert_eq!(
            packet.destination_hash.as_bytes(),
            &expected_destination_hash
        );
        assert_eq!(packet.context, expected_context);
        assert_eq!(packet.data, expected_data.as_slice());

        let mut output = [0; RNS_MTU];
        let len = encode_packet(packet, &mut output)?;
        assert_eq!(&output[..len], raw_packet.as_slice());
    }

    Ok(())
}

#[test]
fn fixture_manifest_tracks_packet_header_vectors() -> Result<(), FixtureError> {
    let manifest = parse_manifest(MANIFEST)?;

    assert_manifest_entry(
        &manifest,
        "packet_header_vectors.json",
        "packet_header",
        2,
        FIXTURE,
    )?;
    Ok(())
}

fn decode_optional_transport_id(
    transport_id: &Option<String>,
) -> Result<Option<[u8; RNS_TRUNCATED_HASH_LEN]>, FixtureError> {
    let Some(transport_id) = transport_id else {
        return Ok(None);
    };

    Ok(Some(decode_hex_exact::<RNS_TRUNCATED_HASH_LEN>(
        transport_id,
    )?))
}
