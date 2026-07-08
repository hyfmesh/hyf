use std::vec::Vec;

use hyf_link_kiss::{
    KISS_CMD_DATA, KissDecoder, KissError, encode_command_frame, encode_data_frame,
};
use hyf_rns_conformance::fixtures::{
    ExpectedManifestEntry, FixtureCasesFile, FixtureError, PROFILE_1_KISS_RNODE,
    assert_exact_manifest_entries, decode_hex, decode_hex_exact, parse_fixture_cases_for_profile,
    parse_manifest_for_profile,
};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../../../fixtures/rns/profile_1_kiss_rnode/manifest.json");
const KISS_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/kiss_vectors.json");
const KISS_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/kiss_negative_vectors.json");
const RNODE_COMMAND_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_command_vectors.json");
const RNODE_CONFIG_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_config_validation_vectors.json");
const RNODE_STAT_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/rnode_stat_vectors.json");

#[derive(Debug, Deserialize)]
struct KissVector {
    schema: String,
    profile: String,
    case_id: String,
    command_hex: String,
    payload_hex: String,
    encoded_hex: String,
    chunks_hex: Vec<String>,
    expected_frames: Vec<ExpectedFrame>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFrame {
    kind: String,
    command_hex: String,
    payload_hex: String,
}

#[derive(Debug, Deserialize)]
struct KissNegativeVector {
    schema: String,
    profile: String,
    case_id: String,
    chunks_hex: Vec<String>,
    decoder_capacity: usize,
    expected_error: String,
}

#[test]
fn profile_1_manifest_tracks_kiss_vectors() -> Result<(), FixtureError> {
    let manifest = parse_manifest_for_profile(MANIFEST, PROFILE_1_KISS_RNODE)?;

    assert_exact_manifest_entries(
        &manifest,
        &[
            ExpectedManifestEntry {
                file: "kiss_vectors.json",
                category: "kiss",
                case_count: 3,
                contents: KISS_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "kiss_negative_vectors.json",
                category: "kiss_negative",
                case_count: 2,
                contents: KISS_NEGATIVE_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_command_vectors.json",
                category: "rnode_command",
                case_count: 6,
                contents: RNODE_COMMAND_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_config_validation_vectors.json",
                category: "rnode_config_validation",
                case_count: 3,
                contents: RNODE_CONFIG_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "rnode_stat_vectors.json",
                category: "rnode_stat",
                case_count: 6,
                contents: RNODE_STAT_FIXTURE,
            },
        ],
    )
}

#[test]
fn kiss_vectors_encode_and_stream_decode() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<KissVector> =
        parse_fixture_cases_for_profile(KISS_FIXTURE, PROFILE_1_KISS_RNODE)?;

    for case in fixture.cases {
        assert_kiss_case_fields(&case)?;
        let command = decode_hex_exact::<1>(&case.command_hex)?[0];
        let payload = decode_hex(&case.payload_hex)?;
        let expected_encoded = decode_hex(&case.encoded_hex)?;
        let mut encoded = vec![0; expected_encoded.len()];
        let encoded_len = if command == KISS_CMD_DATA {
            encode_data_frame(&payload, &mut encoded)?
        } else {
            encode_command_frame(command, &payload, &mut encoded)?
        };
        let frames = decode_chunks::<64>(&case.chunks_hex)?;

        assert_eq!(&encoded[..encoded_len], expected_encoded);
        assert_eq!(frames.len(), case.expected_frames.len());
        for (actual, expected) in frames.iter().zip(case.expected_frames.iter()) {
            let expected_command = decode_hex_exact::<1>(&expected.command_hex)?[0];
            let expected_payload = decode_hex(&expected.payload_hex)?;
            let expected_kind = if expected_command == KISS_CMD_DATA {
                "data"
            } else {
                "command"
            };

            assert_eq!(expected.kind, expected_kind);
            assert_eq!(actual.0, expected_command);
            assert_eq!(actual.1, expected_payload);
        }
    }

    Ok(())
}

#[test]
fn kiss_negative_vectors_fail_closed() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<KissNegativeVector> =
        parse_fixture_cases_for_profile(KISS_NEGATIVE_FIXTURE, PROFILE_1_KISS_RNODE)?;

    for case in fixture.cases {
        assert_eq!(case.schema, "hyf.rns.kiss_negative_vector.v1");
        assert_eq!(case.profile, PROFILE_1_KISS_RNODE);
        let result = match case.decoder_capacity {
            3 => decode_chunks::<3>(&case.chunks_hex),
            64 => decode_chunks::<64>(&case.chunks_hex),
            other => {
                return Err(FixtureError::UnexpectedFixtureValue {
                    field: "decoder_capacity".to_owned(),
                    value: other.to_string(),
                });
            }
        };

        match result {
            Ok(_) => {
                return Err(FixtureError::UnexpectedFixtureValue {
                    field: "case_id".to_owned(),
                    value: case.case_id,
                });
            }
            Err(FixtureError::Kiss(error)) => {
                assert_eq!(kiss_error_code(error), case.expected_error);
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn decode_chunks<const N: usize>(
    chunks_hex: &[String],
) -> Result<Vec<(u8, Vec<u8>)>, FixtureError> {
    let mut frames = Vec::new();
    let mut decoder = KissDecoder::<N>::new();
    for chunk_hex in chunks_hex {
        let chunk = decode_hex(chunk_hex)?;
        decoder.push_bytes(&chunk, |frame| {
            frames.push((frame.command(), frame.payload().to_vec()));
            Ok(())
        })?;
    }
    Ok(frames)
}

fn assert_kiss_case_fields(case: &KissVector) -> Result<(), FixtureError> {
    assert_eq!(case.schema, "hyf.rns.kiss_vector.v1");
    assert_eq!(case.profile, PROFILE_1_KISS_RNODE);
    match case.case_id.as_str() {
        "kiss.data.no_escape_001"
        | "kiss.data.escapes_fend_fesc_001"
        | "kiss.command.ready_empty_001" => Ok(()),
        other => Err(FixtureError::UnexpectedFixtureValue {
            field: "case_id".to_owned(),
            value: other.to_owned(),
        }),
    }
}

fn kiss_error_code(error: KissError) -> &'static str {
    match error {
        KissError::EncodedLengthOverflow => "encoded_length_overflow",
        KissError::OutputBufferTooShort { .. } => "output_buffer_too_short",
        KissError::FrameTooLarge { .. } => "frame_too_large",
        KissError::MalformedEscape { .. } => "malformed_escape",
    }
}
