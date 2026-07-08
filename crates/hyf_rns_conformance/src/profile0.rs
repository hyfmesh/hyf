use std::collections::BTreeSet;
#[cfg(feature = "python_oracle")]
use std::path::{Path, PathBuf};
#[cfg(feature = "python_oracle")]
use std::process::Command;

#[cfg(feature = "python_oracle")]
use hyf_rns_core::RnsDestinationHash;
use hyf_rns_core::{
    RNS_MTU, RNS_NAME_HASH_LEN, RNS_TRUNCATED_HASH_LEN, RnsIdentityHash, destination_hash,
    destination_name_hash,
};
use hyf_rns_crypto::{
    RNS_PUBLIC_IDENTITY_LEN, RNS_SECRET_IDENTITY_LEN, identity_hash, public_identity_from_bytes,
    public_identity_to_bytes, secret_identity_from_bytes, sign, verify,
};
use hyf_rns_wire::{
    RNS_ANNOUNCE_RANDOM_HASH_LEN, RNS_ANNOUNCE_RATCHET_LEN, RNS_ANNOUNCE_SIGNATURE_LEN,
    RnsWireError, build_announce_signed_data, decode_packet, encode_flags, encode_packet,
    packet_hash, packet_truncated_hash, validate_announce_packet, write_packet_hashable_part,
};
#[cfg(feature = "python_oracle")]
use hyf_rns_wire::{
    RNS_CONTEXT_NONE, RNS_CONTEXT_PATH_RESPONSE, RnsAnnounceEncodeParams, RnsClock,
    RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketRef, RnsPacketType,
    RnsTransportType, encode_announce_packet,
};
#[cfg(feature = "python_oracle")]
use rand_core::{Infallible, TryRng};
use serde::Deserialize;

use crate::fixtures::{
    ExpectedManifestEntry, FixtureError, FixtureFile, assert_exact_manifest_entries, decode_hex,
    decode_hex_exact, decode_optional_hex_exact, parse_fixture_case, parse_fixture_cases,
    parse_manifest,
};
use crate::report::{ConformanceEnvironment, ConformanceResult, ConformanceRun};
#[cfg(feature = "python_oracle")]
use crate::runner::{failed_result, passed_result};
use crate::runner::{fixture_result, invalid_environment_result};
#[cfg(feature = "python_oracle")]
use crate::{
    OracleInvalidEnvironment, OracleStatus, PINNED_CRYPTOGRAPHY_PACKAGE, PINNED_PYSERIAL_PACKAGE,
    check_oracle_environment,
};

pub const CATEGORY_FIXTURE_MANIFEST: &str = "fixture_manifest";
pub const CATEGORY_IDENTITY_SIGNATURE: &str = "identity_signature";
pub const CATEGORY_DESTINATION_HASH: &str = "destination_hash";
pub const CATEGORY_PACKET_HEADER: &str = "packet_header";
pub const CATEGORY_PACKET_HASH: &str = "packet_hash";
pub const CATEGORY_ANNOUNCE: &str = "announce";
pub const CATEGORY_ANNOUNCE_NEGATIVE: &str = "announce_negative";
pub const CATEGORY_PYTHON_ORACLE_PACKET: &str = "python_oracle_packet";
pub const CATEGORY_PYTHON_ORACLE_ANNOUNCE: &str = "python_oracle_announce";

pub const RESULT_ID_FIXTURE_MANIFEST: &str = "profile_0_packet_announce.fixture_manifest";
pub const RESULT_ID_IDENTITY_SIGNATURE: &str = "profile_0_packet_announce.identity_signature";
pub const RESULT_ID_DESTINATION_HASH: &str = "profile_0_packet_announce.destination_hash";
pub const RESULT_ID_PACKET_HEADER: &str = "profile_0_packet_announce.packet_header";
pub const RESULT_ID_PACKET_HASH: &str = "profile_0_packet_announce.packet_hash";
pub const RESULT_ID_ANNOUNCE: &str = "profile_0_packet_announce.announce";
pub const RESULT_ID_ANNOUNCE_NEGATIVE: &str = "profile_0_packet_announce.announce_negative";
pub const RESULT_ID_PYTHON_ORACLE_PACKET: &str = "profile_0_packet_announce.python_oracle.packet";
pub const RESULT_ID_PYTHON_ORACLE_ANNOUNCE: &str =
    "profile_0_packet_announce.python_oracle.announce";

pub const REQUIRED_PROFILE_0_RESULTS: &[(&str, &str)] = &[
    (RESULT_ID_FIXTURE_MANIFEST, CATEGORY_FIXTURE_MANIFEST),
    (RESULT_ID_IDENTITY_SIGNATURE, CATEGORY_IDENTITY_SIGNATURE),
    (RESULT_ID_DESTINATION_HASH, CATEGORY_DESTINATION_HASH),
    (RESULT_ID_PACKET_HEADER, CATEGORY_PACKET_HEADER),
    (RESULT_ID_PACKET_HASH, CATEGORY_PACKET_HASH),
    (RESULT_ID_ANNOUNCE, CATEGORY_ANNOUNCE),
    (RESULT_ID_ANNOUNCE_NEGATIVE, CATEGORY_ANNOUNCE_NEGATIVE),
    (
        RESULT_ID_PYTHON_ORACLE_PACKET,
        CATEGORY_PYTHON_ORACLE_PACKET,
    ),
    (
        RESULT_ID_PYTHON_ORACLE_ANNOUNCE,
        CATEGORY_PYTHON_ORACLE_ANNOUNCE,
    ),
];

pub const REQUIRED_PROFILE_0_RESULT_CATEGORIES: &[&str] = &[
    CATEGORY_FIXTURE_MANIFEST,
    CATEGORY_IDENTITY_SIGNATURE,
    CATEGORY_DESTINATION_HASH,
    CATEGORY_PACKET_HEADER,
    CATEGORY_PACKET_HASH,
    CATEGORY_ANNOUNCE,
    CATEGORY_ANNOUNCE_NEGATIVE,
    CATEGORY_PYTHON_ORACLE_PACKET,
    CATEGORY_PYTHON_ORACLE_ANNOUNCE,
];

const IDENTITY_FIXTURE: &str = include_str!("../../../fixtures/rns/identity_vectors.json");
const DESTINATION_HASH_FIXTURE: &str =
    include_str!("../../../fixtures/rns/destination_hash_vectors.json");
const PACKET_HEADER_FIXTURE: &str =
    include_str!("../../../fixtures/rns/packet_header_vectors.json");
const PACKET_HASH_FIXTURE: &str = include_str!("../../../fixtures/rns/packet_hash_vectors.json");
const ANNOUNCE_FIXTURE: &str = include_str!("../../../fixtures/rns/announce_vectors.json");
const ANNOUNCE_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/announce_negative_vectors.json");
const MANIFEST: &str = include_str!("../../../fixtures/rns/manifest.json");

pub fn profile_0_results() -> Vec<ConformanceResult> {
    let mut results = profile_0_fixture_results();
    results.extend(profile_0_oracle_unavailable_results());
    results
}

pub fn profile_0_fixture_results() -> Vec<ConformanceResult> {
    vec![
        fixture_result(
            RESULT_ID_FIXTURE_MANIFEST,
            CATEGORY_FIXTURE_MANIFEST,
            validate_fixture_manifest(),
        ),
        fixture_result(
            RESULT_ID_IDENTITY_SIGNATURE,
            CATEGORY_IDENTITY_SIGNATURE,
            validate_identity_fixture(),
        ),
        fixture_result(
            RESULT_ID_DESTINATION_HASH,
            CATEGORY_DESTINATION_HASH,
            validate_destination_hash_fixtures(),
        ),
        fixture_result(
            RESULT_ID_PACKET_HEADER,
            CATEGORY_PACKET_HEADER,
            validate_packet_header_fixtures(),
        ),
        fixture_result(
            RESULT_ID_PACKET_HASH,
            CATEGORY_PACKET_HASH,
            validate_packet_hash_fixtures(),
        ),
        fixture_result(
            RESULT_ID_ANNOUNCE,
            CATEGORY_ANNOUNCE,
            validate_announce_fixtures(),
        ),
        fixture_result(
            RESULT_ID_ANNOUNCE_NEGATIVE,
            CATEGORY_ANNOUNCE_NEGATIVE,
            validate_announce_negative_fixtures(),
        ),
    ]
}

pub fn profile_0_oracle_unavailable_results() -> [ConformanceResult; 2] {
    [
        invalid_environment_result(
            RESULT_ID_PYTHON_ORACLE_PACKET,
            CATEGORY_PYTHON_ORACLE_PACKET,
            "python_oracle feature is not enabled for this report generator",
        ),
        invalid_environment_result(
            RESULT_ID_PYTHON_ORACLE_ANNOUNCE,
            CATEGORY_PYTHON_ORACLE_ANNOUNCE,
            "python_oracle feature is not enabled for this report generator",
        ),
    ]
}

pub fn profile_0_report(
    run_id: impl Into<String>,
    hyf_commit: impl Into<String>,
    started_at: impl Into<String>,
    environment: ConformanceEnvironment,
) -> ConformanceRun {
    ConformanceRun::profile_0(
        run_id,
        hyf_commit,
        started_at,
        environment,
        profile_0_results(),
    )
}

#[cfg(feature = "python_oracle")]
pub fn profile_0_report_with_required_oracle(
    run_id: impl Into<String>,
    hyf_commit: impl Into<String>,
    started_at: impl Into<String>,
    environment: ConformanceEnvironment,
    reticulum_path: &Path,
) -> Result<ConformanceRun, Profile0OracleError> {
    let readiness = check_oracle_environment(Some(reticulum_path));
    if readiness.status() != OracleStatus::Passed {
        return Err(Profile0OracleError::InvalidEnvironment(readiness.reason()));
    }
    let Some(metadata) = readiness.metadata().cloned() else {
        return Err(Profile0OracleError::MissingOracleMetadata);
    };
    let oracle_path = oracle_python_path(&metadata.reticulum_module_path, reticulum_path);

    let mut results = profile_0_fixture_results();
    results.extend(profile_0_oracle_results(oracle_path.as_path()));
    Ok(ConformanceRun::profile_0(
        run_id,
        hyf_commit,
        started_at,
        environment.with_oracle(metadata.into()),
        results,
    ))
}

#[cfg(feature = "python_oracle")]
fn oracle_python_path(reticulum_module_path: &str, fallback: &Path) -> PathBuf {
    let module_path = Path::new(reticulum_module_path);
    if let Some(rns_dir) = module_path.parent()
        && let Some(reticulum_root) = rns_dir.parent()
    {
        return reticulum_root.to_path_buf();
    }

    fallback.to_path_buf()
}

#[cfg(feature = "python_oracle")]
pub fn profile_0_oracle_results(reticulum_path: &Path) -> [ConformanceResult; 2] {
    match run_profile_0_oracle(reticulum_path) {
        Ok(response) => [
            packet_oracle_result(&response),
            announce_oracle_result(response.announce_valid),
        ],
        Err(error) => [
            failed_result(
                RESULT_ID_PYTHON_ORACLE_PACKET,
                CATEGORY_PYTHON_ORACLE_PACKET,
                error.to_string(),
            ),
            failed_result(
                RESULT_ID_PYTHON_ORACLE_ANNOUNCE,
                CATEGORY_PYTHON_ORACLE_ANNOUNCE,
                error.to_string(),
            ),
        ],
    }
}

pub fn required_categories_are_present(results: &[ConformanceResult]) -> bool {
    let categories: BTreeSet<&str> = results
        .iter()
        .map(|result| result.category.as_str())
        .collect();
    REQUIRED_PROFILE_0_RESULT_CATEGORIES
        .iter()
        .all(|category| categories.contains(category))
}

#[cfg(feature = "python_oracle")]
fn packet_oracle_result(response: &OracleResponse) -> ConformanceResult {
    let packet_passed = response.header_1.unpack_ok
        && response.header_1.header_type == 0
        && response.header_1.transport_id.is_none()
        && response.header_1.destination_hash == "11111111111111111111111111111111"
        && response.header_1.context == RNS_CONTEXT_NONE
        && response.header_1.data == "6865616465722d6f6e65"
        && response.header_2.unpack_ok
        && response.header_2.header_type == 1
        && response.header_2.transport_id.as_deref() == Some("22222222222222222222222222222222")
        && response.header_2.destination_hash == "33333333333333333333333333333333"
        && response.header_2.context == RNS_CONTEXT_PATH_RESPONSE
        && response.header_2.data == "6865616465722d74776f";

    if packet_passed {
        return passed_result(
            RESULT_ID_PYTHON_ORACLE_PACKET,
            CATEGORY_PYTHON_ORACLE_PACKET,
        );
    }

    failed_result(
        RESULT_ID_PYTHON_ORACLE_PACKET,
        CATEGORY_PYTHON_ORACLE_PACKET,
        "python oracle packet validation mismatch",
    )
}

#[cfg(feature = "python_oracle")]
fn announce_oracle_result(announce_valid: bool) -> ConformanceResult {
    if announce_valid {
        return passed_result(
            RESULT_ID_PYTHON_ORACLE_ANNOUNCE,
            CATEGORY_PYTHON_ORACLE_ANNOUNCE,
        );
    }

    failed_result(
        RESULT_ID_PYTHON_ORACLE_ANNOUNCE,
        CATEGORY_PYTHON_ORACLE_ANNOUNCE,
        "python oracle rejected Rust-generated announce",
    )
}

#[cfg(feature = "python_oracle")]
fn run_profile_0_oracle(reticulum_path: &Path) -> Result<OracleResponse, Profile0OracleError> {
    let header_1_packet = encode_oracle_header_1_packet()?;
    let header_2_packet = encode_oracle_header_2_packet()?;
    let full_hash = packet_hash(&header_2_packet)?.into_bytes();
    let truncated_hash = packet_truncated_hash(&header_2_packet)?.into_bytes();
    let announce_packet = encode_oracle_announce()?;
    let request = OracleRequest {
        header_1_packet: hex(&header_1_packet),
        header_2_packet: hex(&header_2_packet),
        hash_packet: hex(&header_2_packet),
        expected_full_hash: hex(&full_hash),
        expected_truncated_hash: hex(&truncated_hash),
        announce_packet: hex(&announce_packet),
    };
    let request_json = serde_json::to_string(&request)?;
    let output = Command::new("uv")
        .arg("run")
        .arg("--with")
        .arg(PINNED_CRYPTOGRAPHY_PACKAGE)
        .arg("--with")
        .arg(PINNED_PYSERIAL_PACKAGE)
        .arg("python")
        .arg("-c")
        .arg(PYTHON_ORACLE_SCRIPT)
        .arg(request_json)
        .env("PYTHONPATH", reticulum_path)
        .output()?;

    if !output.status.success() {
        return Err(Profile0OracleError::OracleFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(feature = "python_oracle")]
fn encode_oracle_header_1_packet() -> Result<Vec<u8>, RnsWireError> {
    let data = b"header-one";
    let mut output = [0; RNS_MTU];
    let len = encode_packet(
        RnsPacketRef {
            flags: RnsPacketFlags {
                header_type: RnsHeaderType::Header1,
                context_flag: false,
                transport_type: RnsTransportType::Broadcast,
                destination_type: RnsDestinationType::Single,
                packet_type: RnsPacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: RnsDestinationHash::new([0x11; RNS_TRUNCATED_HASH_LEN]),
            context: RNS_CONTEXT_NONE,
            data,
        },
        &mut output,
    )?;

    Ok(output[..len].to_vec())
}

#[cfg(feature = "python_oracle")]
fn encode_oracle_header_2_packet() -> Result<Vec<u8>, RnsWireError> {
    let data = b"header-two";
    let mut output = [0; RNS_MTU];
    let len = encode_packet(
        RnsPacketRef {
            flags: RnsPacketFlags {
                header_type: RnsHeaderType::Header2,
                context_flag: true,
                transport_type: RnsTransportType::Transport,
                destination_type: RnsDestinationType::Group,
                packet_type: RnsPacketType::Announce,
            },
            hops: 0,
            transport_id: Some([0x22; RNS_TRUNCATED_HASH_LEN]),
            destination_hash: RnsDestinationHash::new([0x33; RNS_TRUNCATED_HASH_LEN]),
            context: RNS_CONTEXT_PATH_RESPONSE,
            data,
        },
        &mut output,
    )?;

    Ok(output[..len].to_vec())
}

#[cfg(feature = "python_oracle")]
fn encode_oracle_announce() -> Result<Vec<u8>, Profile0OracleError> {
    let secret = secret_identity_from_bytes(&TEST_SECRET_IDENTITY)?;
    let public_identity = secret.public_identity()?;
    let aspects = ["announce"];
    let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
    let clock = FixedClock(0x01_0203_0405);
    let mut output = [0; RNS_MTU];
    let len = encode_announce_packet(
        RnsAnnounceEncodeParams {
            secret_identity: &secret,
            public_identity,
            app_name: "hyf",
            aspects: &aspects,
            app_data: b"oracle-app-data",
        },
        &mut rng,
        &clock,
        &mut output,
    )?;

    Ok(output[..len].to_vec())
}

fn validate_fixture_manifest() -> Result<(), FixtureError> {
    let manifest = parse_manifest(MANIFEST)?;

    assert_exact_manifest_entries(
        &manifest,
        &[
            ExpectedManifestEntry {
                file: "identity_vectors.json",
                category: CATEGORY_IDENTITY_SIGNATURE,
                case_count: 1,
                contents: IDENTITY_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "destination_hash_vectors.json",
                category: CATEGORY_DESTINATION_HASH,
                case_count: 6,
                contents: DESTINATION_HASH_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "packet_header_vectors.json",
                category: CATEGORY_PACKET_HEADER,
                case_count: 2,
                contents: PACKET_HEADER_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "packet_hash_vectors.json",
                category: CATEGORY_PACKET_HASH,
                case_count: 3,
                contents: PACKET_HASH_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "announce_vectors.json",
                category: CATEGORY_ANNOUNCE,
                case_count: 2,
                contents: ANNOUNCE_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "announce_negative_vectors.json",
                category: CATEGORY_ANNOUNCE_NEGATIVE,
                case_count: 8,
                contents: ANNOUNCE_NEGATIVE_FIXTURE,
            },
        ],
    )
}

fn validate_identity_fixture() -> Result<(), FixtureError> {
    let fixture: FixtureFile<IdentityCase> = parse_fixture_case(IDENTITY_FIXTURE)?;
    let case = fixture.case;

    if case.id != "profile_0_packet_announce.identity_signature.synthetic.0001" {
        return Err(FixtureError::UnexpectedFixtureValue {
            field: "id".to_owned(),
            value: case.id,
        });
    }
    validate_case_metadata(
        &case.category,
        CATEGORY_IDENTITY_SIGNATURE,
        case.deterministic,
        case.private_test_material,
    )?;

    let secret_identity =
        decode_hex_exact::<RNS_SECRET_IDENTITY_LEN>(&case.inputs.secret_identity)?;
    let public_identity =
        decode_hex_exact::<RNS_PUBLIC_IDENTITY_LEN>(&case.expected.public_identity)?;
    let identity_hash_bytes = decode_hex_exact::<16>(&case.expected.identity_hash)?;
    let signature = decode_hex_exact::<64>(&case.expected.signature)?;
    let message = decode_hex(&case.inputs.message)?;

    let secret = secret_identity_from_bytes(&secret_identity)?;
    let derived_public = secret.public_identity()?;
    let oracle_public = public_identity_from_bytes(&public_identity)?;

    if public_identity_to_bytes(&derived_public) != public_identity {
        return unexpected("public_identity", "derived public identity mismatch");
    }
    if derived_public != oracle_public {
        return unexpected("public_identity", "oracle public identity mismatch");
    }
    if identity_hash(&oracle_public).into_bytes() != identity_hash_bytes {
        return unexpected("identity_hash", "identity hash mismatch");
    }
    if sign(&secret, &message)? != signature {
        return unexpected("signature", "signature mismatch");
    }
    if verify(&oracle_public, &message, &signature) != Ok(()) {
        return unexpected("signature", "signature verify mismatch");
    }

    Ok(())
}

fn validate_destination_hash_fixtures() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<DestinationHashCase>(DESTINATION_HASH_FIXTURE)?;
    if fixture.cases.len() != 6 {
        return unexpected("case_count", "destination hash fixture case count mismatch");
    }

    let mut plain_cases = 0;
    let mut identity_bound_cases = 0;
    for case in fixture.cases {
        validate_case_metadata(
            &case.category,
            CATEGORY_DESTINATION_HASH,
            case.deterministic,
            case.private_test_material,
        )?;
        if !case
            .id
            .starts_with("profile_0_packet_announce.destination_hash.synthetic.")
        {
            return Err(FixtureError::UnexpectedFixtureValue {
                field: "id".to_owned(),
                value: case.id,
            });
        }
        if expanded_destination_name(&case.inputs.app_name, &case.inputs.aspects)
            != case.expected.expanded_name
        {
            return unexpected("expanded_name", "destination expanded name mismatch");
        }

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
        if name_hash.as_bytes() != &expected_name_hash {
            return unexpected("name_hash", "destination name hash mismatch");
        }
        if destination_hash(name_hash, identity_hash).as_bytes() != &expected_destination_hash {
            return unexpected("destination_hash", "destination hash mismatch");
        }
    }

    if plain_cases != 3 || identity_bound_cases != 3 {
        return unexpected("case_mix", "destination hash fixture case mix mismatch");
    }

    Ok(())
}

fn validate_packet_header_fixtures() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<PacketHeaderCase>(PACKET_HEADER_FIXTURE)?;
    if fixture.cases.len() != 2 {
        return unexpected("case_count", "packet header fixture case count mismatch");
    }

    for case in fixture.cases {
        validate_case_metadata(
            &case.category,
            CATEGORY_PACKET_HEADER,
            case.deterministic,
            case.private_test_material,
        )?;
        if !case
            .id
            .starts_with("profile_0_packet_announce.packet_header.synthetic.")
        {
            return Err(FixtureError::UnexpectedFixtureValue {
                field: "id".to_owned(),
                value: case.id,
            });
        }
        if case.inputs.description != "synthetic Reticulum Packet.pack() header vector" {
            return unexpected("description", "packet header description mismatch");
        }

        let raw_packet = decode_hex(&case.expected.raw_packet)?;
        let packet = decode_packet(&raw_packet)?;
        let expected_flags = decode_hex_exact::<1>(&case.expected.flags)?[0];
        let expected_context = decode_hex_exact::<1>(&case.expected.context)?[0];
        let expected_destination_hash =
            decode_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.destination_hash)?;
        let expected_data = decode_hex(&case.expected.data)?;
        let expected_transport_id = decode_optional_transport_id(&case.expected.transport_id)?;

        if raw_packet.first().copied() != Some(expected_flags)
            || encode_flags(packet.flags) != expected_flags
            || packet.hops != case.expected.hops
            || packet.flags.header_type.to_bits() != case.expected.header_type
            || packet.flags.context_flag as u8 != case.expected.context_flag
            || packet.flags.transport_type.to_bits() != case.expected.transport_type
            || packet.flags.destination_type.to_bits() != case.expected.destination_type
            || packet.flags.packet_type.to_bits() != case.expected.packet_type
            || packet.transport_id != expected_transport_id
            || packet.destination_hash.as_bytes() != &expected_destination_hash
            || packet.context != expected_context
            || packet.data != expected_data.as_slice()
        {
            return unexpected("packet_header", "packet header fixture mismatch");
        }

        let mut output = [0; RNS_MTU];
        let len = encode_packet(packet, &mut output)?;
        if &output[..len] != raw_packet.as_slice() {
            return unexpected("raw_packet", "packet re-encode mismatch");
        }
    }

    Ok(())
}

fn validate_packet_hash_fixtures() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<PacketHashCase>(PACKET_HASH_FIXTURE)?;
    if fixture.cases.len() != 3 {
        return unexpected("case_count", "packet hash fixture case count mismatch");
    }

    let mut header_2_transport_proof: Option<Header2TransportProof> = None;
    for case in fixture.cases {
        validate_case_metadata(
            &case.category,
            CATEGORY_PACKET_HASH,
            case.deterministic,
            case.private_test_material,
        )?;
        if !case
            .id
            .starts_with("profile_0_packet_announce.packet_hash.synthetic.")
        {
            return Err(FixtureError::UnexpectedFixtureValue {
                field: "id".to_owned(),
                value: case.id,
            });
        }
        if case.inputs.description != "synthetic Reticulum Packet hash vector" {
            return unexpected("description", "packet hash description mismatch");
        }

        let raw_packet = decode_hex(&case.expected.raw_packet)?;
        let expected_hashable_part = decode_hex(&case.expected.hashable_part)?;
        let expected_full_hash = decode_hex_exact::<32>(&case.expected.full_hash)?;
        let expected_truncated_hash =
            decode_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.truncated_hash)?;
        let expected_transport_id =
            decode_optional_hex_exact::<RNS_TRUNCATED_HASH_LEN>(&case.expected.transport_id)?;
        let mut hashable_part = [0; RNS_MTU];
        let hashable_len = write_packet_hashable_part(&raw_packet, &mut hashable_part)?;

        if &hashable_part[..hashable_len] != expected_hashable_part.as_slice()
            || packet_hash(&raw_packet)?.into_bytes() != expected_full_hash
            || packet_truncated_hash(&raw_packet)?.into_bytes() != expected_truncated_hash
        {
            return unexpected("packet_hash", "packet hash fixture mismatch");
        }

        if let Some(transport_id) = expected_transport_id {
            let proof = Header2TransportProof {
                transport_id,
                hashable_part: expected_hashable_part,
                full_hash: expected_full_hash,
                truncated_hash: expected_truncated_hash,
            };
            if let Some(previous) = &header_2_transport_proof {
                if previous.transport_id == proof.transport_id
                    || previous.hashable_part != proof.hashable_part
                    || previous.full_hash != proof.full_hash
                    || previous.truncated_hash != proof.truncated_hash
                {
                    return unexpected("packet_hash", "header 2 transport hash proof mismatch");
                }
            } else {
                header_2_transport_proof = Some(proof);
            }
        }
    }

    Ok(())
}

fn validate_announce_fixtures() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<AnnounceCase>(ANNOUNCE_FIXTURE)?;
    if fixture.cases.len() != 2 {
        return unexpected("case_count", "announce fixture case count mismatch");
    }

    for case in fixture.cases {
        validate_case_metadata(
            &case.category,
            CATEGORY_ANNOUNCE,
            case.deterministic,
            case.private_test_material,
        )?;
        if !case
            .id
            .starts_with("profile_0_packet_announce.announce.synthetic.")
        {
            return Err(FixtureError::UnexpectedFixtureValue {
                field: "id".to_owned(),
                value: case.id,
            });
        }
        if decode_hex(&case.inputs.secret_identity)? != (0u8..64).collect::<Vec<_>>()
            || case.inputs.app_name != "hyf"
            || case.inputs.aspects != vec!["announce".to_owned()]
            || case.inputs.app_data != case.expected.app_data
            || case.inputs.random_hash != case.expected.random_hash
        {
            return unexpected("announce_inputs", "announce input fixture mismatch");
        }

        let raw_packet = decode_hex(&case.expected.raw_packet)?;
        let packet = decode_packet(&raw_packet)?;
        let context_flag = packet.flags.context_flag as u8;
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

        if context_flag != case.expected.context_flag
            || announce.destination_hash.as_bytes() != &expected_destination_hash
            || announce.public_identity != expected_public_identity
            || announce.name_hash.as_bytes() != &expected_name_hash
            || announce.random_hash != expected_random_hash
            || announce.ratchet != expected_ratchet
            || announce.signature != expected_signature
            || announce.app_data != expected_app_data.as_slice()
            || &signed_data[..RNS_TRUNCATED_HASH_LEN] != announce.destination_hash.as_bytes()
            || !signed_data_suffix_matches(
                &signed_data,
                signed_data_len,
                expected_app_data.as_slice(),
            )
        {
            return unexpected("announce", "announce fixture mismatch");
        }
    }

    Ok(())
}

fn validate_announce_negative_fixtures() -> Result<(), FixtureError> {
    let fixture = parse_fixture_cases::<AnnounceNegativeCase>(ANNOUNCE_NEGATIVE_FIXTURE)?;
    if fixture.cases.len() != 8 {
        return unexpected(
            "case_count",
            "negative announce fixture case count mismatch",
        );
    }

    for case in fixture.cases {
        validate_case_metadata(
            &case.category,
            CATEGORY_ANNOUNCE_NEGATIVE,
            case.deterministic,
            case.private_test_material,
        )?;
        if !case
            .id
            .starts_with("profile_0_packet_announce.announce_negative.synthetic.")
        {
            return Err(FixtureError::UnexpectedFixtureValue {
                field: "id".to_owned(),
                value: case.id,
            });
        }
        if ![
            "destination",
            "public_identity",
            "name_hash",
            "random_hash",
            "signature",
            "app_data",
            "destination_type",
            "context_flag",
        ]
        .contains(&case.mutation.as_str())
        {
            return Err(FixtureError::UnexpectedFixtureValue {
                field: "mutation".to_owned(),
                value: case.mutation,
            });
        }

        let raw_packet = decode_hex(&case.raw_packet)?;
        let packet = decode_packet(&raw_packet)?;
        if validate_announce_packet(packet) != Err(expected_wire_error(&case.expected_error)?) {
            return unexpected(
                "expected_error",
                "negative announce did not fail as expected",
            );
        }
    }

    Ok(())
}

fn validate_case_metadata(
    actual_category: &str,
    expected_category: &'static str,
    deterministic: bool,
    private_test_material: bool,
) -> Result<(), FixtureError> {
    if actual_category != expected_category {
        return Err(FixtureError::UnexpectedFixtureValue {
            field: "category".to_owned(),
            value: actual_category.to_owned(),
        });
    }
    if !deterministic {
        return unexpected("deterministic", "fixture case is not deterministic");
    }
    if private_test_material != category_uses_private_test_material(expected_category) {
        return unexpected(
            "private_test_material",
            "private test material flag mismatch",
        );
    }
    Ok(())
}

fn category_uses_private_test_material(category: &str) -> bool {
    matches!(
        category,
        CATEGORY_IDENTITY_SIGNATURE | CATEGORY_ANNOUNCE | CATEGORY_ANNOUNCE_NEGATIVE
    )
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

fn signed_data_suffix_matches(
    signed_data: &[u8],
    signed_data_len: usize,
    expected_suffix: &[u8],
) -> bool {
    let Some(suffix_start) = signed_data_len.checked_sub(expected_suffix.len()) else {
        return false;
    };

    signed_data.get(suffix_start..signed_data_len) == Some(expected_suffix)
}

fn expected_wire_error(error: &str) -> Result<RnsWireError, FixtureError> {
    match error {
        "DestinationMismatch" => Ok(RnsWireError::DestinationMismatch),
        "InvalidDestinationType" => Ok(RnsWireError::InvalidDestinationType),
        "InvalidSignature" => Ok(RnsWireError::InvalidSignature),
        "MalformedAnnounce" => Ok(RnsWireError::MalformedAnnounce),
        _ => Err(FixtureError::UnexpectedFixtureValue {
            field: "expected_error".to_owned(),
            value: error.to_owned(),
        }),
    }
}

fn expanded_destination_name(app_name: &str, aspects: &[String]) -> String {
    let mut name = app_name.to_owned();
    for aspect in aspects {
        name.push('.');
        name.push_str(aspect);
    }
    name
}

fn unexpected<T>(field: &str, value: &str) -> Result<T, FixtureError> {
    Err(FixtureError::UnexpectedFixtureValue {
        field: field.to_owned(),
        value: value.to_owned(),
    })
}

#[cfg(feature = "python_oracle")]
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(feature = "python_oracle")]
#[derive(Debug)]
pub enum Profile0OracleError {
    InvalidEnvironment(Option<OracleInvalidEnvironment>),
    MissingOracleMetadata,
    Io(String),
    Json(String),
    OracleFailed(String),
    Crypto(hyf_rns_crypto::RnsCryptoError),
    Wire(RnsWireError),
}

#[cfg(feature = "python_oracle")]
impl From<std::io::Error> for Profile0OracleError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[cfg(feature = "python_oracle")]
impl From<serde_json::Error> for Profile0OracleError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

#[cfg(feature = "python_oracle")]
impl From<hyf_rns_crypto::RnsCryptoError> for Profile0OracleError {
    fn from(error: hyf_rns_crypto::RnsCryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[cfg(feature = "python_oracle")]
impl From<RnsWireError> for Profile0OracleError {
    fn from(error: RnsWireError) -> Self {
        Self::Wire(error)
    }
}

#[cfg(feature = "python_oracle")]
impl std::fmt::Display for Profile0OracleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnvironment(Some(reason)) => {
                write!(formatter, "invalid oracle environment: {reason}")
            }
            Self::InvalidEnvironment(None) => formatter.write_str("invalid oracle environment"),
            Self::MissingOracleMetadata => formatter.write_str("missing oracle metadata"),
            Self::Io(error) | Self::Json(error) | Self::OracleFailed(error) => {
                formatter.write_str(error)
            }
            Self::Crypto(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
        }
    }
}

#[cfg(feature = "python_oracle")]
impl std::error::Error for Profile0OracleError {}

#[cfg(feature = "python_oracle")]
#[derive(serde::Serialize)]
struct OracleRequest {
    header_1_packet: String,
    header_2_packet: String,
    hash_packet: String,
    expected_full_hash: String,
    expected_truncated_hash: String,
    announce_packet: String,
}

#[cfg(feature = "python_oracle")]
#[derive(Deserialize)]
struct OracleResponse {
    header_1: OraclePacket,
    header_2: OraclePacket,
    announce_valid: bool,
}

#[cfg(feature = "python_oracle")]
#[derive(Deserialize)]
struct OraclePacket {
    unpack_ok: bool,
    header_type: u8,
    transport_id: Option<String>,
    destination_hash: String,
    context: u8,
    data: String,
}

#[cfg(feature = "python_oracle")]
struct FixedClock(u64);

#[cfg(feature = "python_oracle")]
impl RnsClock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        self.0
    }
}

#[cfg(feature = "python_oracle")]
struct FixedRng {
    bytes: [u8; 5],
    offset: usize,
}

#[cfg(feature = "python_oracle")]
impl FixedRng {
    const fn new(bytes: [u8; 5]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next_byte(&mut self) -> u8 {
        let byte = self.bytes[self.offset % self.bytes.len()];
        self.offset += 1;
        byte
    }
}

#[cfg(feature = "python_oracle")]
impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dst {
            *byte = self.next_byte();
        }
        Ok(())
    }
}

#[cfg(feature = "python_oracle")]
const TEST_SECRET_IDENTITY: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

#[cfg(feature = "python_oracle")]
pub const PYTHON_ORACLE_SCRIPT: &str = r#"
import json
import sys

import RNS

request = json.loads(sys.argv[1])

def packet_info(raw_hex):
    packet = RNS.Packet(None, bytes.fromhex(raw_hex))
    unpack_ok = packet.unpack()
    return {
        "unpack_ok": unpack_ok,
        "header_type": packet.header_type,
        "transport_id": None if packet.transport_id is None else packet.transport_id.hex(),
        "destination_hash": packet.destination_hash.hex(),
        "context": packet.context,
        "data": packet.data.hex(),
    }

hash_packet = RNS.Packet(None, bytes.fromhex(request["hash_packet"]))
if not hash_packet.unpack():
    raise RuntimeError("hash packet did not unpack")

announce_packet = RNS.Packet(None, bytes.fromhex(request["announce_packet"]))
if not announce_packet.unpack():
    raise RuntimeError("announce packet did not unpack")

response = {
    "header_1": packet_info(request["header_1_packet"]),
    "header_2": packet_info(request["header_2_packet"]),
    "full_hash": hash_packet.get_hash().hex(),
    "truncated_hash": hash_packet.getTruncatedHash().hex(),
    "announce_valid": RNS.Identity.validate_announce(announce_packet, only_validate_signature=False),
}

if response["full_hash"] != request["expected_full_hash"]:
    raise RuntimeError("full hash mismatch")
if response["truncated_hash"] != request["expected_truncated_hash"]:
    raise RuntimeError("truncated hash mismatch")

print(json.dumps(response, sort_keys=True))
"#;

#[derive(Debug, Deserialize)]
struct IdentityCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    inputs: IdentityInputs,
    expected: IdentityExpected,
}

#[derive(Debug, Deserialize)]
struct IdentityInputs {
    secret_identity: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct IdentityExpected {
    public_identity: String,
    identity_hash: String,
    signature: String,
}

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

struct Header2TransportProof {
    transport_id: [u8; RNS_TRUNCATED_HASH_LEN],
    hashable_part: Vec<u8>,
    full_hash: [u8; 32],
    truncated_hash: [u8; RNS_TRUNCATED_HASH_LEN],
}

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

#[cfg(test)]
mod tests {
    #[cfg(feature = "python_oracle")]
    use crate::report::ConformanceEnvironment;
    use crate::report::ConformanceStatus;

    use super::{
        REQUIRED_PROFILE_0_RESULT_CATEGORIES, profile_0_results, required_categories_are_present,
        signed_data_suffix_matches,
    };

    #[test]
    fn profile_0_results_include_every_required_category() {
        let results = profile_0_results();

        assert_eq!(results.len(), REQUIRED_PROFILE_0_RESULT_CATEGORIES.len());
        assert!(required_categories_are_present(&results));
    }

    #[test]
    fn default_profile_0_results_fail_only_on_oracle_environment() {
        let results = profile_0_results();
        let failed = results
            .iter()
            .filter(|result| result.status == ConformanceStatus::Failed)
            .count();
        let invalid_environment = results
            .iter()
            .filter(|result| result.status == ConformanceStatus::InvalidEnvironment)
            .count();

        assert_eq!(failed, 0);
        assert_eq!(invalid_environment, 2);
    }

    #[test]
    fn signed_data_suffix_check_rejects_short_lengths_without_panic() {
        assert!(signed_data_suffix_matches(&[1, 2, 3, 4], 4, &[3, 4]));
        assert!(!signed_data_suffix_matches(&[1, 2, 3, 4], 1, &[2, 3]));
        assert!(!signed_data_suffix_matches(&[1, 2, 3, 4], 8, &[3, 4]));
    }

    #[cfg(feature = "python_oracle")]
    #[test]
    fn oracle_error_display_uses_stable_first_party_error_text() {
        assert_eq!(
            super::Profile0OracleError::InvalidEnvironment(Some(
                crate::OracleInvalidEnvironment::OracleProbeFailed,
            ))
            .to_string(),
            "invalid oracle environment: oracle probe failed"
        );
        assert_eq!(
            super::Profile0OracleError::Wire(hyf_rns_wire::RnsWireError::InvalidSignature)
                .to_string(),
            "invalid signature"
        );
    }

    #[cfg(feature = "python_oracle")]
    #[test]
    fn required_oracle_report_has_no_invalid_environment_when_configured()
    -> Result<(), super::Profile0OracleError> {
        let Some(path) = std::env::var_os("HYF_RETICULUM_PATH").map(std::path::PathBuf::from)
        else {
            return Ok(());
        };
        let environment = ConformanceEnvironment::new("macos", "aarch64", "rustc 1.92.0");
        let report = super::profile_0_report_with_required_oracle(
            "profile0-test",
            "9e4615a",
            "2026-07-08T00:00:00Z",
            environment,
            path.as_path(),
        )?;

        assert!(required_categories_are_present(&report.results));
        assert!(report.environment.oracle.is_some());
        assert_eq!(
            report
                .results
                .iter()
                .filter(|result| result.status == ConformanceStatus::Failed)
                .count(),
            0
        );
        assert_eq!(
            report
                .results
                .iter()
                .filter(|result| result.status == ConformanceStatus::InvalidEnvironment)
                .count(),
            0
        );
        Ok(())
    }
}
