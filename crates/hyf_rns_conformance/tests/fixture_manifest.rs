use hyf_rns_conformance::fixtures::{
    ExpectedManifestEntry, FixtureError, PROFILE_1_KISS_RNODE, PROFILE_2_CRYPTO_IFAC,
    assert_exact_manifest_entries, parse_manifest, parse_manifest_for_profile,
};

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
const PROFILE_1_MANIFEST: &str =
    include_str!("../../../fixtures/rns/profile_1_kiss_rnode/manifest.json");
const PROFILE_2_MANIFEST: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/manifest.json");

#[test]
fn fixture_manifest_tracks_exact_profile_0_fixture_set() -> Result<(), FixtureError> {
    let manifest = parse_manifest(MANIFEST)?;

    assert_exact_manifest_entries(
        &manifest,
        &[
            ExpectedManifestEntry {
                file: "identity_vectors.json",
                category: "identity_signature",
                case_count: 1,
                contents: IDENTITY_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "destination_hash_vectors.json",
                category: "destination_hash",
                case_count: 6,
                contents: DESTINATION_HASH_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "packet_header_vectors.json",
                category: "packet_header",
                case_count: 2,
                contents: PACKET_HEADER_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "packet_hash_vectors.json",
                category: "packet_hash",
                case_count: 3,
                contents: PACKET_HASH_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "announce_vectors.json",
                category: "announce",
                case_count: 2,
                contents: ANNOUNCE_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "announce_negative_vectors.json",
                category: "announce_negative",
                case_count: 8,
                contents: ANNOUNCE_NEGATIVE_FIXTURE,
            },
        ],
    )
}

#[test]
fn fixture_manifest_accepts_profile_1_shell() -> Result<(), FixtureError> {
    let manifest = parse_manifest_for_profile(PROFILE_1_MANIFEST, PROFILE_1_KISS_RNODE)?;

    assert_eq!(manifest.profile, PROFILE_1_KISS_RNODE);
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
fn fixture_manifest_accepts_profile_2_shell() -> Result<(), FixtureError> {
    let manifest = parse_manifest_for_profile(PROFILE_2_MANIFEST, PROFILE_2_CRYPTO_IFAC)?;

    assert_eq!(manifest.profile, PROFILE_2_CRYPTO_IFAC);
    assert_eq!(manifest.fixtures.len(), 7);
    Ok(())
}
