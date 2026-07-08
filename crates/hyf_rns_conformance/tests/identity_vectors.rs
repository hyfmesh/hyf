use hyf_rns_conformance::fixtures::{
    FixtureError, FixtureFile, assert_manifest_entry, decode_hex, decode_hex_exact,
    parse_fixture_case, parse_manifest,
};
use hyf_rns_crypto::{
    RNS_PUBLIC_IDENTITY_LEN, RNS_SECRET_IDENTITY_LEN, identity_hash, public_identity_from_bytes,
    public_identity_to_bytes, secret_identity_from_bytes, sign, verify,
};
use serde::Deserialize;

const FIXTURE: &str = include_str!("../../../fixtures/rns/identity_vectors.json");
const MANIFEST: &str = include_str!("../../../fixtures/rns/manifest.json");

#[derive(Debug, Deserialize)]
struct FixtureCase {
    id: String,
    category: String,
    deterministic: bool,
    private_test_material: bool,
    inputs: FixtureInputs,
    expected: FixtureExpected,
}

#[derive(Debug, Deserialize)]
struct FixtureInputs {
    secret_identity: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    public_identity: String,
    identity_hash: String,
    signature: String,
}

#[test]
fn identity_fixture_matches_reticulum_oracle() -> Result<(), FixtureError> {
    let fixture: FixtureFile<FixtureCase> = parse_fixture_case(FIXTURE)?;
    let case = fixture.case;

    assert_eq!(
        case.id,
        "profile_0_packet_announce.identity_signature.synthetic.0001"
    );
    assert_eq!(case.category, "identity_signature");
    assert!(case.deterministic);
    assert!(case.private_test_material);

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

    assert_eq!(public_identity_to_bytes(&derived_public), public_identity);
    assert_eq!(derived_public, oracle_public);
    assert_eq!(
        identity_hash(&oracle_public).into_bytes(),
        identity_hash_bytes
    );
    assert_eq!(sign(&secret, &message)?, signature);
    assert_eq!(verify(&oracle_public, &message, &signature), Ok(()));

    Ok(())
}

#[test]
fn fixture_manifest_tracks_identity_vector() -> Result<(), FixtureError> {
    let manifest = parse_manifest(MANIFEST)?;

    assert_manifest_entry(
        &manifest,
        "identity_vectors.json",
        "identity_signature",
        1,
        FIXTURE,
    )?;
    Ok(())
}
