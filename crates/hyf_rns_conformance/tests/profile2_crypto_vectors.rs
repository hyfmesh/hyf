use hyf_rns_conformance::fixtures::{
    ExpectedManifestEntry, FixtureCasesFile, FixtureError, PROFILE_2_CRYPTO_IFAC,
    assert_exact_manifest_entries, decode_hex, decode_hex_exact, parse_fixture_cases_for_profile,
    parse_manifest_for_profile,
};
use hyf_rns_crypto::{
    RNS_TOKEN_IV_LEN, RnsCryptoError, rns_hkdf_sha256, token_decrypt, token_encrypt_with_iv,
};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../../../fixtures/rns/profile_2_crypto_ifac/manifest.json");
const HKDF_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/hkdf_vectors.json");
const TOKEN_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/token_vectors.json");
const TOKEN_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/token_negative_vectors.json");

#[derive(Debug, Deserialize)]
struct CryptoVector {
    schema: String,
    profile: String,
    subprofile: String,
    case_id: String,
    determinism: Determinism,
    inputs: CryptoInputs,
    expected: CryptoExpected,
}

#[derive(Debug, Deserialize)]
struct Determinism {
    mode: String,
    test_only_secret_material: bool,
}

#[derive(Debug, Deserialize)]
struct CryptoInputs {
    ikm_hex: Option<String>,
    salt_hex: Option<String>,
    context_hex: Option<String>,
    length: Option<usize>,
    key_hex: Option<String>,
    iv_hex: Option<String>,
    plaintext_hex: Option<String>,
    token_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CryptoExpected {
    okm_hex: Option<String>,
    token_hex: Option<String>,
    error: Option<String>,
    valid: bool,
}

#[test]
fn profile_2_manifest_tracks_crypto_vectors() -> Result<(), FixtureError> {
    let manifest = parse_manifest_for_profile(MANIFEST, PROFILE_2_CRYPTO_IFAC)?;

    assert_exact_manifest_entries(
        &manifest,
        &[
            ExpectedManifestEntry {
                file: "hkdf_vectors.json",
                category: "hkdf",
                case_count: 1,
                contents: HKDF_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "token_vectors.json",
                category: "token",
                case_count: 1,
                contents: TOKEN_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "token_negative_vectors.json",
                category: "token_negative",
                case_count: 1,
                contents: TOKEN_NEGATIVE_FIXTURE,
            },
        ],
    )
}

#[test]
fn hkdf_vectors_match_expected_output() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<CryptoVector> =
        parse_fixture_cases_for_profile(HKDF_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_common_case_fields(&case, "hkdf.sha256.empty_salt.context_001");
        assert_eq!(case.determinism.mode, "deterministic");
        let ikm = decode_required_hex(case.inputs.ikm_hex.as_ref(), "ikm_hex")?;
        let salt = decode_required_hex(case.inputs.salt_hex.as_ref(), "salt_hex")?;
        let context = decode_required_hex(case.inputs.context_hex.as_ref(), "context_hex")?;
        let length = required_usize(case.inputs.length, "length")?;
        let expected = decode_required_hex(case.expected.okm_hex.as_ref(), "okm_hex")?;
        let mut output = vec![0; length];

        rns_hkdf_sha256(&mut output, &ikm, Some(&salt), Some(&context))?;

        assert!(case.expected.valid);
        assert_eq!(output, expected);
    }

    Ok(())
}

#[test]
fn token_vectors_encrypt_and_decrypt() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<CryptoVector> =
        parse_fixture_cases_for_profile(TOKEN_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_common_case_fields(&case, "token.aes128.fixed_iv.basic_001");
        assert_eq!(case.determinism.mode, "fixed_iv");
        let key = decode_required_hex(case.inputs.key_hex.as_ref(), "key_hex")?;
        let iv = decode_hex_exact::<RNS_TOKEN_IV_LEN>(required_str(
            case.inputs.iv_hex.as_ref(),
            "iv_hex",
        )?)?;
        let plaintext = decode_required_hex(case.inputs.plaintext_hex.as_ref(), "plaintext_hex")?;
        let expected_token = decode_required_hex(case.expected.token_hex.as_ref(), "token_hex")?;
        let mut token = vec![0; expected_token.len()];
        let token_len = token_encrypt_with_iv(&key, &plaintext, iv, &mut token)?;
        let mut decrypted = vec![0; plaintext.len() + RNS_TOKEN_IV_LEN];
        let plaintext_len = token_decrypt(&key, &token[..token_len], &mut decrypted)?;

        assert!(case.expected.valid);
        assert_eq!(&token[..token_len], expected_token);
        assert_eq!(&decrypted[..plaintext_len], plaintext);
    }

    Ok(())
}

#[test]
fn token_negative_vectors_fail_closed() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<CryptoVector> =
        parse_fixture_cases_for_profile(TOKEN_NEGATIVE_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_common_case_fields(&case, "token.aes128.bad_hmac_001");
        let key = decode_required_hex(case.inputs.key_hex.as_ref(), "key_hex")?;
        let token = decode_required_hex(case.inputs.token_hex.as_ref(), "token_hex")?;
        let mut output = vec![0x55; token.len()];

        assert!(!case.expected.valid);
        assert_eq!(
            case.expected.error.as_deref(),
            Some("authentication_failed")
        );
        assert_eq!(
            token_decrypt(&key, &token, &mut output),
            Err(RnsCryptoError::AuthenticationFailed)
        );
        assert!(output.iter().all(|byte| *byte == 0x55));
    }

    Ok(())
}

fn assert_common_case_fields(case: &CryptoVector, expected_case_id: &str) {
    assert_eq!(case.schema, "hyf.rns.crypto_vector.v1");
    assert_eq!(case.profile, PROFILE_2_CRYPTO_IFAC);
    assert_eq!(case.subprofile, "profile_2a_hkdf_token");
    assert_eq!(case.case_id, expected_case_id);
    assert!(case.determinism.test_only_secret_material);
}

fn decode_required_hex(
    value: Option<&String>,
    field: &'static str,
) -> Result<Vec<u8>, FixtureError> {
    decode_hex(required_str(value, field)?)
}

fn required_str<'a>(
    value: Option<&'a String>,
    field: &'static str,
) -> Result<&'a str, FixtureError> {
    value
        .map(String::as_str)
        .ok_or_else(|| missing_fixture_value(field))
}

fn required_usize(value: Option<usize>, field: &'static str) -> Result<usize, FixtureError> {
    value.ok_or_else(|| missing_fixture_value(field))
}

fn missing_fixture_value(field: &'static str) -> FixtureError {
    FixtureError::UnexpectedFixtureValue {
        field: field.to_owned(),
        value: "<missing>".to_owned(),
    }
}
