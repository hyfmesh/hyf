use hyf_rns_conformance::fixtures::{
    ExpectedManifestEntry, FixtureCasesFile, FixtureError, PROFILE_2_CRYPTO_IFAC,
    assert_exact_manifest_entries, decode_hex, decode_hex_exact, parse_fixture_cases_for_profile,
    parse_manifest_for_profile,
};
use hyf_rns_crypto::{
    RNS_PUBLIC_IDENTITY_LEN, RNS_SECRET_IDENTITY_LEN, RNS_TOKEN_IV_LEN, RnsCryptoError,
    decrypt_for_identity, encrypt_for_identity_with_ephemeral_and_iv, public_identity_from_bytes,
    rns_hkdf_sha256, secret_identity_from_bytes, token_decrypt, token_encrypt_with_iv,
};
use hyf_rns_wire::{RnsWireError, ifac_apply_outbound, ifac_verify_inbound};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../../../fixtures/rns/profile_2_crypto_ifac/manifest.json");
const HKDF_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/hkdf_vectors.json");
const TOKEN_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/token_vectors.json");
const TOKEN_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/token_negative_vectors.json");
const IDENTITY_ENCRYPT_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/identity_encrypt_vectors.json");
const IDENTITY_DECRYPT_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/identity_decrypt_vectors.json");
const IFAC_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/ifac_vectors.json");
const IFAC_NEGATIVE_FIXTURE: &str =
    include_str!("../../../fixtures/rns/profile_2_crypto_ifac/ifac_negative_vectors.json");

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
    recipient_public_hex: Option<String>,
    recipient_secret_hex: Option<String>,
    ephemeral_secret_hex: Option<String>,
    ciphertext_token_hex: Option<String>,
    output_len: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct CryptoExpected {
    okm_hex: Option<String>,
    token_hex: Option<String>,
    ciphertext_token_hex: Option<String>,
    plaintext_hex: Option<String>,
    error: Option<String>,
    valid: bool,
}

#[derive(Debug, Deserialize)]
struct IfacVector {
    schema: String,
    profile: String,
    subprofile: String,
    case_id: String,
    ifac_size: usize,
    ifac_key_hex: String,
    ifac_identity_secret_hex: String,
    test_only_secret_material: bool,
    raw_packet_hex: Option<String>,
    masked_packet_hex: Option<String>,
    expected_unmasked_hex: Option<String>,
    output_len: Option<usize>,
    expected_error: Option<String>,
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
                case_count: 4,
                contents: TOKEN_NEGATIVE_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "identity_encrypt_vectors.json",
                category: "identity_encrypt",
                case_count: 1,
                contents: IDENTITY_ENCRYPT_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "identity_decrypt_vectors.json",
                category: "identity_decrypt",
                case_count: 5,
                contents: IDENTITY_DECRYPT_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "ifac_vectors.json",
                category: "ifac",
                case_count: 1,
                contents: IFAC_FIXTURE,
            },
            ExpectedManifestEntry {
                file: "ifac_negative_vectors.json",
                category: "ifac_negative",
                case_count: 6,
                contents: IFAC_NEGATIVE_FIXTURE,
            },
        ],
    )
}

#[test]
fn hkdf_vectors_match_expected_output() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<CryptoVector> =
        parse_fixture_cases_for_profile(HKDF_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_common_case_fields(
            &case,
            "profile_2a_hkdf_token",
            "hkdf.sha256.empty_salt.context_001",
        );
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
        assert_common_case_fields(
            &case,
            "profile_2a_hkdf_token",
            "token.aes128.fixed_iv.basic_001",
        );
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
        assert_eq!(case.schema, "hyf.rns.crypto_vector.v1");
        assert_eq!(case.profile, PROFILE_2_CRYPTO_IFAC);
        assert_eq!(case.subprofile, "profile_2a_hkdf_token");
        assert_eq!(case.determinism.mode, "fixed_iv");
        assert!(case.determinism.test_only_secret_material);
        let key = decode_required_hex(case.inputs.key_hex.as_ref(), "key_hex")?;
        let token = decode_required_hex(case.inputs.token_hex.as_ref(), "token_hex")?;
        let mut output = vec![0x55; token.len()];
        let error = expected_crypto_error(case.expected.error.as_deref())?;

        assert!(!case.expected.valid);
        assert_eq!(token_decrypt(&key, &token, &mut output), Err(error));
        match case.case_id.as_str() {
            "token.aes128.short_token_001"
            | "token.aes128.malformed_length_001"
            | "token.aes128.bad_hmac_001" => {
                assert!(output.iter().all(|byte| *byte == 0x55));
            }
            "token.aes128.bad_padding_001" => {
                assert!(output[..16].iter().all(|byte| *byte == 0));
                assert!(output[16..].iter().all(|byte| *byte == 0x55));
            }
            other => {
                return Err(FixtureError::UnexpectedFixtureValue {
                    field: "case_id".to_owned(),
                    value: other.to_owned(),
                });
            }
        }
    }

    Ok(())
}

#[test]
fn identity_encrypt_vectors_match_expected_ciphertext() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<CryptoVector> =
        parse_fixture_cases_for_profile(IDENTITY_ENCRYPT_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_common_case_fields(
            &case,
            "profile_2b_identity_encryption",
            "identity_encrypt.fixed_ephemeral.fixed_iv.basic_001",
        );
        assert_eq!(case.determinism.mode, "fixed_ephemeral_fixed_iv");
        let recipient_public = decode_required_hex_exact::<RNS_PUBLIC_IDENTITY_LEN>(
            case.inputs.recipient_public_hex.as_ref(),
            "recipient_public_hex",
        )?;
        let ephemeral_secret = decode_required_hex_exact::<32>(
            case.inputs.ephemeral_secret_hex.as_ref(),
            "ephemeral_secret_hex",
        )?;
        let iv =
            decode_required_hex_exact::<RNS_TOKEN_IV_LEN>(case.inputs.iv_hex.as_ref(), "iv_hex")?;
        let plaintext = decode_required_hex(case.inputs.plaintext_hex.as_ref(), "plaintext_hex")?;
        let expected_ciphertext = decode_required_hex(
            case.expected.ciphertext_token_hex.as_ref(),
            "ciphertext_token_hex",
        )?;
        let recipient = public_identity_from_bytes(&recipient_public)?;
        let mut ciphertext = vec![0; expected_ciphertext.len()];
        let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
            &recipient,
            &plaintext,
            ephemeral_secret,
            iv,
            &mut ciphertext,
        )?;

        assert!(case.expected.valid);
        assert_eq!(&ciphertext[..ciphertext_len], expected_ciphertext);
    }

    Ok(())
}

#[test]
fn identity_decrypt_vectors_decrypt_and_fail_closed() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<CryptoVector> =
        parse_fixture_cases_for_profile(IDENTITY_DECRYPT_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_eq!(case.schema, "hyf.rns.crypto_vector.v1");
        assert_eq!(case.profile, PROFILE_2_CRYPTO_IFAC);
        assert_eq!(case.subprofile, "profile_2b_identity_encryption");
        assert_eq!(case.determinism.mode, "fixed_ephemeral_fixed_iv");
        assert!(case.determinism.test_only_secret_material);
        let recipient_secret = decode_required_hex_exact::<RNS_SECRET_IDENTITY_LEN>(
            case.inputs.recipient_secret_hex.as_ref(),
            "recipient_secret_hex",
        )?;
        let ciphertext = decode_required_hex(
            case.inputs.ciphertext_token_hex.as_ref(),
            "ciphertext_token_hex",
        )?;
        let recipient = secret_identity_from_bytes(&recipient_secret)?;
        let mut plaintext = vec![0x55; ciphertext.len()];

        match case.case_id.as_str() {
            "identity_decrypt.fixed_ephemeral.fixed_iv.basic_001" => {
                let expected_plaintext =
                    decode_required_hex(case.expected.plaintext_hex.as_ref(), "plaintext_hex")?;
                let outcome =
                    decrypt_for_identity(&recipient, &ciphertext, &[], false, &mut plaintext)?;

                assert!(case.expected.valid);
                assert_eq!(outcome.ratchet_index(), None);
                assert_eq!(outcome.plaintext(), expected_plaintext);
            }
            "identity_decrypt.noncontributory_ephemeral_001" => {
                assert!(!case.expected.valid);
                assert_eq!(
                    case.expected.error.as_deref(),
                    Some("invalid_public_identity")
                );
                assert_eq!(
                    decrypt_for_identity(&recipient, &ciphertext, &[], false, &mut plaintext),
                    Err(RnsCryptoError::InvalidPublicIdentity)
                );
                assert!(plaintext.iter().all(|byte| *byte == 0x55));
            }
            "identity_decrypt.bad_hmac_001"
            | "identity_decrypt.bad_padding_001"
            | "identity_decrypt.output_too_small_001" => {
                assert!(!case.expected.valid);
                let output_len = case.inputs.output_len.unwrap_or(ciphertext.len());
                let mut plaintext = vec![0x55; output_len];
                let error = expected_crypto_error(case.expected.error.as_deref())?;
                assert_eq!(
                    decrypt_for_identity(&recipient, &ciphertext, &[], false, &mut plaintext),
                    Err(error)
                );
                match case.case_id.as_str() {
                    "identity_decrypt.bad_padding_001" => {
                        assert!(plaintext[..16].iter().all(|byte| *byte == 0));
                        assert!(plaintext[16..].iter().all(|byte| *byte == 0x55));
                    }
                    _ => assert!(plaintext.iter().all(|byte| *byte == 0x55)),
                }
            }
            other => {
                return Err(FixtureError::UnexpectedFixtureValue {
                    field: "case_id".to_owned(),
                    value: other.to_owned(),
                });
            }
        }
    }

    Ok(())
}

#[test]
fn ifac_vectors_apply_verify_and_decode() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<IfacVector> =
        parse_fixture_cases_for_profile(IFAC_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_ifac_common_case_fields(&case, "ifac.apply_verify.size8.basic_001");
        let ifac_key = decode_hex(&case.ifac_key_hex)?;
        let ifac_identity_secret =
            decode_hex_exact::<RNS_SECRET_IDENTITY_LEN>(&case.ifac_identity_secret_hex)?;
        let raw_packet = decode_required_hex(case.raw_packet_hex.as_ref(), "raw_packet_hex")?;
        let expected_masked =
            decode_required_hex(case.masked_packet_hex.as_ref(), "masked_packet_hex")?;
        let expected_unmasked =
            decode_required_hex(case.expected_unmasked_hex.as_ref(), "expected_unmasked_hex")?;
        let identity = secret_identity_from_bytes(&ifac_identity_secret)?;
        let mut masked = vec![0; expected_masked.len()];
        let masked_len = ifac_apply_outbound(
            &raw_packet,
            &identity,
            &ifac_key,
            case.ifac_size,
            &mut masked,
        )?;
        let mut unmasked = vec![0; expected_unmasked.len()];
        let unmasked_len = ifac_verify_inbound(
            &masked[..masked_len],
            &identity,
            &ifac_key,
            case.ifac_size,
            &mut unmasked,
        )?;

        assert_eq!(&masked[..masked_len], expected_masked);
        assert_eq!(&unmasked[..unmasked_len], expected_unmasked);
        assert!(hyf_rns_wire::decode_packet(&masked[..masked_len]).is_err());
        assert!(hyf_rns_wire::decode_packet(&unmasked[..unmasked_len]).is_ok());
    }

    Ok(())
}

#[test]
fn ifac_negative_vectors_fail_closed() -> Result<(), FixtureError> {
    let fixture: FixtureCasesFile<IfacVector> =
        parse_fixture_cases_for_profile(IFAC_NEGATIVE_FIXTURE, PROFILE_2_CRYPTO_IFAC)?;

    for case in fixture.cases {
        assert_eq!(case.schema, "hyf.rns.ifac_vector.v1");
        assert_eq!(case.profile, PROFILE_2_CRYPTO_IFAC);
        assert_eq!(case.subprofile, "profile_2c_ifac");
        assert!(case.test_only_secret_material);
        let ifac_key = decode_hex(&case.ifac_key_hex)?;
        let ifac_identity_secret =
            decode_hex_exact::<RNS_SECRET_IDENTITY_LEN>(&case.ifac_identity_secret_hex)?;
        let masked_packet = case
            .masked_packet_hex
            .as_ref()
            .map(|value| decode_hex(value))
            .transpose()?;
        let identity = secret_identity_from_bytes(&ifac_identity_secret)?;

        match case.case_id.as_str() {
            "ifac.verify.bad_code_001" => {
                let masked_packet = required_bytes(masked_packet.as_ref(), "masked_packet_hex")?;
                let mut output = vec![0x55; masked_packet.len()];
                assert_eq!(
                    case.expected_error.as_deref(),
                    Some("invalid_packet_access_code")
                );
                assert_eq!(
                    ifac_verify_inbound(
                        masked_packet,
                        &identity,
                        &ifac_key,
                        case.ifac_size,
                        &mut output
                    ),
                    Err(RnsWireError::InvalidPacketAccessCode)
                );
                assert!(
                    output[..masked_packet.len() - case.ifac_size]
                        .iter()
                        .all(|byte| *byte == 0)
                );
            }
            "ifac.verify.short_packet_001" => {
                let masked_packet = required_bytes(masked_packet.as_ref(), "masked_packet_hex")?;
                let mut output = vec![0x55; masked_packet.len()];
                assert_eq!(case.expected_error.as_deref(), Some("packet_too_short"));
                assert_eq!(
                    ifac_verify_inbound(
                        masked_packet,
                        &identity,
                        &ifac_key,
                        case.ifac_size,
                        &mut output
                    ),
                    Err(RnsWireError::PacketTooShort {
                        actual: masked_packet.len(),
                        minimum: 11
                    })
                );
                assert!(output.iter().all(|byte| *byte == 0x55));
            }
            "ifac.verify.missing_flag_001" => {
                let masked_packet = required_bytes(masked_packet.as_ref(), "masked_packet_hex")?;
                let mut output = vec![0x55; masked_packet.len()];
                assert_eq!(
                    case.expected_error.as_deref(),
                    Some("missing_packet_access_code")
                );
                assert_eq!(
                    ifac_verify_inbound(
                        masked_packet,
                        &identity,
                        &ifac_key,
                        case.ifac_size,
                        &mut output
                    ),
                    Err(RnsWireError::MissingPacketAccessCode)
                );
                assert!(output.iter().all(|byte| *byte == 0x55));
            }
            "ifac.apply.unexpected_flag_001" => {
                let raw_packet =
                    decode_required_hex(case.raw_packet_hex.as_ref(), "raw_packet_hex")?;
                let mut output = vec![0x55; raw_packet.len() + case.ifac_size];
                assert_eq!(
                    case.expected_error.as_deref(),
                    Some("unsupported_packet_access_code")
                );
                assert_eq!(
                    ifac_apply_outbound(
                        &raw_packet,
                        &identity,
                        &ifac_key,
                        case.ifac_size,
                        &mut output
                    ),
                    Err(RnsWireError::UnsupportedPacketAccessCode)
                );
                assert!(output.iter().all(|byte| *byte == 0x55));
            }
            "ifac.verify.invalid_size_001" => {
                let masked_packet = required_bytes(masked_packet.as_ref(), "masked_packet_hex")?;
                let mut output = vec![0x55; masked_packet.len()];
                assert_eq!(case.expected_error.as_deref(), Some("invalid_ifac_size"));
                assert_eq!(
                    ifac_verify_inbound(
                        masked_packet,
                        &identity,
                        &ifac_key,
                        case.ifac_size,
                        &mut output
                    ),
                    Err(RnsWireError::InvalidIfacSize {
                        actual: 0,
                        maximum: 64
                    })
                );
                assert!(output.iter().all(|byte| *byte == 0x55));
            }
            "ifac.verify.output_too_small_001" => {
                let masked_packet = required_bytes(masked_packet.as_ref(), "masked_packet_hex")?;
                let output_len = required_usize(case.output_len, "output_len")?;
                let mut output = vec![0x55; output_len];
                assert_eq!(
                    case.expected_error.as_deref(),
                    Some("output_buffer_too_short")
                );
                assert_eq!(
                    ifac_verify_inbound(
                        masked_packet,
                        &identity,
                        &ifac_key,
                        case.ifac_size,
                        &mut output
                    ),
                    Err(RnsWireError::OutputBufferTooShort {
                        actual: output_len,
                        required: masked_packet.len() - case.ifac_size
                    })
                );
                assert!(output.iter().all(|byte| *byte == 0x55));
            }
            other => {
                return Err(FixtureError::UnexpectedFixtureValue {
                    field: "case_id".to_owned(),
                    value: other.to_owned(),
                });
            }
        }
    }

    Ok(())
}

fn assert_common_case_fields(
    case: &CryptoVector,
    expected_subprofile: &str,
    expected_case_id: &str,
) {
    assert_eq!(case.schema, "hyf.rns.crypto_vector.v1");
    assert_eq!(case.profile, PROFILE_2_CRYPTO_IFAC);
    assert_eq!(case.subprofile, expected_subprofile);
    assert_eq!(case.case_id, expected_case_id);
    assert!(case.determinism.test_only_secret_material);
}

fn assert_ifac_common_case_fields(case: &IfacVector, expected_case_id: &str) {
    assert_eq!(case.schema, "hyf.rns.ifac_vector.v1");
    assert_eq!(case.profile, PROFILE_2_CRYPTO_IFAC);
    assert_eq!(case.subprofile, "profile_2c_ifac");
    assert_eq!(case.case_id, expected_case_id);
    assert!(case.test_only_secret_material);
}

fn decode_required_hex(
    value: Option<&String>,
    field: &'static str,
) -> Result<Vec<u8>, FixtureError> {
    decode_hex(required_str(value, field)?)
}

fn decode_required_hex_exact<const N: usize>(
    value: Option<&String>,
    field: &'static str,
) -> Result<[u8; N], FixtureError> {
    decode_hex_exact(required_str(value, field)?)
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

fn required_bytes<'a>(
    value: Option<&'a Vec<u8>>,
    field: &'static str,
) -> Result<&'a [u8], FixtureError> {
    value
        .map(Vec::as_slice)
        .ok_or_else(|| missing_fixture_value(field))
}

fn expected_crypto_error(value: Option<&str>) -> Result<RnsCryptoError, FixtureError> {
    match value {
        Some("authentication_failed") => Ok(RnsCryptoError::AuthenticationFailed),
        Some("invalid_padding") => Ok(RnsCryptoError::InvalidPadding),
        Some("invalid_public_identity") => Ok(RnsCryptoError::InvalidPublicIdentity),
        Some("invalid_token") => Ok(RnsCryptoError::InvalidToken),
        Some("output_buffer_too_short") => Ok(RnsCryptoError::OutputBufferTooShort {
            actual: 4,
            required: 16,
        }),
        Some(other) => Err(FixtureError::UnexpectedFixtureValue {
            field: "expected.error".to_owned(),
            value: other.to_owned(),
        }),
        None => Err(missing_fixture_value("expected.error")),
    }
}

fn missing_fixture_value(field: &'static str) -> FixtureError {
    FixtureError::UnexpectedFixtureValue {
        field: field.to_owned(),
        value: "<missing>".to_owned(),
    }
}
