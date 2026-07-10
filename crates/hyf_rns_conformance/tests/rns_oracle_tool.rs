#![cfg(feature = "python_oracle")]

use std::path::{Path, PathBuf};
use std::process::Command;

use hyf_rns_conformance::{
    PINNED_CRYPTOGRAPHY_PACKAGE, PINNED_PYSERIAL_PACKAGE, fixtures::EXPECTED_RETICULUM_COMMIT,
};
use hyf_rns_crypto::{
    RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN, RNS_TOKEN_IV_LEN, RnsCryptoError,
    derive_identity_token_key_for_test_vectors, encrypt_for_identity_with_ephemeral_and_iv,
    public_identity_from_bytes, token_encrypt_with_iv, token_retag_for_test_vectors,
};
use serde::Deserialize;

#[test]
fn rns_oracle_tool_replays_profile_1_and_profile_2_vectors() -> Result<(), OracleToolError> {
    let Some(kiss_response) =
        run_oracle(&["kiss-encode", "--case", "kiss.data.escapes_fend_fesc_001"])?
    else {
        return Ok(());
    };
    assert_eq!(kiss_response.command, "kiss-encode");
    assert_eq!(kiss_response.oracle.mode, "fixture_replay");
    assert_eq!(
        kiss_response.oracle.reticulum.commit,
        EXPECTED_RETICULUM_COMMIT
    );
    assert_eq!(
        kiss_response.case.and_then(|case| case.encoded_hex),
        Some("c000dbdcdbdd01c0".to_owned())
    );

    let Some(kiss_decode_response) = run_oracle(&["kiss-decode", "--hex", "c000dbdcdbdd01c0"])?
    else {
        return Ok(());
    };
    assert_eq!(kiss_decode_response.command, "kiss-decode");
    assert_eq!(kiss_decode_response.oracle.mode, "fixture_replay");
    assert_eq!(
        kiss_decode_response.oracle.reticulum.commit,
        EXPECTED_RETICULUM_COMMIT
    );
    assert_eq!(
        kiss_decode_response.encoded_hex,
        Some("c000dbdcdbdd01c0".to_owned())
    );
    assert_eq!(
        kiss_decode_response.frames,
        Some(vec![OracleFrame {
            kind: "data".to_owned(),
            command_hex: "00".to_owned(),
            payload_hex: "c0db01".to_owned(),
        }])
    );

    let Some(kiss_decode_upper_response) =
        run_oracle(&["kiss-decode", "--hex", "C000DBDCDBDD01C0"])?
    else {
        return Ok(());
    };
    assert_eq!(kiss_decode_upper_response.command, "kiss-decode");
    assert_eq!(
        kiss_decode_upper_response.encoded_hex,
        Some("c000dbdcdbdd01c0".to_owned())
    );

    let Some(rnode_response) =
        run_oracle(&["rnode-command", "--case", "rnode.command.frequency_915mhz"])?
    else {
        return Ok(());
    };
    assert_eq!(rnode_response.command, "rnode-command");
    assert_eq!(
        rnode_response.case.and_then(|case| case.kiss_frame_hex),
        Some("c0013689cadbdcc0".to_owned())
    );

    let Some(token_response) = run_oracle(&["token-decrypt", "--hex", TOKEN_VECTOR_HEX])? else {
        return Ok(());
    };
    assert_eq!(token_response.command, "token-decrypt");
    assert_eq!(token_response.oracle.mode, "fixture_replay");
    assert_eq!(token_response.valid, Some(true));
    assert_eq!(
        token_response.plaintext_hex,
        Some("68656c6c6f20746f6b656e".to_owned())
    );

    let Some(token_encrypt_response) =
        run_oracle(&["token-encrypt", "--case", "token.aes128.fixed_iv.basic_001"])?
    else {
        return Ok(());
    };
    assert_eq!(token_encrypt_response.command, "token-encrypt");
    assert_eq!(token_encrypt_response.oracle.mode, "fixture_replay");

    let Some(identity_encrypt_response) = run_oracle(&[
        "identity-encrypt",
        "--case",
        "identity_encrypt.fixed_ephemeral.fixed_iv.basic_001",
    ])?
    else {
        return Ok(());
    };
    assert_eq!(identity_encrypt_response.command, "identity-encrypt");
    assert_eq!(identity_encrypt_response.oracle.mode, "fixture_replay");

    let Some(ifac_response) = run_oracle(&["ifac-verify", "--hex", IFAC_VECTOR_HEX])? else {
        return Ok(());
    };
    assert_eq!(ifac_response.command, "ifac-verify");
    assert_eq!(ifac_response.valid, Some(true));
    assert_eq!(ifac_response.masked_hex, Some(IFAC_VECTOR_HEX.to_owned()));
    assert_eq!(
        ifac_response.unmasked_hex,
        Some("00031111111111111111111111111111111100aabbcc".to_owned())
    );

    Ok(())
}

#[test]
fn rns_oracle_tool_rejects_unknown_cases() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&["hkdf-vector", "--case", "missing.case"])? else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown case"));
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_tool_rejects_bad_hex_inputs() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&["token-decrypt", "--hex", "abc"])? else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("token hex must have an even length"));
    assert!(output.stdout.is_empty());

    let Some(output) = run_oracle_raw(&["kiss-decode", "--hex", "c0 0"])? else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("KISS frame is not valid canonical hex")
    );
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_tool_rejects_bad_test_only_inputs() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&[
        "token-decrypt",
        "--hex",
        TOKEN_VECTOR_HEX,
        "--test-token-key-hex",
        "00",
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("test token key hex must be 32 or 64 bytes")
    );
    assert!(output.stdout.is_empty());

    let Some(output) = run_oracle_raw(&[
        "ifac-verify",
        "--hex",
        IFAC_VECTOR_HEX,
        "--test-ifac-size",
        "0",
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("test IFAC size must be between 1 and 64 bytes")
    );
    assert!(output.stdout.is_empty());

    let Some(output) = run_oracle_raw(&[
        "identity-encrypt",
        "--case",
        "identity_encrypt.fixed_ephemeral.fixed_iv.basic_001",
        "--test-recipient-public-identity-hex",
        &hex(&TEST_PUBLIC_IDENTITY_BYTES),
        "--test-plaintext-hex",
        &hex(TOKEN_PLAINTEXT),
        "--test-ephemeral-secret-hex",
        &hex(&EPHEMERAL_SECRET),
        "--test-iv-hex",
        &hex(&TOKEN_IV),
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "identity generation test inputs require recipient public identity, recipient secret identity"
    ));
    assert!(output.stdout.is_empty());

    let Some(output) = run_oracle_raw(&[
        "identity-decrypt",
        "--hex",
        "00",
        "--test-ratchet-secret-hex",
        &hex(&EPHEMERAL_SECRET),
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unrecognized arguments: --test-ratchet-secret-hex")
    );
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_probe_rejects_invalid_environment() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&[
        "probe",
        "--reticulum-path",
        "/definitely/not/a/reticulum/checkout",
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("invalid_environment: Reticulum path is not a directory")
    );
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_token_decrypt_rejects_invalid_environment() -> Result<(), OracleToolError> {
    let Some(output) = run_oracle_raw(&[
        "token-decrypt",
        "--hex",
        TOKEN_VECTOR_HEX,
        "--test-token-key-hex",
        &hex(&TOKEN_KEY_32),
        "--reticulum-path",
        "/definitely/not/a/reticulum/checkout",
    ])?
    else {
        return Ok(());
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("invalid_environment: Reticulum path is not a directory")
    );
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn rns_oracle_ifac_verify_rejects_invalid_environment() -> Result<(), OracleToolError> {
    for packet_hex in ["00", IFAC_MISSING_PACKET_ACCESS_CODE_HEX] {
        let secret_hex = hex(&IFAC_SECRET_IDENTITY);
        let key_hex = hex(&IFAC_KEY);
        let Some(output) = run_oracle_raw(&[
            "ifac-verify",
            "--hex",
            packet_hex,
            "--test-ifac-identity-secret-hex",
            &secret_hex,
            "--test-ifac-key-hex",
            &key_hex,
            "--test-ifac-size",
            "8",
            "--reticulum-path",
            "/definitely/not/a/reticulum/checkout",
        ])?
        else {
            return Ok(());
        };

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("invalid_environment: Reticulum path is not a directory")
        );
        assert!(output.stdout.is_empty());
    }

    Ok(())
}

#[test]
fn rns_oracle_tool_validates_rust_generated_token_with_reticulum() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };
    let mut token = [0; 128];
    let token_len = token_encrypt_with_iv(&TOKEN_KEY_32, TOKEN_PLAINTEXT, TOKEN_IV, &mut token)?;
    let args = token_oracle_args(&token[..token_len], &TOKEN_KEY_32, &reticulum_path);
    let Some(response) = run_oracle_with_packages(&args)? else {
        return Ok(());
    };

    assert_eq!(response.command, "token-decrypt");
    assert_eq!(response.oracle.mode, "python_reticulum");
    assert_eq!(response.valid, Some(true));
    assert_eq!(response.token_hex, Some(hex(&token[..token_len])));
    assert_eq!(response.plaintext_hex, Some(hex(TOKEN_PLAINTEXT)));

    Ok(())
}

#[test]
fn rns_oracle_tool_reports_reticulum_token_failures() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };

    let short_args = token_oracle_args(&[0; 16], &TOKEN_KEY_32, &reticulum_path);
    let Some(short_response) = run_oracle_with_packages(&short_args)? else {
        return Ok(());
    };
    assert_eq!(short_response.oracle.mode, "python_reticulum");
    assert_eq!(short_response.valid, Some(false));
    assert_eq!(short_response.error, Some("invalid_token".to_owned()));

    let mut bad_hmac = [0; 128];
    let bad_hmac_len =
        token_encrypt_with_iv(&TOKEN_KEY_32, TOKEN_PLAINTEXT, TOKEN_IV, &mut bad_hmac)?;
    bad_hmac[bad_hmac_len - 1] ^= 0x01;
    let bad_hmac_args =
        token_oracle_args(&bad_hmac[..bad_hmac_len], &TOKEN_KEY_32, &reticulum_path);
    let Some(bad_hmac_response) = run_oracle_with_packages(&bad_hmac_args)? else {
        return Ok(());
    };
    assert_eq!(bad_hmac_response.oracle.mode, "python_reticulum");
    assert_eq!(bad_hmac_response.valid, Some(false));
    assert_eq!(
        bad_hmac_response.error,
        Some("authentication_failed".to_owned())
    );

    let mut bad_padding = [0; 128];
    let bad_padding_len =
        token_encrypt_with_iv(&TOKEN_KEY_32, TOKEN_PLAINTEXT, TOKEN_IV, &mut bad_padding)?;
    bad_padding[RNS_TOKEN_IV_LEN - 1] ^= 0x20;
    token_retag_for_test_vectors(&TOKEN_KEY_32, &mut bad_padding[..bad_padding_len])?;
    let bad_padding_args = token_oracle_args(
        &bad_padding[..bad_padding_len],
        &TOKEN_KEY_32,
        &reticulum_path,
    );
    let Some(bad_padding_response) = run_oracle_with_packages(&bad_padding_args)? else {
        return Ok(());
    };
    assert_eq!(bad_padding_response.oracle.mode, "python_reticulum");
    assert_eq!(bad_padding_response.valid, Some(false));
    assert_eq!(
        bad_padding_response.error,
        Some("invalid_padding".to_owned())
    );

    Ok(())
}

#[test]
fn rns_oracle_tool_validates_rust_generated_identity_with_reticulum() -> Result<(), OracleToolError>
{
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };
    let recipient = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
    let mut ciphertext = [0; 128];
    let ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
        &recipient,
        TOKEN_PLAINTEXT,
        EPHEMERAL_SECRET,
        TOKEN_IV,
        &mut ciphertext,
    )?;
    let args = identity_oracle_args(
        &ciphertext[..ciphertext_len],
        &TEST_SECRET_IDENTITY_BYTES,
        &reticulum_path,
    );
    let Some(response) = run_oracle_with_packages(&args)? else {
        return Ok(());
    };

    assert_eq!(response.command, "identity-decrypt");
    assert_eq!(response.oracle.mode, "python_reticulum");
    assert_eq!(response.valid, Some(true));
    assert_eq!(
        response.ciphertext_token_hex,
        Some(hex(&ciphertext[..ciphertext_len]))
    );
    assert_eq!(response.plaintext_hex, Some(hex(TOKEN_PLAINTEXT)));

    Ok(())
}

#[test]
fn rns_oracle_tool_reports_reticulum_identity_failures() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };
    let recipient = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;

    let mut bad_hmac = [0; 128];
    let bad_hmac_len = encrypt_for_identity_with_ephemeral_and_iv(
        &recipient,
        TOKEN_PLAINTEXT,
        EPHEMERAL_SECRET,
        TOKEN_IV,
        &mut bad_hmac,
    )?;
    bad_hmac[bad_hmac_len - 1] ^= 0x01;
    assert_identity_decrypt_failed(&bad_hmac[..bad_hmac_len], &reticulum_path)?;

    let mut bad_padding = [0; 128];
    let bad_padding_len = encrypt_for_identity_with_ephemeral_and_iv(
        &recipient,
        TOKEN_PLAINTEXT,
        EPHEMERAL_SECRET,
        TOKEN_IV,
        &mut bad_padding,
    )?;
    let token_key = derive_identity_token_key_for_test_vectors(&recipient, EPHEMERAL_SECRET)?;
    let token_start = RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN;
    let iv_last = token_start + RNS_TOKEN_IV_LEN - 1;
    bad_padding[iv_last] ^= 0x20;
    token_retag_for_test_vectors(&token_key, &mut bad_padding[token_start..bad_padding_len])?;
    assert_identity_decrypt_failed(&bad_padding[..bad_padding_len], &reticulum_path)?;

    let mut noncontributory = [0; 128];
    let noncontributory_len = encrypt_for_identity_with_ephemeral_and_iv(
        &recipient,
        TOKEN_PLAINTEXT,
        EPHEMERAL_SECRET,
        TOKEN_IV,
        &mut noncontributory,
    )?;
    noncontributory[..RNS_SINGLE_PACKET_EPHEMERAL_PUBLIC_LEN].fill(0);
    assert_identity_decrypt_failed(&noncontributory[..noncontributory_len], &reticulum_path)?;

    Ok(())
}

#[test]
fn rns_oracle_tool_validates_ifac_with_reticulum() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };

    let apply_args = ifac_apply_oracle_args(&reticulum_path);
    let Some(apply_response) = run_oracle_with_packages(&apply_args)? else {
        return Ok(());
    };

    assert_eq!(apply_response.command, "ifac-apply");
    assert_eq!(apply_response.oracle.mode, "python_reticulum");
    assert_eq!(apply_response.valid, Some(true));
    assert_eq!(apply_response.masked_hex, Some(IFAC_VECTOR_HEX.to_owned()));

    let verify_args = ifac_oracle_args(&reticulum_path);
    let Some(verify_response) = run_oracle_with_packages(&verify_args)? else {
        return Ok(());
    };

    assert_eq!(verify_response.command, "ifac-verify");
    assert_eq!(verify_response.oracle.mode, "python_reticulum");
    assert_eq!(verify_response.valid, Some(true));
    assert_eq!(verify_response.masked_hex, Some(IFAC_VECTOR_HEX.to_owned()));
    assert_eq!(
        verify_response.unmasked_hex,
        Some(IFAC_RAW_PACKET_HEX.to_owned())
    );

    Ok(())
}

#[test]
fn rns_oracle_tool_reports_ifac_protocol_negatives_with_reticulum() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };

    let short_args = ifac_oracle_hex_args("00", &reticulum_path);
    let Some(short_response) = run_oracle_with_packages(&short_args)? else {
        return Ok(());
    };
    assert_eq!(short_response.command, "ifac-verify");
    assert_eq!(short_response.oracle.mode, "python_reticulum");
    assert_eq!(short_response.valid, Some(false));
    assert_eq!(short_response.masked_hex, Some("00".to_owned()));
    assert_eq!(short_response.error, Some("packet_too_short".to_owned()));

    let missing_flag_args =
        ifac_oracle_hex_args(IFAC_MISSING_PACKET_ACCESS_CODE_HEX, &reticulum_path);
    let Some(missing_flag_response) = run_oracle_with_packages(&missing_flag_args)? else {
        return Ok(());
    };
    assert_eq!(missing_flag_response.command, "ifac-verify");
    assert_eq!(missing_flag_response.oracle.mode, "python_reticulum");
    assert_eq!(missing_flag_response.valid, Some(false));
    assert_eq!(
        missing_flag_response.masked_hex,
        Some(IFAC_MISSING_PACKET_ACCESS_CODE_HEX.to_owned())
    );
    assert_eq!(
        missing_flag_response.error,
        Some("missing_packet_access_code".to_owned())
    );

    Ok(())
}

#[test]
fn rns_oracle_tool_generates_vectors_for_reticulum_validation() -> Result<(), OracleToolError> {
    let Some(reticulum_path) = reticulum_path_for_tool()? else {
        return Ok(());
    };

    let token_args = token_encrypt_oracle_args(&TOKEN_KEY_32, TOKEN_PLAINTEXT, &reticulum_path);
    let Some(token_response) = run_oracle_with_packages(&token_args)? else {
        return Ok(());
    };
    assert_eq!(token_response.command, "token-encrypt");
    assert_eq!(token_response.oracle.mode, "test_only_oracle_shim");
    assert_eq!(token_response.valid, Some(true));
    assert_eq!(token_response.plaintext_hex, Some(hex(TOKEN_PLAINTEXT)));
    assert_eq!(
        token_response.reticulum_self_validation,
        Some("passed".to_owned())
    );
    assert_eq!(token_response.test_only_secret_material, Some(true));

    let token_hex = token_response
        .token_hex
        .ok_or_else(|| OracleToolError::Json("missing token_hex".to_owned()))?;
    let mut rust_token = [0; 128];
    let rust_token_len =
        token_encrypt_with_iv(&TOKEN_KEY_32, TOKEN_PLAINTEXT, TOKEN_IV, &mut rust_token)?;
    assert_eq!(token_hex, hex(&rust_token[..rust_token_len]));

    let token_decrypt_args = token_oracle_hex_args(&token_hex, &TOKEN_KEY_32, &reticulum_path);
    let Some(token_decrypt_response) = run_oracle_with_packages(&token_decrypt_args)? else {
        return Ok(());
    };
    assert_eq!(token_decrypt_response.command, "token-decrypt");
    assert_eq!(token_decrypt_response.oracle.mode, "python_reticulum");
    assert_eq!(token_decrypt_response.valid, Some(true));
    assert_eq!(token_decrypt_response.token_hex, Some(token_hex));
    assert_eq!(
        token_decrypt_response.plaintext_hex,
        Some(hex(TOKEN_PLAINTEXT))
    );

    let identity_args = identity_encrypt_oracle_args(
        &TEST_PUBLIC_IDENTITY_BYTES,
        TOKEN_PLAINTEXT,
        &reticulum_path,
    );
    let Some(identity_response) = run_oracle_with_packages(&identity_args)? else {
        return Ok(());
    };
    assert_eq!(identity_response.command, "identity-encrypt");
    assert_eq!(identity_response.oracle.mode, "test_only_oracle_shim");
    assert_eq!(identity_response.valid, Some(true));
    assert_eq!(identity_response.plaintext_hex, Some(hex(TOKEN_PLAINTEXT)));
    assert_eq!(
        identity_response.reticulum_self_validation,
        Some("passed".to_owned())
    );
    assert_eq!(identity_response.test_only_secret_material, Some(true));

    let ciphertext_token_hex = identity_response
        .ciphertext_token_hex
        .ok_or_else(|| OracleToolError::Json("missing ciphertext_token_hex".to_owned()))?;
    let ephemeral_public_hex = identity_response
        .ephemeral_public_hex
        .ok_or_else(|| OracleToolError::Json("missing ephemeral_public_hex".to_owned()))?;
    assert!(ciphertext_token_hex.starts_with(&ephemeral_public_hex));

    let recipient = public_identity_from_bytes(&TEST_PUBLIC_IDENTITY_BYTES)?;
    let mut rust_ciphertext = [0; 128];
    let rust_ciphertext_len = encrypt_for_identity_with_ephemeral_and_iv(
        &recipient,
        TOKEN_PLAINTEXT,
        EPHEMERAL_SECRET,
        TOKEN_IV,
        &mut rust_ciphertext,
    )?;
    assert_eq!(
        ciphertext_token_hex,
        hex(&rust_ciphertext[..rust_ciphertext_len])
    );

    let identity_decrypt_args = identity_oracle_hex_args(
        &ciphertext_token_hex,
        &TEST_SECRET_IDENTITY_BYTES,
        &reticulum_path,
    );
    let Some(identity_decrypt_response) = run_oracle_with_packages(&identity_decrypt_args)? else {
        return Ok(());
    };
    assert_eq!(identity_decrypt_response.command, "identity-decrypt");
    assert_eq!(identity_decrypt_response.oracle.mode, "python_reticulum");
    assert_eq!(identity_decrypt_response.valid, Some(true));
    assert_eq!(
        identity_decrypt_response.ciphertext_token_hex,
        Some(ciphertext_token_hex)
    );
    assert_eq!(
        identity_decrypt_response.plaintext_hex,
        Some(hex(TOKEN_PLAINTEXT))
    );

    Ok(())
}

fn run_oracle(args: &[&str]) -> Result<Option<OracleResponse>, OracleToolError> {
    let Some(output) = run_oracle_raw(args)? else {
        return Ok(None);
    };
    if !output.status.success() {
        return Err(OracleToolError::OracleFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let response = serde_json::from_slice(&output.stdout)?;
    Ok(Some(response))
}

fn run_oracle_with_packages(args: &[String]) -> Result<Option<OracleResponse>, OracleToolError> {
    let output = Command::new("uv")
        .arg("run")
        .arg("--with")
        .arg(PINNED_CRYPTOGRAPHY_PACKAGE)
        .arg("--with")
        .arg(PINNED_PYSERIAL_PACKAGE)
        .arg("python")
        .arg(oracle_tool_path())
        .args(args)
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                return Err(OracleToolError::OracleFailed(
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }
            Ok(Some(serde_json::from_slice(&output.stdout)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            oracle_unavailable("invalid oracle environment: uv command unavailable")
        }
        Err(error) => Err(error.into()),
    }
}

fn run_oracle_raw(args: &[&str]) -> Result<Option<std::process::Output>, OracleToolError> {
    let output = Command::new("uv")
        .arg("run")
        .arg("python")
        .arg(oracle_tool_path())
        .args(args)
        .output();

    match output {
        Ok(output) => Ok(Some(output)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            oracle_unavailable("invalid oracle environment: uv command unavailable")
        }
        Err(error) => Err(error.into()),
    }
}

fn oracle_tool_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tools/rns_oracle/rns_oracle.py")
}

fn token_oracle_args(token: &[u8], key: &[u8], reticulum_path: &Path) -> Vec<String> {
    token_oracle_hex_args(&hex(token), key, reticulum_path)
}

fn token_oracle_hex_args(token_hex: &str, key: &[u8], reticulum_path: &Path) -> Vec<String> {
    vec![
        "token-decrypt".to_owned(),
        "--hex".to_owned(),
        token_hex.to_owned(),
        "--test-token-key-hex".to_owned(),
        hex(key),
        "--reticulum-path".to_owned(),
        reticulum_path.to_string_lossy().into_owned(),
    ]
}

fn token_encrypt_oracle_args(key: &[u8], plaintext: &[u8], reticulum_path: &Path) -> Vec<String> {
    vec![
        "token-encrypt".to_owned(),
        "--case".to_owned(),
        "token.aes128.fixed_iv.basic_001".to_owned(),
        "--test-token-key-hex".to_owned(),
        hex(key),
        "--test-plaintext-hex".to_owned(),
        hex(plaintext),
        "--test-iv-hex".to_owned(),
        hex(&TOKEN_IV),
        "--reticulum-path".to_owned(),
        reticulum_path.to_string_lossy().into_owned(),
    ]
}

fn identity_oracle_args(
    ciphertext: &[u8],
    recipient_secret: &[u8],
    reticulum_path: &Path,
) -> Vec<String> {
    identity_oracle_hex_args(&hex(ciphertext), recipient_secret, reticulum_path)
}

fn identity_oracle_hex_args(
    ciphertext_hex: &str,
    recipient_secret: &[u8],
    reticulum_path: &Path,
) -> Vec<String> {
    vec![
        "identity-decrypt".to_owned(),
        "--hex".to_owned(),
        ciphertext_hex.to_owned(),
        "--test-recipient-secret-identity-hex".to_owned(),
        hex(recipient_secret),
        "--reticulum-path".to_owned(),
        reticulum_path.to_string_lossy().into_owned(),
    ]
}

fn identity_encrypt_oracle_args(
    recipient_public: &[u8],
    plaintext: &[u8],
    reticulum_path: &Path,
) -> Vec<String> {
    vec![
        "identity-encrypt".to_owned(),
        "--case".to_owned(),
        "identity_encrypt.fixed_ephemeral.fixed_iv.basic_001".to_owned(),
        "--test-recipient-public-identity-hex".to_owned(),
        hex(recipient_public),
        "--test-recipient-secret-identity-hex".to_owned(),
        hex(&TEST_SECRET_IDENTITY_BYTES),
        "--test-plaintext-hex".to_owned(),
        hex(plaintext),
        "--test-ephemeral-secret-hex".to_owned(),
        hex(&EPHEMERAL_SECRET),
        "--test-iv-hex".to_owned(),
        hex(&TOKEN_IV),
        "--reticulum-path".to_owned(),
        reticulum_path.to_string_lossy().into_owned(),
    ]
}

fn ifac_oracle_args(reticulum_path: &Path) -> Vec<String> {
    ifac_oracle_hex_args(IFAC_VECTOR_HEX, reticulum_path)
}

fn ifac_oracle_hex_args(masked_hex: &str, reticulum_path: &Path) -> Vec<String> {
    vec![
        "ifac-verify".to_owned(),
        "--hex".to_owned(),
        masked_hex.to_owned(),
        "--test-ifac-identity-secret-hex".to_owned(),
        hex(&IFAC_SECRET_IDENTITY),
        "--test-ifac-key-hex".to_owned(),
        hex(&IFAC_KEY),
        "--test-ifac-size".to_owned(),
        "8".to_owned(),
        "--reticulum-path".to_owned(),
        reticulum_path.to_string_lossy().into_owned(),
    ]
}

fn ifac_apply_oracle_args(reticulum_path: &Path) -> Vec<String> {
    vec![
        "ifac-apply".to_owned(),
        "--case".to_owned(),
        "ifac.apply_verify.size8.basic_001".to_owned(),
        "--test-ifac-identity-secret-hex".to_owned(),
        hex(&IFAC_SECRET_IDENTITY),
        "--test-ifac-key-hex".to_owned(),
        hex(&IFAC_KEY),
        "--test-ifac-size".to_owned(),
        "8".to_owned(),
        "--reticulum-path".to_owned(),
        reticulum_path.to_string_lossy().into_owned(),
    ]
}

fn assert_identity_decrypt_failed(
    ciphertext: &[u8],
    reticulum_path: &Path,
) -> Result<(), OracleToolError> {
    let args = identity_oracle_args(ciphertext, &TEST_SECRET_IDENTITY_BYTES, reticulum_path);
    let Some(response) = run_oracle_with_packages(&args)? else {
        return Ok(());
    };

    assert_eq!(response.command, "identity-decrypt");
    assert_eq!(response.oracle.mode, "python_reticulum");
    assert_eq!(response.valid, Some(false));
    assert_eq!(response.error, Some("decrypt_failed".to_owned()));
    Ok(())
}

fn reticulum_path_for_tool() -> Result<Option<PathBuf>, OracleToolError> {
    if let Some(path) = std::env::var_os("HYF_RETICULUM_PATH").map(PathBuf::from)
        && let Some(path) = resolve_reticulum_candidate(path.clone())?
    {
        return Ok(Some(path));
    } else if std::env::var_os("HYF_RETICULUM_PATH").is_some() && oracle_strict() {
        return Err(OracleToolError::InvalidEnvironment(
            "invalid oracle environment: HYF_RETICULUM_PATH is unavailable".to_owned(),
        ));
    }

    let default_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("refs/Reticulum");
    let resolved = resolve_reticulum_candidate(default_path)?;
    if resolved.is_none() && oracle_strict() {
        return Err(OracleToolError::InvalidEnvironment(
            "invalid oracle environment: Reticulum path unavailable".to_owned(),
        ));
    }
    Ok(resolved)
}

fn resolve_reticulum_candidate(path: PathBuf) -> Result<Option<PathBuf>, OracleToolError> {
    if path.is_dir() {
        return Ok(Some(path.canonicalize()?));
    }
    if path.is_absolute() {
        return Ok(None);
    }

    let current_dir_path = std::env::current_dir()?.join(&path);
    if current_dir_path.is_dir() {
        return Ok(Some(current_dir_path.canonicalize()?));
    }

    let workspace_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(&path);
    if workspace_path.is_dir() {
        return Ok(Some(workspace_path.canonicalize()?));
    }

    Ok(None)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn oracle_unavailable<T>(message: &str) -> Result<Option<T>, OracleToolError> {
    if oracle_strict() {
        Err(OracleToolError::InvalidEnvironment(message.to_owned()))
    } else {
        eprintln!("{message}");
        Ok(None)
    }
}

fn oracle_strict() -> bool {
    matches!(
        std::env::var("HYF_RNS_ORACLE_STRICT").as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

#[derive(Debug, Deserialize)]
struct OracleResponse {
    command: String,
    oracle: OracleMetadata,
    case: Option<OracleCase>,
    valid: Option<bool>,
    plaintext_hex: Option<String>,
    token_hex: Option<String>,
    ciphertext_token_hex: Option<String>,
    ephemeral_public_hex: Option<String>,
    masked_hex: Option<String>,
    reticulum_self_validation: Option<String>,
    test_only_secret_material: Option<bool>,
    unmasked_hex: Option<String>,
    encoded_hex: Option<String>,
    frames: Option<Vec<OracleFrame>>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OracleMetadata {
    mode: String,
    reticulum: ReticulumMetadata,
}

#[derive(Debug, Deserialize)]
struct ReticulumMetadata {
    commit: String,
}

#[derive(Debug, Deserialize)]
struct OracleCase {
    encoded_hex: Option<String>,
    kiss_frame_hex: Option<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct OracleFrame {
    kind: String,
    command_hex: String,
    payload_hex: String,
}

#[derive(Debug)]
enum OracleToolError {
    Io(String),
    Json(String),
    Crypto(String),
    InvalidEnvironment(String),
    OracleFailed(String),
}

impl From<std::io::Error> for OracleToolError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for OracleToolError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<RnsCryptoError> for OracleToolError {
    fn from(error: RnsCryptoError) -> Self {
        Self::Crypto(error.to_string())
    }
}

impl std::fmt::Display for OracleToolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error)
            | Self::Json(error)
            | Self::Crypto(error)
            | Self::InvalidEnvironment(error)
            | Self::OracleFailed(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for OracleToolError {}

const TOKEN_VECTOR_HEX: &str = concat!(
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "111c0579413c7cd45de041e1e99e50a79a67288e721b62e303e18a6d4afcc34c75ff",
    "00a0919f0a0e67686886ede87f67",
);

const IFAC_VECTOR_HEX: &str = "dd38fc4c4749c011f90f9628d201d3afb2ff08c0741fd11d98a37c1b54ad";
const IFAC_MISSING_PACKET_ACCESS_CODE_HEX: &str =
    "0038fc4c4749c011f90f9628d201d3afb2ff08c0741fd11d98a37c1b54ad";
const IFAC_RAW_PACKET_HEX: &str = "00031111111111111111111111111111111100aabbcc";

const TOKEN_PLAINTEXT: &[u8] = b"hello token";
const TOKEN_KEY_32: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const TOKEN_IV: [u8; RNS_TOKEN_IV_LEN] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const TEST_SECRET_IDENTITY_BYTES: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const TEST_PUBLIC_IDENTITY_BYTES: [u8; 64] = [
    0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2, 0x14, 0xea, 0x76, 0x7a, 0x6e,
    0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b, 0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f,
    0x29, 0xac, 0xba, 0xe1, 0x41, 0xbc, 0xca, 0xf0, 0xb2, 0x2e, 0x1a, 0x94, 0xd3, 0x4d, 0x0b, 0xc7,
    0x36, 0x1e, 0x52, 0x6d, 0x0b, 0xfe, 0x12, 0xc8, 0x97, 0x94, 0xbc, 0x93, 0x22, 0x96, 0x6d, 0xd7,
];
const EPHEMERAL_SECRET: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
const IFAC_KEY: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const IFAC_SECRET_IDENTITY: [u8; 64] = TEST_SECRET_IDENTITY_BYTES;
