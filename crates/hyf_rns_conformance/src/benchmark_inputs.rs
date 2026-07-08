use hyf_rns_crypto::{RnsSecretIdentity, secret_identity_from_bytes};

use crate::fixtures::{FixtureError, decode_hex};

pub const HEADER_1_PACKET: &str = "00001112131415161718191a1b1c1d1e1f20006865616465722d6f6e65";
pub const HEADER_2_PACKET: &str =
    "75003132333435363738393a3b3c3d3e3f402122232425262728292a2b2c2d2e2f300b6865616465722d74776f";
pub const PACKET_HASH_INPUT: &str = "75006162636465666768696a6b6c6d6e6f705152535455565758595a5b5c5d5e5f600b686173682d6865616465722d74776f";
pub const ANNOUNCE_PACKET: &str = "010054664a7ce697fe2ae552af6fe4595fde008f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7cc320e7f81705ccb3cfe01020304050102030405deed98efafd34b32e0f903bc50a61540024c1e706dd4be388412376d842ab488105719ee28015b30097169aa6efb3ea0e56fc8822f2fe4bc0b00f41639425d0f68796620616e6e6f756e6365206170702064617461";
pub const APP_NAME: &str = "lxmf";
pub const ASPECTS: [&str; 1] = ["announce"];
pub const APP_DATA: &[u8] = b"benchmark announce app data";

const TEST_SECRET_IDENTITY: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

pub fn header_1_packet() -> Result<Vec<u8>, FixtureError> {
    decode_hex(HEADER_1_PACKET)
}

pub fn header_2_packet() -> Result<Vec<u8>, FixtureError> {
    decode_hex(HEADER_2_PACKET)
}

pub fn packet_hash_input() -> Result<Vec<u8>, FixtureError> {
    decode_hex(PACKET_HASH_INPUT)
}

pub fn announce_packet() -> Result<Vec<u8>, FixtureError> {
    decode_hex(ANNOUNCE_PACKET)
}

pub fn secret_identity() -> Result<RnsSecretIdentity, FixtureError> {
    Ok(secret_identity_from_bytes(&TEST_SECRET_IDENTITY)?)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        ANNOUNCE_PACKET, HEADER_1_PACKET, HEADER_2_PACKET, PACKET_HASH_INPUT, announce_packet,
        header_1_packet, header_2_packet, packet_hash_input, secret_identity,
    };

    const PACKET_HEADER_FIXTURE: &str =
        include_str!("../../../fixtures/rns/packet_header_vectors.json");
    const PACKET_HASH_FIXTURE: &str =
        include_str!("../../../fixtures/rns/packet_hash_vectors.json");
    const ANNOUNCE_FIXTURE: &str = include_str!("../../../fixtures/rns/announce_vectors.json");
    const TRACKED_FUZZ_CORPUS_SEEDS: &[&str] = &[
        "fuzz/corpus/fuzz_ifac_verify/valid_masked_packet",
        "fuzz/corpus/fuzz_kiss_decoder/escaped_data_frame",
        "fuzz/corpus/fuzz_rnode_command_parser/rx_stat_frame",
        "fuzz/corpus/fuzz_rns_announce_decode/negative_context_flag",
        "fuzz/corpus/fuzz_rns_announce_decode/negative_destination",
        "fuzz/corpus/fuzz_rns_announce_decode/too_short",
        "fuzz/corpus/fuzz_rns_announce_decode/valid_app_data",
        "fuzz/corpus/fuzz_rns_announce_decode/valid_no_app_data",
        "fuzz/corpus/fuzz_rns_packet_decode/header1_packet",
        "fuzz/corpus/fuzz_rns_packet_decode/header2_packet",
        "fuzz/corpus/fuzz_rns_packet_decode/too_short",
        "fuzz/corpus/fuzz_rns_packet_hash/header1_packet",
        "fuzz/corpus/fuzz_rns_packet_hash/header2_transport_a",
        "fuzz/corpus/fuzz_rns_packet_hash/header2_transport_b",
        "fuzz/corpus/fuzz_rns_packet_hash/too_short",
    ];

    #[test]
    fn benchmark_fixture_inputs_decode_and_secret_identity_parses() {
        assert!(header_1_packet().is_ok());
        assert!(header_2_packet().is_ok());
        assert!(packet_hash_input().is_ok());
        assert!(announce_packet().is_ok());
        assert!(secret_identity().is_ok());
    }

    #[test]
    fn benchmark_packet_inputs_are_present_in_fixture_corpus() {
        assert!(PACKET_HEADER_FIXTURE.contains(HEADER_1_PACKET));
        assert!(PACKET_HEADER_FIXTURE.contains(HEADER_2_PACKET));
        assert!(PACKET_HASH_FIXTURE.contains(PACKET_HASH_INPUT));
        assert!(ANNOUNCE_FIXTURE.contains(ANNOUNCE_PACKET));
    }

    #[test]
    fn tracked_fuzz_corpus_seed_set_is_stable() -> Result<(), Box<dyn std::error::Error>> {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .arg("ls-files")
            .arg("fuzz/corpus/**")
            .output()?;

        if !output.status.success() {
            return Err("git ls-files failed for fuzz corpus".into());
        }

        let mut actual = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        actual.sort();
        let actual = actual.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(actual.as_slice(), TRACKED_FUZZ_CORPUS_SEEDS);
        Ok(())
    }

    #[test]
    fn tracked_fuzz_corpus_copy_rejects_existing_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let destination_root = unique_test_path()?;
        let stale_corpus = destination_root.join("fuzz/corpus/fuzz_rns_packet_decode");
        std::fs::create_dir_all(&stale_corpus)?;
        std::fs::write(stale_corpus.join("stale_untracked_seed"), b"stale")?;

        let output = Command::new("sh")
            .arg("fuzz/copy_tracked_corpus.sh")
            .arg("fuzz_rns_packet_decode")
            .arg(&destination_root)
            .current_dir(repo_root)
            .output()?;
        let _ = std::fs::remove_dir_all(&destination_root);

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("destination root already exists")
        );
        Ok(())
    }

    #[test]
    fn tracked_fuzz_corpus_copy_cleans_empty_destination_for_missing_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let destination_root = unique_test_path()?;

        let output = Command::new("sh")
            .arg("fuzz/copy_tracked_corpus.sh")
            .arg("fuzz_rns_missing_target")
            .arg(&destination_root)
            .current_dir(repo_root)
            .output()?;
        let destination_exists = destination_root.exists();
        let _ = std::fs::remove_dir_all(&destination_root);

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("no tracked corpus seeds"));
        assert!(!destination_exists);
        Ok(())
    }

    fn unique_test_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!(
            "hyf-copy-tracked-corpus-{}-{nanos}",
            std::process::id()
        )))
    }
}
