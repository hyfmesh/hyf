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
    use super::{
        ANNOUNCE_PACKET, HEADER_1_PACKET, HEADER_2_PACKET, PACKET_HASH_INPUT, announce_packet,
        header_1_packet, header_2_packet, packet_hash_input, secret_identity,
    };

    const PACKET_HEADER_FIXTURE: &str =
        include_str!("../../../fixtures/rns/packet_header_vectors.json");
    const PACKET_HASH_FIXTURE: &str =
        include_str!("../../../fixtures/rns/packet_hash_vectors.json");
    const ANNOUNCE_FIXTURE: &str = include_str!("../../../fixtures/rns/announce_vectors.json");

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
}
