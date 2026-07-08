#![cfg(feature = "python_oracle")]

use std::path::{Path, PathBuf};
use std::process::Command;

use hyf_rns_conformance::{
    OracleInvalidEnvironment, OracleStatus, PINNED_CRYPTOGRAPHY_PACKAGE, PINNED_PYSERIAL_PACKAGE,
    check_oracle_environment_from_env, profile0::PYTHON_ORACLE_SCRIPT,
};
use hyf_rns_core::{RNS_MTU, RNS_TRUNCATED_HASH_LEN, RnsDestinationHash};
use hyf_rns_crypto::secret_identity_from_bytes;
use hyf_rns_wire::{
    RNS_CONTEXT_NONE, RNS_CONTEXT_PATH_RESPONSE, RnsAnnounceEncodeParams, RnsClock,
    RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketRef, RnsPacketType,
    RnsTransportType, RnsWireError, encode_announce_packet, encode_packet, packet_hash,
    packet_truncated_hash,
};
use rand_core::{Infallible, TryRng};
use serde::{Deserialize, Serialize};

#[test]
fn rust_generated_packets_and_announces_validate_in_python_reticulum() -> Result<(), OracleTestError>
{
    require_ready_oracle()?;

    let header_1_packet = encode_header_1_packet()?;
    let header_2_packet = encode_header_2_packet()?;
    let full_hash = packet_hash(&header_2_packet)?.into_bytes();
    let truncated_hash = packet_truncated_hash(&header_2_packet)?.into_bytes();
    let announce_packet = encode_test_announce()?;
    let request = OracleRequest {
        header_1_packet: hex(&header_1_packet),
        header_2_packet: hex(&header_2_packet),
        hash_packet: hex(&header_2_packet),
        expected_full_hash: hex(&full_hash),
        expected_truncated_hash: hex(&truncated_hash),
        announce_packet: hex(&announce_packet),
    };
    let response = run_reticulum_oracle(&request)?;

    assert!(response.header_1.unpack_ok);
    assert_eq!(response.header_1.header_type, 0);
    assert_eq!(response.header_1.transport_id, None);
    assert_eq!(
        response.header_1.destination_hash,
        "11111111111111111111111111111111"
    );
    assert_eq!(response.header_1.data, "6865616465722d6f6e65");
    assert!(response.header_2.unpack_ok);
    assert_eq!(response.header_2.header_type, 1);
    assert_eq!(
        response.header_2.transport_id,
        Some("22222222222222222222222222222222".to_owned())
    );
    assert_eq!(
        response.header_2.destination_hash,
        "33333333333333333333333333333333"
    );
    assert_eq!(response.header_2.context, 0x0b);
    assert_eq!(response.header_2.data, "6865616465722d74776f");
    assert_eq!(response.full_hash, request.expected_full_hash);
    assert_eq!(response.truncated_hash, request.expected_truncated_hash);
    assert!(response.announce_valid);

    Ok(())
}

fn require_ready_oracle() -> Result<(), OracleTestError> {
    let readiness = check_oracle_environment_from_env();
    if readiness.status() == OracleStatus::Passed {
        return Ok(());
    }

    Err(OracleTestError::InvalidEnvironment(readiness.reason()))
}

fn encode_header_1_packet() -> Result<Vec<u8>, RnsWireError> {
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

fn encode_header_2_packet() -> Result<Vec<u8>, RnsWireError> {
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

fn encode_test_announce() -> Result<Vec<u8>, OracleTestError> {
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

fn run_reticulum_oracle(request: &OracleRequest) -> Result<OracleResponse, OracleTestError> {
    let reticulum_path = reticulum_path_from_env()?;
    let request_json = serde_json::to_string(request)?;
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
        return Err(OracleTestError::OracleFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

fn reticulum_path_from_env() -> Result<PathBuf, OracleTestError> {
    let Some(path) = std::env::var_os("HYF_RETICULUM_PATH").map(PathBuf::from) else {
        return Err(OracleTestError::InvalidEnvironment(Some(
            OracleInvalidEnvironment::MissingReticulumPath,
        )));
    };
    if path.is_dir() {
        return Ok(path);
    }
    if path.is_absolute() {
        return Err(OracleTestError::InvalidEnvironment(Some(
            OracleInvalidEnvironment::ReticulumPathNotDirectory,
        )));
    }

    let current_dir_path = std::env::current_dir()?.join(&path);
    if current_dir_path.is_dir() {
        return Ok(current_dir_path);
    }

    let workspace_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(&path);
    if workspace_path.is_dir() {
        return Ok(workspace_path);
    }

    Err(OracleTestError::InvalidEnvironment(Some(
        OracleInvalidEnvironment::ReticulumPathNotDirectory,
    )))
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

#[derive(Serialize)]
struct OracleRequest {
    header_1_packet: String,
    header_2_packet: String,
    hash_packet: String,
    expected_full_hash: String,
    expected_truncated_hash: String,
    announce_packet: String,
}

#[derive(Deserialize)]
struct OracleResponse {
    header_1: OraclePacket,
    header_2: OraclePacket,
    full_hash: String,
    truncated_hash: String,
    announce_valid: bool,
}

#[derive(Deserialize)]
struct OraclePacket {
    unpack_ok: bool,
    header_type: u8,
    transport_id: Option<String>,
    destination_hash: String,
    context: u8,
    data: String,
}

#[derive(Debug)]
enum OracleTestError {
    InvalidEnvironment(Option<OracleInvalidEnvironment>),
    Io(String),
    Json(String),
    OracleFailed(String),
    Crypto(hyf_rns_crypto::RnsCryptoError),
    Wire(RnsWireError),
}

impl From<std::io::Error> for OracleTestError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for OracleTestError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<hyf_rns_crypto::RnsCryptoError> for OracleTestError {
    fn from(error: hyf_rns_crypto::RnsCryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<RnsWireError> for OracleTestError {
    fn from(error: RnsWireError) -> Self {
        Self::Wire(error)
    }
}

impl std::fmt::Display for OracleTestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnvironment(Some(reason)) => {
                write!(formatter, "invalid oracle environment: {reason}")
            }
            Self::InvalidEnvironment(None) => {
                write!(formatter, "invalid oracle environment")
            }
            Self::Io(error) | Self::Json(error) | Self::OracleFailed(error) => {
                formatter.write_str(error)
            }
            Self::Crypto(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for OracleTestError {}

struct FixedClock(u64);

impl RnsClock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        self.0
    }
}

struct FixedRng {
    bytes: [u8; 5],
    offset: usize,
}

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

const TEST_SECRET_IDENTITY: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
