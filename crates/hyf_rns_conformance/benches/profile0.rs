use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use hyf_rns_conformance::fixtures::decode_hex;
use hyf_rns_core::{RNS_MTU, destination_name_hash};
use hyf_rns_crypto::secret_identity_from_bytes;
use hyf_rns_wire::{
    RnsAnnounceEncodeParams, RnsClock, decode_packet, encode_announce_packet, packet_hash,
    validate_announce_packet,
};
use rand_core::{Infallible, TryRng};

const HEADER_1_PACKET: &str = "00001112131415161718191a1b1c1d1e1f20006865616465722d6f6e65";
const HEADER_2_PACKET: &str =
    "75003132333435363738393a3b3c3d3e3f402122232425262728292a2b2c2d2e2f300b6865616465722d74776f";
const PACKET_HASH_INPUT: &str = "75006162636465666768696a6b6c6d6e6f705152535455565758595a5b5c5d5e5f600b686173682d6865616465722d74776f";
const ANNOUNCE_PACKET: &str = "010054664a7ce697fe2ae552af6fe4595fde008f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7cc320e7f81705ccb3cfe01020304050102030405deed98efafd34b32e0f903bc50a61540024c1e706dd4be388412376d842ab488105719ee28015b30097169aa6efb3ea0e56fc8822f2fe4bc0b00f41639425d0f68796620616e6e6f756e6365206170702064617461";
const APP_NAME: &str = "lxmf";
const ASPECTS: [&str; 1] = ["announce"];
const APP_DATA: &[u8] = b"benchmark announce app data";
const TEST_SECRET_IDENTITY: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

fn profile0_benchmarks(criterion: &mut Criterion) {
    benchmark_destination_name_hash(criterion);
    benchmark_packet_decode(criterion);
    benchmark_packet_hash(criterion);
    benchmark_announce_validate(criterion);
    benchmark_announce_encode(criterion);
}

fn benchmark_destination_name_hash(criterion: &mut Criterion) {
    criterion.bench_function("profile0_destination_name_hash", |bench| {
        bench.iter(|| {
            let _ = destination_name_hash(black_box(APP_NAME), black_box(&ASPECTS));
        });
    });
}

fn benchmark_packet_decode(criterion: &mut Criterion) {
    let header_1 = fixture_bytes(HEADER_1_PACKET);
    let header_2 = fixture_bytes(HEADER_2_PACKET);

    if !header_1.is_empty() {
        criterion.bench_function("profile0_header1_packet_decode", |bench| {
            bench.iter(|| {
                let _ = decode_packet(black_box(header_1.as_slice()));
            });
        });
    }

    if !header_2.is_empty() {
        criterion.bench_function("profile0_header2_packet_decode", |bench| {
            bench.iter(|| {
                let _ = decode_packet(black_box(header_2.as_slice()));
            });
        });
    }
}

fn benchmark_packet_hash(criterion: &mut Criterion) {
    let packet = fixture_bytes(PACKET_HASH_INPUT);
    if packet.is_empty() {
        return;
    }

    criterion.bench_function("profile0_packet_hash", |bench| {
        bench.iter(|| {
            let _ = packet_hash(black_box(packet.as_slice()));
        });
    });
}

fn benchmark_announce_validate(criterion: &mut Criterion) {
    let announce_packet = fixture_bytes(ANNOUNCE_PACKET);
    if announce_packet.is_empty() {
        return;
    }

    criterion.bench_function("profile0_announce_validate", |bench| {
        bench.iter(|| {
            if let Ok(packet) = decode_packet(black_box(announce_packet.as_slice())) {
                let _ = validate_announce_packet(packet);
            }
        });
    });
}

fn benchmark_announce_encode(criterion: &mut Criterion) {
    let Some(secret_identity) = secret_identity_from_bytes(&TEST_SECRET_IDENTITY).ok() else {
        return;
    };

    criterion.bench_function("profile0_announce_encode", |bench| {
        bench.iter(|| {
            let mut output = [0; RNS_MTU];
            let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
            let clock = FixedClock(0x01_0203_0405);

            let _ = encode_announce_packet(
                RnsAnnounceEncodeParams {
                    secret_identity: black_box(&secret_identity),
                    app_name: black_box(APP_NAME),
                    aspects: black_box(&ASPECTS),
                    app_data: black_box(APP_DATA),
                },
                &mut rng,
                &clock,
                &mut output,
            );
        });
    });
}

fn fixture_bytes(hex: &str) -> Vec<u8> {
    decode_hex(hex).unwrap_or_default()
}

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

criterion_group!(benches, profile0_benchmarks);
criterion_main!(benches);
