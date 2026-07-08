use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use hyf_rns_conformance::benchmark_inputs::{
    APP_DATA, APP_NAME, ASPECTS, announce_packet, header_1_packet, header_2_packet,
    packet_hash_input, secret_identity,
};
use hyf_rns_conformance::fixtures::FixtureError;
use hyf_rns_core::{RNS_MTU, destination_name_hash};
use hyf_rns_wire::{
    RnsAnnounceEncodeParams, RnsClock, decode_packet, encode_announce_packet, packet_hash,
    validate_announce_packet,
};
use rand_core::{Infallible, TryRng};

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
    let header_1 = benchmark_input("header1 packet", header_1_packet());
    let header_2 = benchmark_input("header2 packet", header_2_packet());

    criterion.bench_function("profile0_header1_packet_decode", |bench| {
        bench.iter(|| {
            let _ = decode_packet(black_box(header_1.as_slice()));
        });
    });

    criterion.bench_function("profile0_header2_packet_decode", |bench| {
        bench.iter(|| {
            let _ = decode_packet(black_box(header_2.as_slice()));
        });
    });
}

fn benchmark_packet_hash(criterion: &mut Criterion) {
    let packet = benchmark_input("packet hash input", packet_hash_input());

    criterion.bench_function("profile0_packet_hash", |bench| {
        bench.iter(|| {
            let _ = packet_hash(black_box(packet.as_slice()));
        });
    });
}

fn benchmark_announce_validate(criterion: &mut Criterion) {
    let announce_packet = benchmark_input("announce packet", announce_packet());

    criterion.bench_function("profile0_announce_validate", |bench| {
        bench.iter(|| {
            if let Ok(packet) = decode_packet(black_box(announce_packet.as_slice())) {
                let _ = validate_announce_packet(packet);
            }
        });
    });
}

fn benchmark_announce_encode(criterion: &mut Criterion) {
    let secret_identity = benchmark_input("secret identity", secret_identity());
    let public_identity = benchmark_input(
        "public identity",
        secret_identity
            .public_identity()
            .map_err(FixtureError::from),
    );

    criterion.bench_function("profile0_announce_encode", |bench| {
        bench.iter(|| {
            let mut output = [0; RNS_MTU];
            let mut rng = FixedRng::new([0x01, 0x02, 0x03, 0x04, 0x05]);
            let clock = FixedClock(0x01_0203_0405);

            let _ = encode_announce_packet(
                RnsAnnounceEncodeParams {
                    secret_identity: black_box(&secret_identity),
                    public_identity: black_box(public_identity),
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

fn benchmark_input<T>(name: &str, result: Result<T, FixtureError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("profile0 benchmark setup failed for {name}: {error}");
            std::process::exit(2);
        }
    }
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
