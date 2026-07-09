use std::{fmt::Display, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use hyf_rns_crypto::{
    rns_hkdf_sha256, secret_identity_from_bytes, token_decrypt, token_encrypt_with_iv,
};
use hyf_rns_wire::{ifac_apply_outbound, ifac_verify_inbound};

const KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const IV: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const PLAINTEXT: [u8; 383] = [0x42; 383];
const IFAC_SIZE: usize = 8;
const IFAC_KEY: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const IFAC_SECRET_IDENTITY: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const IFAC_RAW_PACKET_LEN: usize = 492;
const IFAC_MASKED_PACKET_LEN: usize = 500;

fn profile2_crypto_benchmarks(criterion: &mut Criterion) {
    benchmark_hkdf(criterion);
    benchmark_token_encrypt(criterion);
    benchmark_token_decrypt(criterion);
    benchmark_ifac_apply(criterion);
    benchmark_ifac_verify(criterion);
}

fn benchmark_hkdf(criterion: &mut Criterion) {
    criterion.bench_function("profile2_hkdf_64", |bench| {
        bench.iter(|| {
            let mut output = [0; 64];
            let _ = rns_hkdf_sha256(
                black_box(&mut output),
                black_box(b"hyf hkdf ikm"),
                black_box(None),
                black_box(Some(b"hyf-context")),
            );
        });
    });
}

fn benchmark_token_encrypt(criterion: &mut Criterion) {
    criterion.bench_function("profile2_token_encrypt_383", |bench| {
        bench.iter(|| {
            let mut output = [0; 512];
            let _ = token_encrypt_with_iv(
                black_box(&KEY),
                black_box(&PLAINTEXT),
                black_box(IV),
                black_box(&mut output),
            );
        });
    });
}

fn benchmark_token_decrypt(criterion: &mut Criterion) {
    let mut token = [0; 512];
    let token_len = benchmark_input(
        "profile2 token decrypt input",
        token_encrypt_with_iv(&KEY, &PLAINTEXT, IV, &mut token),
    );

    criterion.bench_function("profile2_token_decrypt_383", |bench| {
        bench.iter(|| {
            let mut output = [0; 512];
            let _ = token_decrypt(
                black_box(&KEY),
                black_box(&token[..token_len]),
                black_box(&mut output),
            );
        });
    });
}

fn benchmark_ifac_apply(criterion: &mut Criterion) {
    let identity = benchmark_input(
        "profile2 IFAC identity",
        secret_identity_from_bytes(&IFAC_SECRET_IDENTITY),
    );
    let raw_packet = ifac_raw_packet();

    criterion.bench_function("profile2_ifac_apply_500", |bench| {
        bench.iter(|| {
            let mut output = [0; IFAC_MASKED_PACKET_LEN];
            let _ = ifac_apply_outbound(
                black_box(&raw_packet),
                black_box(&identity),
                black_box(&IFAC_KEY),
                black_box(IFAC_SIZE),
                black_box(&mut output),
            );
        });
    });
}

fn benchmark_ifac_verify(criterion: &mut Criterion) {
    let identity = benchmark_input(
        "profile2 IFAC identity",
        secret_identity_from_bytes(&IFAC_SECRET_IDENTITY),
    );
    let raw_packet = ifac_raw_packet();
    let mut masked_packet = [0; IFAC_MASKED_PACKET_LEN];
    let masked_len = benchmark_input(
        "profile2 IFAC verify input",
        ifac_apply_outbound(
            &raw_packet,
            &identity,
            &IFAC_KEY,
            IFAC_SIZE,
            &mut masked_packet,
        ),
    );

    criterion.bench_function("profile2_ifac_verify_500", |bench| {
        bench.iter(|| {
            let mut output = [0; IFAC_RAW_PACKET_LEN];
            let _ = ifac_verify_inbound(
                black_box(&masked_packet[..masked_len]),
                black_box(&identity),
                black_box(&IFAC_KEY),
                black_box(IFAC_SIZE),
                black_box(&mut output),
            );
        });
    });
}

fn ifac_raw_packet() -> [u8; IFAC_RAW_PACKET_LEN] {
    let mut packet = [0x42; IFAC_RAW_PACKET_LEN];
    packet[0] = 0x00;
    packet[1] = 0x01;
    packet
}

fn benchmark_input<T, E: Display>(name: &str, result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("profile2 benchmark setup failed for {name}: {error}");
            std::process::exit(2);
        }
    }
}

criterion_group!(benches, profile2_crypto_benchmarks);
criterion_main!(benches);
