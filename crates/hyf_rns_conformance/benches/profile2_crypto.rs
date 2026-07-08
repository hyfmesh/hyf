use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use hyf_rns_crypto::{rns_hkdf_sha256, token_decrypt, token_encrypt_with_iv};

const KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const IV: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const PLAINTEXT: [u8; 383] = [0x42; 383];

fn profile2_crypto_benchmarks(criterion: &mut Criterion) {
    benchmark_hkdf(criterion);
    benchmark_token_encrypt(criterion);
    benchmark_token_decrypt(criterion);
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
    let token_len = token_encrypt_with_iv(&KEY, &PLAINTEXT, IV, &mut token).unwrap_or(0);

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

criterion_group!(benches, profile2_crypto_benchmarks);
criterion_main!(benches);
