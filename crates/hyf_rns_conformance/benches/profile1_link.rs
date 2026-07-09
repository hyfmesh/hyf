use std::{fmt::Display, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use hyf_link_kiss::{KissDecoder, encode_data_frame};
use hyf_link_rnode::{RNodeCommand, encode_command, parse_command_frame};

const PAYLOAD: [u8; 500] = [0xc0; 500];

fn profile1_link_benchmarks(criterion: &mut Criterion) {
    benchmark_kiss_encode(criterion);
    benchmark_kiss_decode(criterion);
    benchmark_rnode_encode(criterion);
    benchmark_rnode_parse(criterion);
}

fn benchmark_kiss_encode(criterion: &mut Criterion) {
    criterion.bench_function("profile1_kiss_encode_500", |bench| {
        bench.iter(|| {
            let mut output = [0; 1003];
            let _ = encode_data_frame(black_box(&PAYLOAD), black_box(&mut output));
        });
    });
}

fn benchmark_kiss_decode(criterion: &mut Criterion) {
    let mut frame = [0; 1003];
    let frame_len = benchmark_input(
        "profile1 KISS decode frame",
        encode_data_frame(&PAYLOAD, &mut frame),
    );

    criterion.bench_function("profile1_kiss_decode_500", |bench| {
        bench.iter(|| {
            let mut decoder = KissDecoder::<512>::new();
            let _ = decoder.push_bytes(black_box(&frame[..frame_len]), |_| Ok(()));
        });
    });
}

fn benchmark_rnode_encode(criterion: &mut Criterion) {
    criterion.bench_function("profile1_rnode_encode_frequency", |bench| {
        bench.iter(|| {
            let mut output = [0; 16];
            let _ = encode_command(
                black_box(RNodeCommand::FrequencyHz(915_000_000)),
                black_box(&mut output),
            );
        });
    });
}

fn benchmark_rnode_parse(criterion: &mut Criterion) {
    let mut frame = [0; 8];
    let frame_len = benchmark_input(
        "profile1 RNode parse frame",
        encode_command(RNodeCommand::FrequencyHz(915_000_000), &mut frame),
    );

    criterion.bench_function("profile1_rnode_parse_frequency", |bench| {
        bench.iter(|| {
            let mut decoder = KissDecoder::<16>::new();
            let _ = decoder.push_bytes(black_box(&frame[..frame_len]), |frame| {
                let _ = parse_command_frame(black_box(frame));
                Ok(())
            });
        });
    });
}

fn benchmark_input<T, E: Display>(name: &str, result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("profile1 benchmark setup failed for {name}: {error}");
            std::process::exit(2);
        }
    }
}

criterion_group!(benches, profile1_link_benchmarks);
criterion_main!(benches);
