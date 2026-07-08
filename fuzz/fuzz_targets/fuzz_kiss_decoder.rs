#![no_main]

mod seed_input;

use hyf_link_kiss::KissDecoder;
use hyf_rns_core::RNS_MTU;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoded = [0; RNS_MTU];
    let input = seed_input::input_bytes(data, &mut decoded);
    let mut decoder = KissDecoder::<512>::new();
    let _ = decoder.push_bytes(input, |_| Ok(()));
});
