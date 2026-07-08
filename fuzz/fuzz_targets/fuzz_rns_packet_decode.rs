#![no_main]

mod seed_input;

use hyf_rns_core::RNS_MTU;
use hyf_rns_wire::decode_packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoded = [0; RNS_MTU];
    let input = seed_input::input_bytes(data, &mut decoded);

    let _ = decode_packet(input);
});
