#![no_main]

use hyf_rns_core::RNS_MTU;
use hyf_rns_wire::{packet_hash, packet_truncated_hash, write_packet_hashable_part};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoded = [0; RNS_MTU];
    let mut hashable = [0; RNS_MTU];
    let input = hyf_fuzz::seed_input::input_bytes(data, &mut decoded);

    let _ = write_packet_hashable_part(input, &mut hashable);
    let _ = packet_hash(input);
    let _ = packet_truncated_hash(input);
});
