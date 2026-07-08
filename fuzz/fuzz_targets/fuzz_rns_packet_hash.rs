#![no_main]

use hyf_rns_core::RNS_MTU;
use hyf_rns_wire::{packet_hash, packet_truncated_hash, write_packet_hashable_part};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut hashable = [0; RNS_MTU];

    let _ = write_packet_hashable_part(data, &mut hashable);
    let _ = packet_hash(data);
    let _ = packet_truncated_hash(data);
});
