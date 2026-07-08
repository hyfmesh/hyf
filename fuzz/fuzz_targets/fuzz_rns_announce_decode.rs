#![no_main]

use hyf_rns_wire::{decode_announce_packet, decode_packet, validate_announce_packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = decode_packet(data) {
        let _ = decode_announce_packet(packet);
        let _ = validate_announce_packet(packet);
    }
});
