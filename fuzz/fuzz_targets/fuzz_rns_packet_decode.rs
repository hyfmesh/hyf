#![no_main]

use hyf_rns_wire::decode_packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_packet(data);
});
