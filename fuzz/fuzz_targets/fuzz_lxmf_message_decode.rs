#![no_main]

use hyf_rns_core::RNS_MTU;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoded = [0; RNS_MTU];
    let input = hyf_fuzz::seed_input::input_bytes(data, &mut decoded);

    let _ = hyf_lxmf_core::decode_lxmf_message(input);
});
