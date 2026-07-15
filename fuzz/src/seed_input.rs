use hyf_rns_core::RNS_MTU;

pub fn input_bytes<'a>(data: &'a [u8], decoded: &'a mut [u8; RNS_MTU]) -> &'a [u8] {
    let trimmed = trim_ascii_whitespace(data);
    if !trimmed.len().is_multiple_of(2) || trimmed.len() / 2 > decoded.len() {
        return data;
    }

    if let Some(decoded_len) = decode_lower_hex(trimmed, decoded) {
        return &decoded[..decoded_len];
    }

    data
}

fn trim_ascii_whitespace(input: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = input.len();

    while start < end && input[start].is_ascii_whitespace() {
        start += 1;
    }

    while end > start && input[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    &input[start..end]
}

fn decode_lower_hex(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut offset = 0;
    for pair in input.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[offset] = (high << 4) | low;
        offset += 1;
    }

    Some(offset)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    use hyf_rns_core::RNS_MTU;

    use super::input_bytes;

    const TRACKED_TEXT_HEX_CORPUS: &[(&str, usize)] = &[
        ("corpus/fuzz_bitchat_packet_decode/compressed_structural", 29),
        ("corpus/fuzz_bitchat_packet_decode/reserved_flags", 29),
        ("corpus/fuzz_bitchat_packet_decode/truncated_header", 2),
        ("corpus/fuzz_bitchat_packet_decode/v1_plain", 27),
        ("corpus/fuzz_bitchat_packet_decode/v2_plain", 29),
        ("corpus/fuzz_bitchat_packet_decode/v2_route", 46),
        ("corpus/fuzz_ifac_verify/valid_masked_packet", 30),
        ("corpus/fuzz_kiss_decoder/escaped_data_frame", 8),
        ("corpus/fuzz_lxmf_message_decode/full_message4", 121),
        ("corpus/fuzz_lxmf_message_decode/full_message5", 125),
        ("corpus/fuzz_rnode_command_parser/rx_stat_frame", 7),
        ("corpus/fuzz_rns_announce_decode/negative_context_flag", 188),
        ("corpus/fuzz_rns_announce_decode/negative_destination", 188),
        ("corpus/fuzz_rns_announce_decode/too_short", 1),
        ("corpus/fuzz_rns_announce_decode/valid_app_data", 188),
        ("corpus/fuzz_rns_announce_decode/valid_no_app_data", 167),
        ("corpus/fuzz_rns_packet_decode/header1_packet", 29),
        ("corpus/fuzz_rns_packet_decode/header2_packet", 45),
        ("corpus/fuzz_rns_packet_decode/too_short", 1),
        ("corpus/fuzz_rns_packet_hash/header1_packet", 34),
        ("corpus/fuzz_rns_packet_hash/header2_transport_a", 50),
        ("corpus/fuzz_rns_packet_hash/header2_transport_b", 50),
        ("corpus/fuzz_rns_packet_hash/too_short", 1),
        ("corpus/fuzz_single_packet_decrypt/valid_ciphertext_token", 96),
        ("corpus/fuzz_token_decrypt/basic_token", 64),
    ];

    #[test]
    fn lowercase_text_hex_decodes_to_binary() {
        let mut decoded = [0; RNS_MTU];

        assert_eq!(input_bytes(b"0001ff", &mut decoded), &[0x00, 0x01, 0xff]);
    }

    #[test]
    fn surrounding_ascii_whitespace_is_trimmed_before_decode() {
        let mut decoded = [0; RNS_MTU];

        assert_eq!(input_bytes(b"\n\t0a0b  \r", &mut decoded), &[0x0a, 0x0b]);
    }

    #[test]
    fn malformed_or_non_hex_input_remains_raw() {
        let mut decoded = [0; RNS_MTU];

        assert_eq!(input_bytes(b"abc", &mut decoded), b"abc");
        assert_eq!(input_bytes(b"not hex", &mut decoded), b"not hex");
        assert_eq!(input_bytes(b"0A", &mut decoded), b"0A");
    }

    #[test]
    fn oversized_decoded_input_remains_raw() {
        let oversized = vec![b'0'; (RNS_MTU + 1) * 2];
        let mut decoded = [0; RNS_MTU];

        assert_eq!(input_bytes(&oversized, &mut decoded), oversized.as_slice());
    }

    #[test]
    fn tracked_text_hex_corpus_decodes_to_expected_lengths() -> Result<(), Box<dyn std::error::Error>>
    {
        let fuzz_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(actual_corpus_paths(fuzz_root)?, expected_corpus_paths());

        for (relative_path, expected_len) in TRACKED_TEXT_HEX_CORPUS {
            let seed = fs::read(fuzz_root.join(relative_path))?;
            let mut decoded = [0; RNS_MTU];
            let input = input_bytes(&seed, &mut decoded);
            assert_eq!(
                input.len(),
                *expected_len,
                "decoded length mismatch for {relative_path}"
            );
            assert_ne!(
                input.len(),
                seed.len(),
                "seed was not decoded from text hex: {relative_path}"
            );
        }

        Ok(())
    }

    fn expected_corpus_paths() -> BTreeSet<String> {
        TRACKED_TEXT_HEX_CORPUS
            .iter()
            .map(|(path, _len)| (*path).to_owned())
            .collect()
    }

    fn actual_corpus_paths(fuzz_root: &Path) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
        let corpus_root = fuzz_root.join("corpus");
        let mut paths = BTreeSet::new();
        for target_entry in fs::read_dir(corpus_root)? {
            let target_entry = target_entry?;
            if !target_entry.file_type()?.is_dir() {
                continue;
            }
            let target_name = target_entry.file_name().into_string().map_err(|name| {
                std::io::Error::other(format!("non-UTF-8 corpus directory: {name:?}"))
            })?;

            for seed_entry in fs::read_dir(target_entry.path())? {
                let seed_entry = seed_entry?;
                if !seed_entry.file_type()?.is_file() {
                    continue;
                }
                let seed_name = seed_entry.file_name().into_string().map_err(|name| {
                    std::io::Error::other(format!("non-UTF-8 corpus seed: {name:?}"))
                })?;
                paths.insert(format!("corpus/{target_name}/{seed_name}"));
            }
        }
        Ok(paths)
    }
}
