use hyf_rns_core::RNS_MTU;

pub fn input_bytes<'a>(data: &'a [u8], decoded: &'a mut [u8; RNS_MTU]) -> &'a [u8] {
    let trimmed = trim_ascii_whitespace(data);
    if trimmed.len() % 2 != 0 || trimmed.len() / 2 > decoded.len() {
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
