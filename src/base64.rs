use anyhow::{bail, Result};

const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode binary data to Base64, appending to `output`.
pub fn binary_to_base64(binary_data: &[u8], output: &mut Vec<u8>) {
    let input_size = binary_data.len();
    let output_size = ((input_size + 2) / 3) * 4;
    let base_offset = output.len();
    output.resize(base_offset + output_size, 0);

    let mut out = base_offset;
    let mut i = 0;
    while i < input_size {
        let a = binary_data[i];
        let b = if i + 1 < input_size { binary_data[i + 1] } else { 0 };
        let c = if i + 2 < input_size { binary_data[i + 2] } else { 0 };

        let triple = (a as u32) << 16 | (b as u32) << 8 | c as u32;

        output[out] = BASE64_TABLE[((triple >> 18) & 0x3F) as usize];
        output[out + 1] = BASE64_TABLE[((triple >> 12) & 0x3F) as usize];
        output[out + 2] = if i + 1 < input_size {
            BASE64_TABLE[((triple >> 6) & 0x3F) as usize]
        } else {
            b'='
        };
        output[out + 3] = if i + 2 < input_size {
            BASE64_TABLE[(triple & 0x3F) as usize]
        } else {
            b'='
        };
        out += 4;
        i += 3;
    }
}

/// Decode Base64 data and append the raw bytes to `destination`.
pub fn append_base64_as_binary(base64_data: &[u8], destination: &mut Vec<u8>) -> Result<()> {
    #[rustfmt::skip]
    const DECODE_TABLE: [i8; 256] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    ];

    let input_size = base64_data.len();
    if input_size == 0 || (input_size % 4) != 0 {
        bail!("Base64 input size must be a multiple of 4 and non-empty");
    }

    destination.reserve(input_size * 3 / 4);

    for i in (0..input_size).step_by(4) {
        let c0 = base64_data[i];
        let c1 = base64_data[i + 1];
        let c2 = base64_data[i + 2];
        let c3 = base64_data[i + 3];

        let p2 = c2 == b'=';
        let p3 = c3 == b'=';

        if p2 && !p3 {
            bail!("Invalid Base64 padding: '==' required when third char is '='");
        }
        if (p2 || p3) && (i + 4 < input_size) {
            bail!("Padding '=' may only appear in the final quartet");
        }

        let v0 = DECODE_TABLE[c0 as usize];
        let v1 = DECODE_TABLE[c1 as usize];
        let v2 = if p2 { 0 } else { DECODE_TABLE[c2 as usize] };
        let v3 = if p3 { 0 } else { DECODE_TABLE[c3 as usize] };

        if v0 < 0 || v1 < 0 || (!p2 && v2 < 0) || (!p3 && v3 < 0) {
            bail!("Invalid Base64 character encountered");
        }

        let triple = (v0 as u32) << 18 | (v1 as u32) << 12 | (v2 as u32) << 6 | v3 as u32;

        destination.push(((triple >> 16) & 0xFF) as u8);
        if !p2 {
            destination.push(((triple >> 8) & 0xFF) as u8);
        }
        if !p3 {
            destination.push((triple & 0xFF) as u8);
        }
    }
    Ok(())
}
