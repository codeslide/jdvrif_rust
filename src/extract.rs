use super::*;
use std::path::Path;

fn search_sig(data: &[u8], sig: &[u8]) -> Option<usize> {
    if sig.is_empty() || data.len() < sig.len() {
        return None;
    }
    data.windows(sig.len()).position(|w| w == sig)
}

fn scan_file_windows<F>(
    path: &Path,
    overlap: usize,
    search_limit: usize,
    start_offset: usize,
    mut visitor: F,
) -> Result<(), String>
where
    F: FnMut(&[u8], usize) -> Result<bool, String>,
{
    let mut input = open_binary_input_or_throw(path, "Read Error: Failed to open image file.")?;
    if start_offset != 0 {
        input
            .seek(SeekFrom::Start(start_offset as u64))
            .map_err(|_| "Read Error: Failed to seek read position.".to_string())?;
    }

    const CHUNK_SIZE: usize = 1024 * 1024;
    let mut buffer = vec![0u8; CHUNK_SIZE + overlap];
    let mut carry = 0usize;
    let mut consumed = start_offset;

    loop {
        if search_limit != 0 && consumed >= search_limit {
            break;
        }

        let mut to_read = CHUNK_SIZE;
        if search_limit != 0 {
            to_read = to_read.min(search_limit - consumed);
        }

        let got = input
            .read(&mut buffer[carry..carry + to_read])
            .map_err(|_| "Read Error: Failed while scanning image file.".to_string())?;
        if got == 0 {
            break;
        }

        let window_size = carry + got;
        let base = consumed - carry;
        if visitor(&buffer[..window_size], base)? {
            break;
        }

        if overlap > 0 {
            carry = overlap.min(window_size);
            let src_start = window_size - carry;
            buffer.copy_within(src_start..window_size, 0);
        } else {
            carry = 0;
        }

        consumed = consumed
            .checked_add(got)
            .ok_or_else(|| "File Extraction Error: Signature scan offset overflow.".to_string())?;
    }

    Ok(())
}

pub(crate) fn find_signature_in_file(
    path: &Path,
    sig: &[u8],
    search_limit: usize,
    start_offset: usize,
) -> Result<Option<usize>, String> {
    if sig.is_empty() {
        return Ok(None);
    }
    if search_limit != 0 && search_limit <= start_offset {
        return Ok(None);
    }

    let mut found = None;
    let overlap = if sig.len() > 1 { sig.len() - 1 } else { 0 };

    scan_file_windows(path, overlap, search_limit, start_offset, |window, base| {
        if let Some(pos) = search_sig(window, sig) {
            found = Some(base + pos);
            return Ok(true);
        }
        Ok(false)
    })?;

    Ok(found)
}

struct DualSignatureLocations {
    first: Option<usize>,
    second: Option<usize>,
}

fn find_dual_signatures_in_file(
    path: &Path,
    first_sig: &[u8],
    second_sig: &[u8],
    search_limit: usize,
) -> Result<DualSignatureLocations, String> {
    if first_sig.is_empty() || second_sig.is_empty() {
        return Err("Internal Error: Invalid signature search arguments.".to_string());
    }

    let mut loc = DualSignatureLocations {
        first: None,
        second: None,
    };
    let overlap = first_sig.len().max(second_sig.len()).saturating_sub(1);

    scan_file_windows(path, overlap, search_limit, 0, |window, base| {
        if loc.first.is_none() {
            if let Some(pos) = search_sig(window, first_sig) {
                loc.first = Some(base + pos);
            }
        }
        if loc.second.is_none() {
            if let Some(pos) = search_sig(window, second_sig) {
                loc.second = Some(base + pos);
            }
        }
        Ok(loc.first.is_some() && loc.second.is_some())
    })?;

    Ok(loc)
}

pub(crate) fn read_exact_at(input: &mut File, offset: usize, out: &mut [u8]) -> Result<(), String> {
    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek read position.".to_string())?;
    input
        .read_exact(out)
        .map_err(|_| "Read Error: Failed to read expected bytes.".to_string())
}

pub(crate) fn has_signature_at(
    input: &mut File,
    image_size: usize,
    offset: usize,
    signature: &[u8],
) -> Result<bool, String> {
    if signature.is_empty()
        || offset > image_size
        || signature.len() > image_size.saturating_sub(offset)
    {
        return Ok(false);
    }

    let mut bytes = vec![0u8; signature.len()];
    read_exact_at(input, offset, &mut bytes)?;
    Ok(bytes == signature)
}

fn read_u16_at(input: &mut File, offset: usize) -> Result<u16, String> {
    let mut bytes = [0u8; 2];
    read_exact_at(input, offset, &mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn copy_bytes_to_output(
    input: &mut File,
    output: &mut BufWriter<File>,
    mut length: usize,
    copy_buffer: &mut [u8],
) -> Result<(), String> {
    if copy_buffer.is_empty() {
        return Err("Internal Error: Empty copy buffer.".to_string());
    }
    while length > 0 {
        let chunk = cmp::min(length, copy_buffer.len());
        input
            .read_exact(&mut copy_buffer[..chunk])
            .map_err(|_| "Read Error: Failed while extracting encrypted payload.".to_string())?;
        output
            .write_all(&copy_buffer[..chunk])
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        length -= chunk;
    }

    Ok(())
}

fn copy_range_to_output(
    input: &mut File,
    output: &mut BufWriter<File>,
    offset: usize,
    length: usize,
    copy_buffer: &mut [u8],
) -> Result<(), String> {
    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek payload position.".to_string())?;
    copy_bytes_to_output(input, output, length, copy_buffer)
}

fn copy_bytes_to_consumer<F>(
    input: &mut File,
    mut length: usize,
    copy_buffer: &mut [u8],
    consume: &mut F,
) -> Result<(), String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    if copy_buffer.is_empty() {
        return Err("Internal Error: Empty copy buffer.".to_string());
    }

    while length > 0 {
        let chunk = cmp::min(length, copy_buffer.len());
        input
            .read_exact(&mut copy_buffer[..chunk])
            .map_err(|_| "Read Error: Failed while extracting encrypted payload.".to_string())?;
        consume(&copy_buffer[..chunk])?;
        length -= chunk;
    }

    Ok(())
}

fn copy_range_to_consumer<F>(
    input: &mut File,
    offset: usize,
    length: usize,
    copy_buffer: &mut [u8],
    consume: &mut F,
) -> Result<(), String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek payload position.".to_string())?;
    copy_bytes_to_consumer(input, length, copy_buffer, consume)
}

fn skip_exact_bytes(input: &mut File, mut length: usize) -> Result<(), String> {
    const SKIP_CHUNK_SIZE: usize = 4096;
    let mut skip_buffer = [0u8; SKIP_CHUNK_SIZE];

    while length > 0 {
        let chunk = cmp::min(length, skip_buffer.len());
        input.read_exact(&mut skip_buffer[..chunk]).map_err(|_| {
            "Read Error: Failed while skipping ICC profile header bytes.".to_string()
        })?;
        length -= chunk;
    }

    Ok(())
}

fn decode_base64_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn stream_decode_base64_until_delimiter_to_output(
    input: &mut File,
    offset: usize,
    delimiter: u8,
    max_bytes: usize,
    expected_decoded_size: usize,
    output: &mut BufWriter<File>,
    corrupt_error: &str,
) -> Result<usize, String> {
    const READ_CHUNK_SIZE: usize = 4096;
    const WRITE_CHUNK_SIZE: usize = 4096;

    if max_bytes == 0 {
        return Err(corrupt_error.to_string());
    }

    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek read position.".to_string())?;

    let mut in_chunk = [0u8; READ_CHUNK_SIZE];
    let mut out_chunk = [0u8; WRITE_CHUNK_SIZE];
    let mut quartet = [0u8; 4];

    let mut quartet_len = 0usize;
    let mut out_len = 0usize;
    let mut decoded_total = 0usize;
    let mut scanned = 0usize;
    let mut found_delimiter = false;
    let mut saw_padding = false;

    let mut emit_decoded =
        |value: u8, out_len_ref: &mut usize, decoded_total_ref: &mut usize| -> Result<(), String> {
            if *decoded_total_ref >= expected_decoded_size {
                return Err(corrupt_error.to_string());
            }

            out_chunk[*out_len_ref] = value;
            *out_len_ref += 1;
            *decoded_total_ref += 1;

            if *out_len_ref == out_chunk.len() {
                output
                    .write_all(&out_chunk[..*out_len_ref])
                    .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
                *out_len_ref = 0;
            }

            Ok(())
        };

    while scanned < max_bytes && !found_delimiter {
        let chunk = cmp::min(READ_CHUNK_SIZE, max_bytes - scanned);
        let got = input
            .read(&mut in_chunk[..chunk])
            .map_err(|_| "Read Error: Failed while scanning XMP payload.".to_string())?;
        if got == 0 {
            break;
        }
        scanned += got;

        for &c in &in_chunk[..got] {
            if c == delimiter {
                found_delimiter = true;
                break;
            }

            if saw_padding {
                return Err(corrupt_error.to_string());
            }

            quartet[quartet_len] = c;
            quartet_len += 1;
            if quartet_len != 4 {
                continue;
            }

            let p2 = quartet[2] == b'=';
            let p3 = quartet[3] == b'=';
            if p2 && !p3 {
                return Err(corrupt_error.to_string());
            }

            let v0 = decode_base64_char(quartet[0]).ok_or_else(|| corrupt_error.to_string())?;
            let v1 = decode_base64_char(quartet[1]).ok_or_else(|| corrupt_error.to_string())?;
            let v2 = if p2 {
                0
            } else {
                decode_base64_char(quartet[2]).ok_or_else(|| corrupt_error.to_string())?
            };
            let v3 = if p3 {
                0
            } else {
                decode_base64_char(quartet[3]).ok_or_else(|| corrupt_error.to_string())?
            };

            let triple =
                ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);

            emit_decoded(
                ((triple >> 16) & 0xFF) as u8,
                &mut out_len,
                &mut decoded_total,
            )?;
            if !p2 {
                emit_decoded(
                    ((triple >> 8) & 0xFF) as u8,
                    &mut out_len,
                    &mut decoded_total,
                )?;
            }
            if !p3 {
                emit_decoded((triple & 0xFF) as u8, &mut out_len, &mut decoded_total)?;
            }

            saw_padding = p2 || p3;
            quartet_len = 0;
        }
    }

    if !found_delimiter || quartet_len != 0 || decoded_total != expected_decoded_size {
        return Err(corrupt_error.to_string());
    }

    if out_len > 0 {
        output
            .write_all(&out_chunk[..out_len])
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
    }

    Ok(decoded_total)
}

fn stream_decode_base64_until_delimiter_to_consumer<F>(
    input: &mut File,
    offset: usize,
    delimiter: u8,
    max_bytes: usize,
    expected_decoded_size: usize,
    consume: &mut F,
    corrupt_error: &str,
) -> Result<usize, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    const READ_CHUNK_SIZE: usize = 4096;
    const WRITE_CHUNK_SIZE: usize = 4096;

    if max_bytes == 0 {
        return Err(corrupt_error.to_string());
    }

    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek read position.".to_string())?;

    let mut in_chunk = [0u8; READ_CHUNK_SIZE];
    let mut out_chunk = [0u8; WRITE_CHUNK_SIZE];
    let mut quartet = [0u8; 4];

    let mut quartet_len = 0usize;
    let mut out_len = 0usize;
    let mut decoded_total = 0usize;
    let mut scanned = 0usize;
    let mut found_delimiter = false;
    let mut saw_padding = false;

    let mut emit_decoded =
        |value: u8, out_len_ref: &mut usize, decoded_total_ref: &mut usize| -> Result<(), String> {
            if *decoded_total_ref >= expected_decoded_size {
                return Err(corrupt_error.to_string());
            }

            out_chunk[*out_len_ref] = value;
            *out_len_ref += 1;
            *decoded_total_ref += 1;

            if *out_len_ref == out_chunk.len() {
                consume(&out_chunk[..*out_len_ref])?;
                *out_len_ref = 0;
            }

            Ok(())
        };

    while scanned < max_bytes && !found_delimiter {
        let chunk = cmp::min(READ_CHUNK_SIZE, max_bytes - scanned);
        let got = input
            .read(&mut in_chunk[..chunk])
            .map_err(|_| "Read Error: Failed while scanning XMP payload.".to_string())?;
        if got == 0 {
            break;
        }
        scanned += got;

        for &c in &in_chunk[..got] {
            if c == delimiter {
                found_delimiter = true;
                break;
            }

            if saw_padding {
                return Err(corrupt_error.to_string());
            }

            quartet[quartet_len] = c;
            quartet_len += 1;
            if quartet_len != 4 {
                continue;
            }

            let p2 = quartet[2] == b'=';
            let p3 = quartet[3] == b'=';
            if p2 && !p3 {
                return Err(corrupt_error.to_string());
            }

            let v0 = decode_base64_char(quartet[0]).ok_or_else(|| corrupt_error.to_string())?;
            let v1 = decode_base64_char(quartet[1]).ok_or_else(|| corrupt_error.to_string())?;
            let v2 = if p2 {
                0
            } else {
                decode_base64_char(quartet[2]).ok_or_else(|| corrupt_error.to_string())?
            };
            let v3 = if p3 {
                0
            } else {
                decode_base64_char(quartet[3]).ok_or_else(|| corrupt_error.to_string())?
            };

            let triple =
                ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);

            emit_decoded(
                ((triple >> 16) & 0xFF) as u8,
                &mut out_len,
                &mut decoded_total,
            )?;
            if !p2 {
                emit_decoded(
                    ((triple >> 8) & 0xFF) as u8,
                    &mut out_len,
                    &mut decoded_total,
                )?;
            }
            if !p3 {
                emit_decoded((triple & 0xFF) as u8, &mut out_len, &mut decoded_total)?;
            }

            saw_padding = p2 || p3;
            quartet_len = 0;
        }
    }

    if !found_delimiter || quartet_len != 0 || decoded_total != expected_decoded_size {
        return Err(corrupt_error.to_string());
    }

    if out_len > 0 {
        consume(&out_chunk[..out_len])?;
    }

    Ok(decoded_total)
}

pub(crate) fn extract_default_ciphertext_to_file(
    image_path: &Path,
    image_size: usize,
    base_offset: usize,
    embedded_file_size: usize,
    total_profile_header_segments: u16,
    output_path: &Path,
) -> Result<usize, String> {
    const ENCRYPTED_FILE_START_INDEX: usize = 0x33B;
    const HEADER_INDEX: usize = 0xFCB0;
    const PROFILE_HEADER_LENGTH: usize = 18;
    const COMMON_DIFF_VAL: usize = 65537;

    if base_offset > image_size
        || ENCRYPTED_FILE_START_INDEX > image_size.saturating_sub(base_offset)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let payload_start = base_offset + ENCRYPTED_FILE_START_INDEX;
    if embedded_file_size > image_size.saturating_sub(payload_start) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let mut input =
        open_binary_input_or_throw(image_path, "Read Error: Failed to open image file.")?;
    let output_file = open_binary_output_for_write_or_throw(output_path)?;
    let mut output = BufWriter::new(output_file);
    let mut copy_buffer = vec![0u8; 2 * 1024 * 1024];

    if total_profile_header_segments != 0 {
        let segment_count = (total_profile_header_segments as usize).saturating_sub(1);
        let marker_offset = segment_count
            .checked_mul(COMMON_DIFF_VAL)
            .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
        if marker_offset < 0x16 {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }

        let marker_index = marker_offset - 0x16;
        if marker_index > image_size.saturating_sub(base_offset)
            || image_size
                .saturating_sub(base_offset)
                .saturating_sub(marker_index)
                < 2
        {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }

        let mut marker = [0u8; 2];
        read_exact_at(&mut input, base_offset + marker_index, &mut marker)?;
        if marker != [0xFF, 0xE2] {
            return Err(
                "File Extraction Error: Missing segments detected. Embedded data file is corrupt!"
                    .to_string(),
            );
        }
    }

    let has_profile_headers = total_profile_header_segments != 0;
    input
        .seek(SeekFrom::Start(payload_start as u64))
        .map_err(|_| "Read Error: Failed to seek payload position.".to_string())?;

    let mut cursor = 0usize;
    let mut next_header = HEADER_INDEX;
    let mut written = 0usize;

    while cursor < embedded_file_size {
        if has_profile_headers && cursor == next_header {
            let skip = cmp::min(PROFILE_HEADER_LENGTH, embedded_file_size - cursor);
            skip_exact_bytes(&mut input, skip)?;
            cursor += skip;
            if let Some(v) = next_header.checked_add(COMMON_DIFF_VAL) {
                next_header = v;
            }
            continue;
        }

        let next_cut = if has_profile_headers {
            cmp::min(embedded_file_size, next_header)
        } else {
            embedded_file_size
        };
        let run = next_cut - cursor;

        copy_bytes_to_output(&mut input, &mut output, run, &mut copy_buffer)?;
        cursor += run;
        written += run;
    }

    output
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

    Ok(written)
}

pub(crate) fn extract_default_ciphertext_to_consumer<F>(
    image_path: &Path,
    image_size: usize,
    base_offset: usize,
    embedded_file_size: usize,
    total_profile_header_segments: u16,
    mut consume: F,
) -> Result<usize, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    const ENCRYPTED_FILE_START_INDEX: usize = 0x33B;
    const HEADER_INDEX: usize = 0xFCB0;
    const PROFILE_HEADER_LENGTH: usize = 18;
    const COMMON_DIFF_VAL: usize = 65537;

    if base_offset > image_size
        || ENCRYPTED_FILE_START_INDEX > image_size.saturating_sub(base_offset)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let payload_start = base_offset + ENCRYPTED_FILE_START_INDEX;
    if embedded_file_size > image_size.saturating_sub(payload_start) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let mut input =
        open_binary_input_or_throw(image_path, "Read Error: Failed to open image file.")?;
    let mut copy_buffer = vec![0u8; 2 * 1024 * 1024];

    if total_profile_header_segments != 0 {
        let segment_count = (total_profile_header_segments as usize).saturating_sub(1);
        let marker_offset = segment_count
            .checked_mul(COMMON_DIFF_VAL)
            .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
        if marker_offset < 0x16 {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }

        let marker_index = marker_offset - 0x16;
        if marker_index > image_size.saturating_sub(base_offset)
            || image_size
                .saturating_sub(base_offset)
                .saturating_sub(marker_index)
                < 2
        {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }

        let mut marker = [0u8; 2];
        read_exact_at(&mut input, base_offset + marker_index, &mut marker)?;
        if marker != [0xFF, 0xE2] {
            return Err(
                "File Extraction Error: Missing segments detected. Embedded data file is corrupt!"
                    .to_string(),
            );
        }
    }

    let has_profile_headers = total_profile_header_segments != 0;
    input
        .seek(SeekFrom::Start(payload_start as u64))
        .map_err(|_| "Read Error: Failed to seek payload position.".to_string())?;

    let mut cursor = 0usize;
    let mut next_header = HEADER_INDEX;
    let mut written = 0usize;

    while cursor < embedded_file_size {
        if has_profile_headers && cursor == next_header {
            let skip = cmp::min(PROFILE_HEADER_LENGTH, embedded_file_size - cursor);
            skip_exact_bytes(&mut input, skip)?;
            cursor += skip;
            if let Some(v) = next_header.checked_add(COMMON_DIFF_VAL) {
                next_header = v;
            }
            continue;
        }

        let next_cut = if has_profile_headers {
            cmp::min(embedded_file_size, next_header)
        } else {
            embedded_file_size
        };
        let run = next_cut - cursor;

        copy_bytes_to_consumer(&mut input, run, &mut copy_buffer, &mut consume)?;
        cursor += run;
        written += run;
    }

    Ok(written)
}

pub(crate) fn extract_bluesky_ciphertext_to_file(
    image_path: &Path,
    image_size: usize,
    embedded_file_size: usize,
    output_path: &Path,
) -> Result<usize, String> {
    const ENCRYPTED_FILE_START_INDEX: usize = 0x1D1;
    const EXIF_SEGMENT_DATA_SIZE: usize = 65027;
    const DATASET_MAX_SIZE: usize = 32800;
    const PSHOP_SEGMENT_SIZE_DIFF: usize = 7;
    const FIRST_DATASET_SIZE_DIFF: usize = 24;
    const DATASET_FILE_INDEX_DIFF: usize = 2;
    const SECOND_DATASET_SIZE_DIFF: usize = 3;
    const XMP_BASE64_MAX_SCAN_BYTES: usize = 128 * 1024;
    const BASE64_END_SIG: u8 = 0x3C;

    const PSHOP_SEGMENT_SIG: [u8; 7] = [0x73, 0x68, 0x6F, 0x70, 0x20, 0x33, 0x2E];
    const XMP_CREATOR_SIG: [u8; 7] = [0x3C, 0x72, 0x64, 0x66, 0x3A, 0x6C, 0x69];

    if embedded_file_size == 0 || ENCRYPTED_FILE_START_INDEX > image_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let exif_chunk_size = cmp::min(embedded_file_size, EXIF_SEGMENT_DATA_SIZE);
    if exif_chunk_size > image_size.saturating_sub(ENCRYPTED_FILE_START_INDEX) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let mut input =
        open_binary_input_or_throw(image_path, "Read Error: Failed to open image file.")?;
    let output_file = open_binary_output_for_write_or_throw(output_path)?;
    let mut output = BufWriter::new(output_file);
    let mut copy_buffer = vec![0u8; 2 * 1024 * 1024];

    let mut written = 0usize;
    copy_range_to_output(
        &mut input,
        &mut output,
        ENCRYPTED_FILE_START_INDEX,
        exif_chunk_size,
        &mut copy_buffer,
    )?;
    written += exif_chunk_size;

    let mut remaining = embedded_file_size - exif_chunk_size;
    if remaining == 0 {
        output
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        return Ok(written);
    }

    let tail_sigs =
        find_dual_signatures_in_file(image_path, &PSHOP_SEGMENT_SIG, &XMP_CREATOR_SIG, 0)?;
    let pshop_sig_index = tail_sigs
        .first
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;

    if pshop_sig_index < PSHOP_SEGMENT_SIZE_DIFF {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let pshop_segment_size_index = pshop_sig_index - PSHOP_SEGMENT_SIZE_DIFF;
    let first_dataset_size_index = pshop_sig_index + FIRST_DATASET_SIZE_DIFF;
    let first_dataset_file_index = first_dataset_size_index + DATASET_FILE_INDEX_DIFF;

    if pshop_segment_size_index > image_size
        || 2 > image_size.saturating_sub(pshop_segment_size_index)
        || first_dataset_file_index > image_size
        || 2 > image_size.saturating_sub(first_dataset_size_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let pshop_segment_size = read_u16_at(&mut input, pshop_segment_size_index)?;
    let first_dataset_size = read_u16_at(&mut input, first_dataset_size_index)? as usize;

    if first_dataset_size == 0
        || first_dataset_size > remaining
        || first_dataset_size > image_size.saturating_sub(first_dataset_file_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    copy_range_to_output(
        &mut input,
        &mut output,
        first_dataset_file_index,
        first_dataset_size,
        &mut copy_buffer,
    )?;
    written += first_dataset_size;
    remaining -= first_dataset_size;

    if remaining == 0 {
        output
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        return Ok(written);
    }

    if pshop_segment_size as usize <= DATASET_MAX_SIZE
        || first_dataset_file_index
            > usize::MAX.saturating_sub(first_dataset_size + SECOND_DATASET_SIZE_DIFF)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let second_dataset_size_index =
        first_dataset_file_index + first_dataset_size + SECOND_DATASET_SIZE_DIFF;
    let second_dataset_file_index = second_dataset_size_index + DATASET_FILE_INDEX_DIFF;

    if second_dataset_file_index > image_size
        || 2 > image_size.saturating_sub(second_dataset_size_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let second_dataset_size = read_u16_at(&mut input, second_dataset_size_index)? as usize;
    if second_dataset_size == 0
        || second_dataset_size > remaining
        || second_dataset_size > image_size.saturating_sub(second_dataset_file_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    copy_range_to_output(
        &mut input,
        &mut output,
        second_dataset_file_index,
        second_dataset_size,
        &mut copy_buffer,
    )?;
    written += second_dataset_size;
    remaining -= second_dataset_size;

    if remaining == 0 {
        output
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        return Ok(written);
    }

    let xmp_sig_index = tail_sigs
        .second
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
    let base64_begin_index = xmp_sig_index + XMP_CREATOR_SIG.len() + 1;
    if base64_begin_index > image_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    written += stream_decode_base64_until_delimiter_to_output(
        &mut input,
        base64_begin_index,
        BASE64_END_SIG,
        XMP_BASE64_MAX_SCAN_BYTES,
        remaining,
        &mut output,
        CORRUPT_FILE_ERROR,
    )?;

    output
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

    if written != embedded_file_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    Ok(written)
}

pub(crate) fn extract_bluesky_ciphertext_to_consumer<F>(
    image_path: &Path,
    image_size: usize,
    embedded_file_size: usize,
    mut consume: F,
) -> Result<usize, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    const ENCRYPTED_FILE_START_INDEX: usize = 0x1D1;
    const EXIF_SEGMENT_DATA_SIZE: usize = 65027;
    const DATASET_MAX_SIZE: usize = 32800;
    const PSHOP_SEGMENT_SIZE_DIFF: usize = 7;
    const FIRST_DATASET_SIZE_DIFF: usize = 24;
    const DATASET_FILE_INDEX_DIFF: usize = 2;
    const SECOND_DATASET_SIZE_DIFF: usize = 3;
    const XMP_BASE64_MAX_SCAN_BYTES: usize = 128 * 1024;
    const BASE64_END_SIG: u8 = 0x3C;

    const PSHOP_SEGMENT_SIG: [u8; 7] = [0x73, 0x68, 0x6F, 0x70, 0x20, 0x33, 0x2E];
    const XMP_CREATOR_SIG: [u8; 7] = [0x3C, 0x72, 0x64, 0x66, 0x3A, 0x6C, 0x69];

    if embedded_file_size == 0 || ENCRYPTED_FILE_START_INDEX > image_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let exif_chunk_size = cmp::min(embedded_file_size, EXIF_SEGMENT_DATA_SIZE);
    if exif_chunk_size > image_size.saturating_sub(ENCRYPTED_FILE_START_INDEX) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let mut input =
        open_binary_input_or_throw(image_path, "Read Error: Failed to open image file.")?;
    let mut copy_buffer = vec![0u8; 2 * 1024 * 1024];

    let mut written = 0usize;
    copy_range_to_consumer(
        &mut input,
        ENCRYPTED_FILE_START_INDEX,
        exif_chunk_size,
        &mut copy_buffer,
        &mut consume,
    )?;
    written += exif_chunk_size;

    let mut remaining = embedded_file_size - exif_chunk_size;
    if remaining == 0 {
        return Ok(written);
    }

    let tail_sigs =
        find_dual_signatures_in_file(image_path, &PSHOP_SEGMENT_SIG, &XMP_CREATOR_SIG, 0)?;
    let pshop_sig_index = tail_sigs
        .first
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;

    if pshop_sig_index < PSHOP_SEGMENT_SIZE_DIFF {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let pshop_segment_size_index = pshop_sig_index - PSHOP_SEGMENT_SIZE_DIFF;
    let first_dataset_size_index = pshop_sig_index + FIRST_DATASET_SIZE_DIFF;
    let first_dataset_file_index = first_dataset_size_index + DATASET_FILE_INDEX_DIFF;

    if pshop_segment_size_index > image_size
        || 2 > image_size.saturating_sub(pshop_segment_size_index)
        || first_dataset_file_index > image_size
        || 2 > image_size.saturating_sub(first_dataset_size_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let pshop_segment_size = read_u16_at(&mut input, pshop_segment_size_index)?;
    let first_dataset_size = read_u16_at(&mut input, first_dataset_size_index)? as usize;

    if first_dataset_size == 0
        || first_dataset_size > remaining
        || first_dataset_size > image_size.saturating_sub(first_dataset_file_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    copy_range_to_consumer(
        &mut input,
        first_dataset_file_index,
        first_dataset_size,
        &mut copy_buffer,
        &mut consume,
    )?;
    written += first_dataset_size;
    remaining -= first_dataset_size;

    if remaining == 0 {
        return Ok(written);
    }

    if pshop_segment_size as usize <= DATASET_MAX_SIZE
        || first_dataset_file_index
            > usize::MAX.saturating_sub(first_dataset_size + SECOND_DATASET_SIZE_DIFF)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let second_dataset_size_index =
        first_dataset_file_index + first_dataset_size + SECOND_DATASET_SIZE_DIFF;
    let second_dataset_file_index = second_dataset_size_index + DATASET_FILE_INDEX_DIFF;

    if second_dataset_file_index > image_size
        || 2 > image_size.saturating_sub(second_dataset_size_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let second_dataset_size = read_u16_at(&mut input, second_dataset_size_index)? as usize;
    if second_dataset_size == 0
        || second_dataset_size > remaining
        || second_dataset_size > image_size.saturating_sub(second_dataset_file_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    copy_range_to_consumer(
        &mut input,
        second_dataset_file_index,
        second_dataset_size,
        &mut copy_buffer,
        &mut consume,
    )?;
    written += second_dataset_size;
    remaining -= second_dataset_size;

    if remaining == 0 {
        return Ok(written);
    }

    let xmp_sig_index = tail_sigs
        .second
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
    let base64_begin_index = xmp_sig_index + XMP_CREATOR_SIG.len() + 1;
    if base64_begin_index > image_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    written += stream_decode_base64_until_delimiter_to_consumer(
        &mut input,
        base64_begin_index,
        BASE64_END_SIG,
        XMP_BASE64_MAX_SCAN_BYTES,
        remaining,
        &mut consume,
        CORRUPT_FILE_ERROR,
    )?;

    if written != embedded_file_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    Ok(written)
}
