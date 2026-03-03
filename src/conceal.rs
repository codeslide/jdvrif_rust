use crate::cli::ConcealOption;
use crate::conceal_helpers::{
    finalize_default_platform_report, generate_recovery_pin, maybe_print_large_file_notice,
    platform_report_template, print_conceal_summary, save_embedded_jpg, should_bypass_compression,
    temp_compressed_path, validate_combined_size_limits, validate_data_filename,
    zlib_compress_file_to_path_native,
};
use crate::conceal_segments::{
    make_bluesky_segment_template, make_default_segment_template, segment_data_file,
    BlueskySegmentStreamBuilder,
};
use std::path::Path;

use super::*;

fn estimate_prefixed_stream_encrypted_size(
    input_size: usize,
    prefix_plain_len: usize,
) -> Result<usize, String> {
    if prefix_plain_len > usize::MAX - input_size {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }
    let total_plain_size = input_size + prefix_plain_len;
    if total_plain_size == 0 {
        return Ok(0);
    }

    let prefix_chunks = if prefix_plain_len == 0 {
        0
    } else {
        prefix_plain_len.div_ceil(STREAM_CHUNK_SIZE)
    };
    let data_chunks = if input_size == 0 {
        0
    } else {
        input_size.div_ceil(STREAM_CHUNK_SIZE)
    };
    let chunk_count = prefix_chunks
        .checked_add(data_chunks)
        .ok_or_else(|| "File Size Error: Encrypted output overflow.".to_string())?;

    let per_chunk_overhead = secretstream::ABYTES + STREAM_FRAME_LEN_BYTES;
    if chunk_count > (usize::MAX - total_plain_size) / per_chunk_overhead {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }

    Ok(total_plain_size + chunk_count * per_chunk_overhead)
}

fn encrypt_file_with_secretstream_to_sink<F>(
    data_path: &Path,
    input_size: usize,
    prefix_plaintext: &[u8],
    key: &secretstream::Key,
    mut sink: F,
) -> Result<secretstream::Header, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    if input_size == 0 {
        return Err("Data File Error: File is empty.".to_string());
    }
    if prefix_plaintext.len() > usize::MAX - input_size {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }
    let total_plain_size = input_size + prefix_plaintext.len();

    let mut input =
        open_binary_input_or_throw(data_path, "Read Error: Failed to open file for encryption.")?;
    let (mut stream, header) = secretstream::Stream::init_push(key)
        .map_err(|_| "crypto_secretstream init_push failed".to_string())?;

    let mut push_plain_chunk = |plain_chunk: &[u8], is_final: bool| -> Result<(), String> {
        let tag = if is_final {
            secretstream::Tag::Final
        } else {
            secretstream::Tag::Message
        };
        let cipher = stream
            .push(plain_chunk, None, tag)
            .map_err(|_| "crypto_secretstream push failed".to_string())?;

        let frame_len = u32::try_from(cipher.len())
            .map_err(|_| "File Size Error: Stream chunk exceeds size limit.".to_string())?;
        sink(&frame_len.to_be_bytes())?;
        sink(&cipher)
    };

    let mut remaining_plain = total_plain_size;
    let mut prefix_off = 0usize;
    while prefix_off < prefix_plaintext.len() {
        let mlen = cmp::min(STREAM_CHUNK_SIZE, prefix_plaintext.len() - prefix_off);
        let is_final = remaining_plain == mlen;
        push_plain_chunk(&prefix_plaintext[prefix_off..prefix_off + mlen], is_final)?;
        prefix_off += mlen;
        remaining_plain -= mlen;
    }

    let mut input_left = input_size;
    let mut in_chunk = vec![0u8; STREAM_CHUNK_SIZE];

    while input_left > 0 {
        let mlen = cmp::min(STREAM_CHUNK_SIZE, input_left);
        input
            .read_exact(&mut in_chunk[..mlen])
            .map_err(|_| "Read Error: Failed to read full input while encrypting.".to_string())?;

        let is_final = remaining_plain == mlen;
        push_plain_chunk(&in_chunk[..mlen], is_final)?;

        memzero(&mut in_chunk[..mlen]);
        input_left -= mlen;
        remaining_plain -= mlen;
    }

    if remaining_plain != 0 {
        return Err("Internal Error: Plaintext size accounting mismatch.".to_string());
    }

    Ok(header)
}

fn encrypt_file_with_secretstream_append(
    data_path: &Path,
    input_size: usize,
    prefix_plaintext: &[u8],
    key: &secretstream::Key,
    out: &mut Vec<u8>,
) -> Result<secretstream::Header, String> {
    let reserve_bytes =
        estimate_prefixed_stream_encrypted_size(input_size, prefix_plaintext.len())?;
    if out.len() > usize::MAX - reserve_bytes {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }
    out.reserve(reserve_bytes);

    encrypt_file_with_secretstream_to_sink(data_path, input_size, prefix_plaintext, key, |chunk| {
        out.extend_from_slice(chunk);
        Ok(())
    })
}

fn encrypt_data_file_from_path_native(
    segment_vec: &mut Vec<u8>,
    data_path: &Path,
    input_size: usize,
    jpg_vec: &mut Vec<u8>,
    platforms_vec: &mut Vec<String>,
    data_filename: &str,
    option: ConcealOption,
) -> Result<u64, String> {
    let has_bluesky_option = matches!(option, ConcealOption::Bluesky);
    let has_reddit_option = matches!(option, ConcealOption::Reddit);

    let kdf_metadata_index = if has_bluesky_option {
        BLUESKY_KDF_METADATA_INDEX
    } else {
        DEFAULT_KDF_METADATA_INDEX
    };

    if !span_has_range(
        segment_vec.len(),
        kdf_metadata_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err("Internal Error: Corrupt segment metadata template.".to_string());
    }

    if data_filename.is_empty() || data_filename.len() >= u8::MAX as usize {
        return Err("Data File Error: Invalid data filename length.".to_string());
    }
    let mut filename_prefix = Vec::with_capacity(1 + data_filename.len());
    let filename_len = u8::try_from(data_filename.len())
        .map_err(|_| "Data File Error: Invalid data filename length.".to_string())?;
    filename_prefix.push(filename_len);
    filename_prefix.extend_from_slice(data_filename.as_bytes());
    if input_size > usize::MAX - filename_prefix.len() {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }

    let pin = generate_recovery_pin();
    let mut salt = [0u8; argon2id13::SALTBYTES];
    randombytes_into(&mut salt);
    let mut key_bytes = derive_key_from_pin(pin, &salt)?;
    let key = secretstream::Key::from_slice(&key_bytes)
        .ok_or_else(|| "KDF Error: Unable to derive encryption key.".to_string())?;

    let stream_header = if has_bluesky_option {
        let encrypted_size =
            estimate_prefixed_stream_encrypted_size(input_size, filename_prefix.len())?;
        let mut bluesky_builder = BlueskySegmentStreamBuilder::new(segment_vec, encrypted_size)?;
        let stream_header = encrypt_file_with_secretstream_to_sink(
            data_path,
            input_size,
            &filename_prefix,
            &key,
            |chunk| bluesky_builder.push(chunk),
        )?;
        bluesky_builder.finish()?;
        stream_header
    } else {
        encrypt_file_with_secretstream_append(
            data_path,
            input_size,
            &filename_prefix,
            &key,
            segment_vec,
        )?
    };
    memzero(&mut key_bytes);

    let mut kdf_region = vec![0u8; KDF_METADATA_REGION_BYTES];
    randombytes_into(&mut kdf_region);
    segment_vec[kdf_metadata_index..kdf_metadata_index + KDF_METADATA_REGION_BYTES]
        .copy_from_slice(&kdf_region);
    segment_vec[kdf_metadata_index + KDF_MAGIC_OFFSET
        ..kdf_metadata_index + KDF_MAGIC_OFFSET + KDF_METADATA_MAGIC_V2.len()]
        .copy_from_slice(&KDF_METADATA_MAGIC_V2);
    segment_vec[kdf_metadata_index + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
    segment_vec[kdf_metadata_index + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;
    segment_vec
        [kdf_metadata_index + KDF_SALT_OFFSET..kdf_metadata_index + KDF_SALT_OFFSET + salt.len()]
        .copy_from_slice(&salt);
    segment_vec[kdf_metadata_index + KDF_NONCE_OFFSET
        ..kdf_metadata_index + KDF_NONCE_OFFSET + stream_header.0.len()]
        .copy_from_slice(&stream_header.0);

    if has_bluesky_option {
        if platforms_vec.len() <= 2 {
            return Err("Internal Error: Corrupt platform compatibility list.".to_string());
        }
        let mut merged = std::mem::take(segment_vec);
        merged.extend_from_slice(jpg_vec);
        *jpg_vec = merged;
        platforms_vec[0] = platforms_vec[2].clone();
        platforms_vec.truncate(1);
    } else {
        segment_data_file(segment_vec, jpg_vec, platforms_vec, has_reddit_option)?;
    }

    Ok(pin)
}

pub(crate) fn run_native_conceal(
    option: &ConcealOption,
    image_file_path: &Path,
    data_file_path: &Path,
) -> Result<(), String> {
    let has_no_option = matches!(option, ConcealOption::None);
    let has_bluesky_option = matches!(option, ConcealOption::Bluesky);
    let has_reddit_option = matches!(option, ConcealOption::Reddit);

    sodiumoxide::init().map_err(|_| "Libsodium initialization failed!".to_string())?;

    let source_data_size = validate_file_for_read(data_file_path, false, false)?;
    let _cover_size = validate_file_for_read(image_file_path, true, true)?;
    let mut jpg_vec = crate::jpeg_preprocess::prepare_cover_image_for_conceal(
        image_file_path,
        source_data_size,
        has_no_option,
        has_bluesky_option,
    )?;
    let jpg_size = jpg_vec.len();

    let data_filename = validate_data_filename(data_file_path)?;
    let bypass_compression = should_bypass_compression(data_file_path, source_data_size);

    let mut segment_vec = if has_bluesky_option {
        make_bluesky_segment_template()?
    } else {
        make_default_segment_template()?
    };

    maybe_print_large_file_notice(source_data_size);

    let mut compressed_guard: Option<TempFileGuard> = None;
    let (encrypt_input_path, encrypt_input_size) = if bypass_compression {
        segment_vec[NO_ZLIB_COMPRESSION_ID_INDEX] = NO_ZLIB_COMPRESSION_ID;
        (data_file_path.to_path_buf(), source_data_size)
    } else {
        let compressed_path = temp_compressed_path(&data_filename)?;
        zlib_compress_file_to_path_native(data_file_path, &compressed_path)?;
        let compressed_size = checked_file_size(
            &compressed_path,
            "Zlib Compression Error: Failed to build compressed payload.",
            true,
        )?;
        compressed_guard = Some(TempFileGuard::new(compressed_path.clone()));
        (compressed_path, compressed_size)
    };

    let filename_prefix_len = 1usize
        .checked_add(data_filename.len())
        .ok_or_else(|| "File Size Error: Encrypted output overflow.".to_string())?;
    let encrypted_payload_size =
        estimate_prefixed_stream_encrypted_size(encrypt_input_size, filename_prefix_len)?;
    validate_combined_size_limits(
        encrypted_payload_size,
        jpg_size,
        has_reddit_option,
        has_bluesky_option,
    )?;

    let mut platforms_vec = platform_report_template();
    let recovery_pin = encrypt_data_file_from_path_native(
        &mut segment_vec,
        &encrypt_input_path,
        encrypt_input_size,
        &mut jpg_vec,
        &mut platforms_vec,
        &data_filename,
        *option,
    )?;

    drop(compressed_guard);

    let output_path = save_embedded_jpg(&segment_vec, &jpg_vec)?;
    let embedded_jpg_size = segment_vec.len() + jpg_vec.len();

    if has_no_option {
        finalize_default_platform_report(
            &mut platforms_vec,
            &mut segment_vec,
            &mut jpg_vec,
            embedded_jpg_size,
        )?;
    }

    print_conceal_summary(
        &platforms_vec,
        &output_path,
        embedded_jpg_size,
        recovery_pin,
    );
    Ok(())
}
