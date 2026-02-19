use crate::base64::{append_base64_as_binary, binary_to_base64};
use crate::binary_io::{get_value, search_sig, update_value};
use crate::pin_input::get_pin;
use crate::segmentation::segment_data_file;
use anyhow::{bail, Result};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::randombytes;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::Zeroize;

// Photoshop IPTC segment template.
#[rustfmt::skip]
const PHOTOSHOP_SEGMENT: [u8; 35] = [
    0xFF, 0xED, 0xFF, 0xFF, 0x50, 0x68, 0x6F, 0x74, 0x6F, 0x73, 0x68, 0x6F, 0x70, 0x20, 0x33, 0x2E,
    0x30, 0x00, 0x38, 0x42, 0x49, 0x4D, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE3, 0x1C, 0x08,
    0x0A, 0x7F, 0xFF,
];

// XMP segment template.
#[rustfmt::skip]
const XMP_SEGMENT: [u8; 313] = [
    0xFF, 0xE1, 0x01, 0x93, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6E, 0x73, 0x2E, 0x61, 0x64,
    0x6F, 0x62, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x78, 0x61, 0x70, 0x2F, 0x31, 0x2E, 0x30, 0x2F,
    0x00, 0x3C, 0x3F, 0x78, 0x70, 0x61, 0x63, 0x6B, 0x65, 0x74, 0x20, 0x62, 0x65, 0x67, 0x69, 0x6E,
    0x3D, 0x22, 0x22, 0x20, 0x69, 0x64, 0x3D, 0x22, 0x57, 0x35, 0x4D, 0x30, 0x4D, 0x70, 0x43, 0x65,
    0x68, 0x69, 0x48, 0x7A, 0x72, 0x65, 0x53, 0x7A, 0x4E, 0x54, 0x63, 0x7A, 0x6B, 0x63, 0x39, 0x64,
    0x22, 0x3F, 0x3E, 0x0A, 0x3C, 0x78, 0x3A, 0x78, 0x6D, 0x70, 0x6D, 0x65, 0x74, 0x61, 0x20, 0x78,
    0x6D, 0x6C, 0x6E, 0x73, 0x3A, 0x78, 0x3D, 0x22, 0x61, 0x64, 0x6F, 0x62, 0x65, 0x3A, 0x6E, 0x73,
    0x3A, 0x6D, 0x65, 0x74, 0x61, 0x2F, 0x22, 0x20, 0x78, 0x3A, 0x78, 0x6D, 0x70, 0x74, 0x6B, 0x3D,
    0x22, 0x47, 0x6F, 0x20, 0x58, 0x4D, 0x50, 0x20, 0x53, 0x44, 0x4B, 0x20, 0x31, 0x2E, 0x30, 0x22,
    0x3E, 0x3C, 0x72, 0x64, 0x66, 0x3A, 0x52, 0x44, 0x46, 0x20, 0x78, 0x6D, 0x6C, 0x6E, 0x73, 0x3A,
    0x72, 0x64, 0x66, 0x3D, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E,
    0x77, 0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x31, 0x39, 0x39, 0x39, 0x2F, 0x30, 0x32, 0x2F, 0x32,
    0x32, 0x2D, 0x72, 0x64, 0x66, 0x2D, 0x73, 0x79, 0x6E, 0x74, 0x61, 0x78, 0x2D, 0x6E, 0x73, 0x23,
    0x22, 0x3E, 0x3C, 0x72, 0x64, 0x66, 0x3A, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
    0x6F, 0x6E, 0x20, 0x78, 0x6D, 0x6C, 0x6E, 0x73, 0x3A, 0x64, 0x63, 0x3D, 0x22, 0x68, 0x74, 0x74,
    0x70, 0x3A, 0x2F, 0x2F, 0x70, 0x75, 0x72, 0x6C, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x64, 0x63, 0x2F,
    0x65, 0x6C, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x73, 0x2F, 0x31, 0x2E, 0x31, 0x2F, 0x22, 0x20, 0x72,
    0x64, 0x66, 0x3A, 0x61, 0x62, 0x6F, 0x75, 0x74, 0x3D, 0x22, 0x22, 0x3E, 0x3C, 0x64, 0x63, 0x3A,
    0x63, 0x72, 0x65, 0x61, 0x74, 0x6F, 0x72, 0x3E, 0x3C, 0x72, 0x64, 0x66, 0x3A, 0x53, 0x65, 0x71,
    0x3E, 0x3C, 0x72, 0x64, 0x66, 0x3A, 0x6C, 0x69, 0x3E,
];

// XMP footer.
#[rustfmt::skip]
const XMP_FOOTER: [u8; 92] = [
    0x3C, 0x2F, 0x72, 0x64, 0x66, 0x3A, 0x6C, 0x69, 0x3E, 0x3C, 0x2F, 0x72, 0x64, 0x66, 0x3A, 0x53,
    0x65, 0x71, 0x3E, 0x3C, 0x2F, 0x64, 0x63, 0x3A, 0x63, 0x72, 0x65, 0x61, 0x74, 0x6F, 0x72, 0x3E,
    0x3C, 0x2F, 0x72, 0x64, 0x66, 0x3A, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6F,
    0x6E, 0x3E, 0x3C, 0x2F, 0x72, 0x64, 0x66, 0x3A, 0x52, 0x44, 0x46, 0x3E, 0x3C, 0x2F, 0x78, 0x3A,
    0x78, 0x6D, 0x70, 0x6D, 0x65, 0x74, 0x61, 0x3E, 0x0A, 0x3C, 0x3F, 0x78, 0x70, 0x61, 0x63, 0x6B,
    0x65, 0x74, 0x20, 0x65, 0x6E, 0x64, 0x3D, 0x22, 0x77, 0x22, 0x3F, 0x3E,
];

/// Build Bluesky-specific EXIF/IPTC/XMP segments for encrypted data.
pub fn build_bluesky_segments(segment_vec: &mut Vec<u8>, data_vec: &[u8]) -> Result<()> {
    const COMPRESSED_FILE_SIZE_INDEX: usize = 0x1CD;
    const EXIF_SEGMENT_DATA_SIZE_LIMIT: usize = 65027;
    const EXIF_SEGMENT_DATA_INSERT_INDEX: usize = 0x1D1;
    const EXIF_SEGMENT_SIZE_INDEX: usize = 0x04;
    const ARTIST_FIELD_SIZE_INDEX: usize = 0x4A;
    const ARTIST_FIELD_SIZE_DIFF: usize = 140;
    const FIRST_MARKER_BYTES_SIZE: usize = 4;
    const VALUE_BYTE_LENGTH: usize = 4;

    let encrypted_vec_size = data_vec.len();
    let segment_vec_data_size = segment_vec.len() - FIRST_MARKER_BYTES_SIZE;

    let exif_segment_data_size = if encrypted_vec_size > EXIF_SEGMENT_DATA_SIZE_LIMIT {
        EXIF_SEGMENT_DATA_SIZE_LIMIT + segment_vec_data_size
    } else {
        encrypted_vec_size + segment_vec_data_size
    };
    let artist_field_size = exif_segment_data_size - ARTIST_FIELD_SIZE_DIFF;

    let mut has_xmp_segment = false;

    update_value(segment_vec, COMPRESSED_FILE_SIZE_INDEX, encrypted_vec_size, VALUE_BYTE_LENGTH)?;

    if encrypted_vec_size <= EXIF_SEGMENT_DATA_SIZE_LIMIT {
        update_value(segment_vec, ARTIST_FIELD_SIZE_INDEX, artist_field_size, VALUE_BYTE_LENGTH)?;
        update_value(segment_vec, EXIF_SEGMENT_SIZE_INDEX, exif_segment_data_size, 2)?;
        segment_vec.splice(
            EXIF_SEGMENT_DATA_INSERT_INDEX..EXIF_SEGMENT_DATA_INSERT_INDEX,
            data_vec.iter().copied(),
        );
        return Ok(());
    }

    // Data exceeds single EXIF segment — split across IPTC/XMP segments.
    segment_vec.splice(
        EXIF_SEGMENT_DATA_INSERT_INDEX..EXIF_SEGMENT_DATA_INSERT_INDEX,
        data_vec[..EXIF_SEGMENT_DATA_SIZE_LIMIT].iter().copied(),
    );

    const FIRST_DATASET_SIZE_LIMIT: usize = 32767;
    const LAST_DATASET_SIZE_LIMIT: usize = 32730;
    const FIRST_DATASET_SIZE_INDEX: usize = 0x21;

    let mut pshop_vec = PHOTOSHOP_SEGMENT.to_vec();

    let mut remaining_data_size = encrypted_vec_size - EXIF_SEGMENT_DATA_SIZE_LIMIT;
    let mut data_file_index = EXIF_SEGMENT_DATA_SIZE_LIMIT;

    pshop_vec.reserve(remaining_data_size);

    let first_copy_size = remaining_data_size.min(FIRST_DATASET_SIZE_LIMIT);

    if FIRST_DATASET_SIZE_LIMIT > first_copy_size {
        update_value(&mut pshop_vec, FIRST_DATASET_SIZE_INDEX, first_copy_size, 2)?;
    }

    pshop_vec.extend_from_slice(&data_vec[data_file_index..data_file_index + first_copy_size]);

    let mut xmp_vec = XMP_SEGMENT.to_vec();

    if remaining_data_size > FIRST_DATASET_SIZE_LIMIT {
        remaining_data_size -= FIRST_DATASET_SIZE_LIMIT;
        data_file_index += FIRST_DATASET_SIZE_LIMIT;

        let last_copy_size = remaining_data_size.min(LAST_DATASET_SIZE_LIMIT);

        let dataset_marker_base: [u8; 3] = [0x1C, 0x08, 0x0A];
        pshop_vec.extend_from_slice(&dataset_marker_base);
        pshop_vec.push((last_copy_size >> 8) as u8);
        pshop_vec.push((last_copy_size & 0xFF) as u8);
        pshop_vec.extend_from_slice(&data_vec[data_file_index..data_file_index + last_copy_size]);

        if remaining_data_size > LAST_DATASET_SIZE_LIMIT {
            has_xmp_segment = true;

            remaining_data_size -= LAST_DATASET_SIZE_LIMIT;
            data_file_index += LAST_DATASET_SIZE_LIMIT;

            const XMP_SEGMENT_SIZE_LIMIT: usize = 60033;
            const XMP_FOOTER_SIZE: usize = 92;

            let base64_size = ((remaining_data_size + 2) / 3) * 4;
            xmp_vec.reserve(base64_size + XMP_FOOTER_SIZE);

            let remaining_data = &data_vec[data_file_index..data_file_index + remaining_data_size];
            binary_to_base64(remaining_data, &mut xmp_vec);

            xmp_vec.extend_from_slice(&XMP_FOOTER);

            if xmp_vec.len() > XMP_SEGMENT_SIZE_LIMIT {
                bail!("File Size Error: Data file exceeds segment size limit for Bluesky.");
            }
        }
    }

    // Finalize segment sizes and append to segment_vec.
    const PSHOP_VEC_DEFAULT_SIZE: usize = 35;
    const SEGMENT_MARKER_BYTES_SIZE: usize = 2;
    const SEGMENT_SIZE_INDEX: usize = 0x2;
    const BIM_SECTION_SIZE_INDEX: usize = 0x1C;
    const BIM_SECTION_SIZE_DIFF: usize = 28;

    if has_xmp_segment {
        let xmp_size_val = xmp_vec.len() - SEGMENT_MARKER_BYTES_SIZE;
        update_value(&mut xmp_vec, SEGMENT_SIZE_INDEX, xmp_size_val, 2)?;
        segment_vec.extend_from_slice(&xmp_vec);
    }

    if pshop_vec.len() > PSHOP_VEC_DEFAULT_SIZE {
        let pshop_segment_data_size = pshop_vec.len() - SEGMENT_MARKER_BYTES_SIZE;
        let bim_section_size = pshop_segment_data_size - BIM_SECTION_SIZE_DIFF;

        if !has_xmp_segment {
            update_value(&mut pshop_vec, SEGMENT_SIZE_INDEX, pshop_segment_data_size, 2)?;
            update_value(&mut pshop_vec, BIM_SECTION_SIZE_INDEX, bim_section_size, 2)?;
        }
        segment_vec.extend_from_slice(&pshop_vec);
    }

    Ok(())
}

/// Encrypt the data file and embed it within the segment/jpg vectors.
/// Returns the recovery PIN.
pub fn encrypt_data_file(
    segment_vec: &mut Vec<u8>,
    data_vec: &mut Vec<u8>,
    jpg_vec: &mut Vec<u8>,
    platforms_vec: &mut Vec<String>,
    data_filename: &str,
    has_bluesky_option: bool,
    has_reddit_option: bool,
) -> Result<usize> {
    let data_filename_xor_key_index: usize = if has_bluesky_option { 0x175 } else { 0x2FB };
    let data_filename_index: usize = if has_bluesky_option { 0x161 } else { 0x2E7 };
    let sodium_key_index: usize = if has_bluesky_option { 0x18D } else { 0x313 };
    let nonce_key_index: usize = if has_bluesky_option { 0x1AD } else { 0x333 };

    let data_filename_length = segment_vec[data_filename_index - 1] as usize;

    // Generate random XOR key for filename and XOR-encrypt filename.
    let mut filename_xor_key = vec![0u8; data_filename_length];
    randombytes::randombytes_into(&mut filename_xor_key);
    segment_vec[data_filename_xor_key_index..data_filename_xor_key_index + data_filename_length]
        .copy_from_slice(&filename_xor_key);

    let filename_bytes = data_filename.as_bytes();
    for i in 0..data_filename_length {
        segment_vec[data_filename_index + i] = filename_bytes[i] ^ filename_xor_key[i];
    }

    // Generate encryption key and nonce.
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 24];
    randombytes::randombytes_into(&mut key_bytes);
    randombytes::randombytes_into(&mut nonce_bytes);

    // Copy key and nonce into segment.
    segment_vec[sodium_key_index..sodium_key_index + 32].copy_from_slice(&key_bytes);
    segment_vec[nonce_key_index..nonce_key_index + 24].copy_from_slice(&nonce_bytes);

    // Encrypt data.
    let key = secretbox::Key::from_slice(&key_bytes).unwrap();
    let nonce = secretbox::Nonce::from_slice(&nonce_bytes).unwrap();
    let ciphertext = secretbox::seal(data_vec, &nonce, &key);

    // Securely zero local copies.
    key_bytes.zeroize();
    nonce_bytes.zeroize();

    // Reserve space and insert encrypted data.
    segment_vec.reserve(ciphertext.len());

    if has_bluesky_option {
        build_bluesky_segments(segment_vec, &ciphertext)?;
    } else {
        segment_vec.extend_from_slice(&ciphertext);
    }

    data_vec.clear();
    data_vec.shrink_to_fit();

    // XOR-obfuscate the stored key+nonce with the first 8 bytes at sodium_key_index.
    // The PIN is derived from these 8 bytes before obfuscation.
    const SODIUM_XOR_KEY_LENGTH: usize = 8;
    const VALUE_BYTE_LENGTH: usize = 8;

    let pin = get_value(segment_vec, sodium_key_index, VALUE_BYTE_LENGTH)?;

    let mut sodium_keys_length: usize = 48;
    let mut sodium_xor_key_pos = sodium_key_index;
    let mut sodium_key_pos = sodium_key_index + SODIUM_XOR_KEY_LENGTH;

    while sodium_keys_length > 0 {
        segment_vec[sodium_key_pos] ^= segment_vec[sodium_xor_key_pos];
        sodium_key_pos += 1;
        sodium_xor_key_pos += 1;
        if sodium_xor_key_pos >= sodium_key_index + SODIUM_XOR_KEY_LENGTH {
            sodium_xor_key_pos = sodium_key_index;
        }
        sodium_keys_length -= 1;
    }

    // Overwrite PIN bytes with random data.
    let mut random_val = [0u8; 8];
    randombytes::randombytes_into(&mut random_val);
    let random_val_usize = u64::from_be_bytes(random_val) as usize;
    update_value(segment_vec, sodium_key_index, random_val_usize, VALUE_BYTE_LENGTH)?;

    if has_bluesky_option {
        jpg_vec.reserve(segment_vec.len());
        let mut combined = std::mem::take(segment_vec);
        combined.extend_from_slice(jpg_vec);
        *jpg_vec = combined;

        segment_vec.clear();
        segment_vec.shrink_to_fit();

        let bluesky_entry = platforms_vec[2].clone();
        platforms_vec.clear();
        platforms_vec.push(bluesky_entry);
    } else {
        segment_data_file(segment_vec, data_vec, jpg_vec, platforms_vec, has_reddit_option)?;
    }

    Ok(pin)
}

/// Decrypt the data file from the embedded image.
/// Returns the original filename. Sets `has_decryption_failed` on failure.
pub fn decrypt_data_file(
    jpg_vec: &mut Vec<u8>,
    is_bluesky_file: bool,
    has_decryption_failed: &mut bool,
) -> Result<String> {
    const SODIUM_XOR_KEY_LENGTH: usize = 8;

    let sodium_key_index: usize = if is_bluesky_file { 0x18D } else { 0x2FB };
    let nonce_key_index: usize = if is_bluesky_file { 0x1AD } else { 0x31B };
    let encrypted_filename_index: usize = if is_bluesky_file { 0x161 } else { 0x2CF };
    let filename_xor_key_index: usize = if is_bluesky_file { 0x175 } else { 0x2E3 };
    let file_size_index: usize = if is_bluesky_file { 0x1CD } else { 0x2CA };
    let filename_length_index = encrypted_filename_index - 1;

    // Get PIN from user.
    let recovery_pin = get_pin();

    // Write recovery PIN into the key location.
    update_value(jpg_vec, sodium_key_index, recovery_pin, SODIUM_XOR_KEY_LENGTH)?;

    // XOR de-obfuscate key+nonce.
    let mut sodium_keys_length: usize = 48;
    let mut sodium_xor_key_pos = sodium_key_index;
    let mut sodium_key_pos = sodium_key_index + SODIUM_XOR_KEY_LENGTH;

    while sodium_keys_length > 0 {
        jpg_vec[sodium_key_pos] ^= jpg_vec[sodium_xor_key_pos];
        sodium_key_pos += 1;
        sodium_xor_key_pos += 1;
        if sodium_xor_key_pos >= sodium_key_index + SODIUM_XOR_KEY_LENGTH {
            sodium_xor_key_pos = sodium_key_index;
        }
        sodium_keys_length -= 1;
    }

    // Extract key and nonce (with secure zeroing).
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 24];
    key_bytes.copy_from_slice(&jpg_vec[sodium_key_index..sodium_key_index + 32]);
    nonce_bytes.copy_from_slice(&jpg_vec[nonce_key_index..nonce_key_index + 24]);

    let key = secretbox::Key::from_slice(&key_bytes).unwrap();
    let nonce = secretbox::Nonce::from_slice(&nonce_bytes).unwrap();

    key_bytes.zeroize();
    nonce_bytes.zeroize();

    // Decrypt the original filename.
    let filename_length = jpg_vec[filename_length_index] as usize;
    let mut decrypted_filename = vec![0u8; filename_length];

    for i in 0..filename_length {
        decrypted_filename[i] =
            jpg_vec[encrypted_filename_index + i] ^ jpg_vec[filename_xor_key_index + i];
    }

    let decrypted_filename_str =
        String::from_utf8(decrypted_filename).unwrap_or_else(|_| "recovered_file".to_string());

    // Validate segment integrity and extract embedded data.
    const TOTAL_PROFILE_HEADER_SEGMENTS_INDEX: usize = 0x2C8;
    const COMMON_DIFF_VAL: usize = 65537;

    let total_profile_header_segments: u16 = if !is_bluesky_file {
        get_value(jpg_vec, TOTAL_PROFILE_HEADER_SEGMENTS_INDEX, 2)? as u16
    } else {
        0
    };

    let encrypted_file_start_index: usize = if is_bluesky_file { 0x1D1 } else { 0x33B };
    let embedded_file_size = get_value(jpg_vec, file_size_index, 4)?;

    if total_profile_header_segments > 0 && !is_bluesky_file {
        let last_segment_index =
            (total_profile_header_segments as usize - 1) * COMMON_DIFF_VAL - 0x16;

        if last_segment_index >= jpg_vec.len()
            || jpg_vec[last_segment_index] != 0xFF
            || jpg_vec[last_segment_index + 1] != 0xE2
        {
            bail!(
                "File Extraction Error: Missing segments detected. Embedded data file is corrupt!"
            );
        }
    }

    if is_bluesky_file {
        const EXIF_SIG: [u8; 2] = [0xFF, 0xE1];
        const SEARCH_LIMIT: usize = 100;
        const EXIF_MAX_SIZE: usize = 65534;

        let index_opt = search_sig(jpg_vec, &EXIF_SIG, SEARCH_LIMIT);
        if index_opt.is_none() {
            bail!("File Extraction Error: Expected segment marker not found. Embedded data file is corrupt!");
        }
        let exif_sig_index = index_opt.unwrap();
        let exif_segment_size = get_value(jpg_vec, exif_sig_index + 2, 2)?;

        if embedded_file_size >= EXIF_MAX_SIZE && EXIF_MAX_SIZE > exif_segment_size {
            bail!("File Extraction Error: Invalid segment size. Embedded data file is corrupt!");
        }
    }

    // Isolate the encrypted data.
    jpg_vec.copy_within(
        encrypted_file_start_index..encrypted_file_start_index + embedded_file_size,
        0,
    );
    jpg_vec.truncate(embedded_file_size);

    // Strip ICC profile headers from multi-segment data before decryption.
    let has_zero_profile_headers = is_bluesky_file || total_profile_header_segments == 0;

    if !has_zero_profile_headers {
        const PROFILE_HEADER_LENGTH: usize = 18;
        const HEADER_INDEX: usize = 0xFCB0;

        let limit = jpg_vec.len();
        let mut read_pos: usize = 0;
        let mut write_pos: usize = 0;
        let mut next_header: usize = HEADER_INDEX;

        while read_pos < limit {
            if read_pos == next_header {
                read_pos += PROFILE_HEADER_LENGTH.min(limit - read_pos);
                next_header += COMMON_DIFF_VAL;
                continue;
            }
            jpg_vec[write_pos] = jpg_vec[read_pos];
            write_pos += 1;
            read_pos += 1;
        }
        jpg_vec.truncate(write_pos);
        jpg_vec.shrink_to_fit();
    }

    // Decrypt.
    match secretbox::open(jpg_vec, &nonce, &key) {
        Ok(plaintext) => {
            *jpg_vec = plaintext;
        }
        Err(()) => {
            eprintln!("\nDecryption failed!");
            *has_decryption_failed = true;
            return Ok(String::new());
        }
    }

    Ok(decrypted_filename_str)
}

/// Write the PIN attempts counter to the image file.
pub fn write_pin_attempts(path: &Path, offset: u64, value: u8) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&[value])?;
    file.flush()?;
    Ok(())
}

/// Truncate the image file to zero bytes after too many failed PIN attempts.
pub fn destroy_image_file(path: &Path) -> Result<()> {
    File::create(path)?;
    Ok(())
}

/// Reassemble Bluesky data from EXIF/IPTC/XMP segments.
pub fn reassemble_bluesky_data(jpg_vec: &mut Vec<u8>, sig_length: usize) -> Result<()> {
    const SEARCH_LIMIT: usize = 125480;
    const PSHOP_SEGMENT_SIG: [u8; 7] = [0x73, 0x68, 0x6F, 0x70, 0x20, 0x33, 0x2E];
    const XMP_CREATOR_SIG: [u8; 7] = [0x3C, 0x72, 0x64, 0x66, 0x3A, 0x6C, 0x69];

    let Some(pshop_segment_sig_index) = search_sig(jpg_vec, &PSHOP_SEGMENT_SIG, SEARCH_LIMIT)
    else {
        return Ok(());
    };

    const DATASET_MAX_SIZE: usize = 32800;
    const PSHOP_SEGMENT_SIZE_INDEX_DIFF: usize = 7;
    const FIRST_DATASET_SIZE_INDEX_DIFF: usize = 24;
    const DATASET_FILE_INDEX_DIFF: usize = 2;

    let pshop_segment_size_index = pshop_segment_sig_index - PSHOP_SEGMENT_SIZE_INDEX_DIFF;
    let first_dataset_size_index = pshop_segment_sig_index + FIRST_DATASET_SIZE_INDEX_DIFF;
    let first_dataset_file_index = first_dataset_size_index + DATASET_FILE_INDEX_DIFF;

    let pshop_segment_size = get_value(jpg_vec, pshop_segment_size_index, 2)? as u16;
    let first_dataset_size = get_value(jpg_vec, first_dataset_size_index, 2)? as u16;

    let mut file_parts_vec: Vec<u8> = Vec::with_capacity(first_dataset_size as usize * 5);
    file_parts_vec.extend_from_slice(
        &jpg_vec[first_dataset_file_index..first_dataset_file_index + first_dataset_size as usize],
    );

    let mut has_xmp_segment = false;
    let mut xmp_creator_sig_index: usize = 0;

    if pshop_segment_size as usize > DATASET_MAX_SIZE {
        const SECOND_DATASET_SIZE_INDEX_DIFF: usize = 3;
        let second_dataset_size_index = first_dataset_file_index
            + first_dataset_size as usize
            + SECOND_DATASET_SIZE_INDEX_DIFF;
        let second_dataset_file_index = second_dataset_size_index + DATASET_FILE_INDEX_DIFF;

        let second_dataset_size = get_value(jpg_vec, second_dataset_size_index, 2)? as u16;

        file_parts_vec.extend_from_slice(
            &jpg_vec[second_dataset_file_index
                ..second_dataset_file_index + second_dataset_size as usize],
        );

        if let Some(xmp_idx) = search_sig(jpg_vec, &XMP_CREATOR_SIG, SEARCH_LIMIT) {
            has_xmp_segment = true;
            xmp_creator_sig_index = xmp_idx;

            const BASE64_END_SIG: u8 = 0x3C;
            let base64_begin_index = xmp_creator_sig_index + sig_length + 1;
            let base64_end_index = jpg_vec[base64_begin_index..]
                .iter()
                .position(|&b| b == BASE64_END_SIG)
                .map(|p| base64_begin_index + p)
                .unwrap_or(jpg_vec.len());

            let base64_span = &jpg_vec[base64_begin_index..base64_end_index];
            append_base64_as_binary(base64_span, &mut file_parts_vec)?;
        }
    }

    let exif_data_end_index_diff: usize = if has_xmp_segment { 351 } else { 55 };
    let reference_index = if has_xmp_segment {
        xmp_creator_sig_index
    } else {
        pshop_segment_sig_index
    };
    let exif_data_end_index = reference_index - exif_data_end_index_diff;

    // Copy reassembled data into jpg_vec.
    let copy_len = file_parts_vec.len();
    jpg_vec[exif_data_end_index..exif_data_end_index + copy_len]
        .copy_from_slice(&file_parts_vec[..copy_len]);

    Ok(())
}
