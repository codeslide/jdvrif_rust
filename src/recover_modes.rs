use crate::decrypt::{
    decrypt_from_cipher_stage, decrypt_streaming_from_cipher_chunks, metadata_has_v2_secretstream,
};
use crate::extract::{
    extract_bluesky_ciphertext_to_consumer, extract_bluesky_ciphertext_to_file,
    extract_default_ciphertext_to_consumer, extract_default_ciphertext_to_file, read_exact_at,
};
use std::path::Path;

use super::output::{
    commit_recovered_output, print_recovery_success, safe_recovery_path, temp_recovery_path,
};
use super::*;

pub(super) fn recover_from_icc_path(
    image_file_path: &Path,
    image_file_size: usize,
    icc_profile_sig_index: usize,
) -> Result<(), NativeRecoverError> {
    const INDEX_DIFF: usize = 8;
    const NO_ZLIB_COMPRESSION_ID_INDEX_DIFF: usize = 24;
    const TOTAL_PROFILE_HEADER_SEGMENTS_INDEX: usize = 0x2C8;
    const FILE_SIZE_INDEX: usize = 0x2CA;
    const ENCRYPTED_FILE_START_INDEX: usize = 0x33B;

    if icc_profile_sig_index < INDEX_DIFF {
        return Err(NativeRecoverError::Message(
            "File Extraction Error: Corrupt ICC metadata.".to_string(),
        ));
    }

    let base_offset = icc_profile_sig_index - INDEX_DIFF;
    if base_offset > image_file_size
        || ENCRYPTED_FILE_START_INDEX > image_file_size.saturating_sub(base_offset)
    {
        return Err(NativeRecoverError::Message(CORRUPT_FILE_ERROR.to_string()));
    }

    let mut metadata = vec![0u8; ENCRYPTED_FILE_START_INDEX];
    {
        let mut input =
            open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")
                .map_err(NativeRecoverError::Message)?;
        read_exact_at(&mut input, base_offset, &mut metadata)
            .map_err(NativeRecoverError::Message)?;
    }

    let compression_marker_index = NO_ZLIB_COMPRESSION_ID_INDEX - NO_ZLIB_COMPRESSION_ID_INDEX_DIFF;
    if !span_has_range(metadata.len(), compression_marker_index, 1)
        || !span_has_range(metadata.len(), TOTAL_PROFILE_HEADER_SEGMENTS_INDEX, 2)
        || !span_has_range(metadata.len(), FILE_SIZE_INDEX, 4)
    {
        return Err(NativeRecoverError::Message(
            "File Extraction Error: Corrupt metadata.".to_string(),
        ));
    }

    let is_data_compressed = metadata[compression_marker_index] != NO_ZLIB_COMPRESSION_ID;
    let total_profile_header_segments = get_value(&metadata, TOTAL_PROFILE_HEADER_SEGMENTS_INDEX, 2)
        .map_err(NativeRecoverError::Message)? as u16;
    let embedded_file_size =
        get_value(&metadata, FILE_SIZE_INDEX, 4).map_err(NativeRecoverError::Message)?;

    let stream_stage_path = temp_recovery_path(Path::new("jdvrif_recovered.bin"))
        .map_err(NativeRecoverError::Message)?;
    let mut stream_guard = TempFileGuard::new(stream_stage_path.clone());
    let mut cipher_stage_path: Option<PathBuf> = None;
    let mut cipher_guard: Option<TempFileGuard> = None;
    let mut extracted_cipher_size = 0usize;

    let decrypt_result = if metadata_has_v2_secretstream(&metadata, false) {
        decrypt_streaming_from_cipher_chunks(
            &metadata,
            false,
            is_data_compressed,
            &stream_stage_path,
            |sink| {
                let extracted = extract_default_ciphertext_to_consumer(
                    image_file_path,
                    image_file_size,
                    base_offset,
                    embedded_file_size,
                    total_profile_header_segments,
                    |chunk| sink(chunk),
                )?;
                extracted_cipher_size = extracted;
                Ok(extracted)
            },
        )?
    } else {
        let path = temp_recovery_path(Path::new("jdvrif_cipher.bin"))
            .map_err(NativeRecoverError::Message)?;
        let guard = TempFileGuard::new(path.clone());
        extracted_cipher_size = extract_default_ciphertext_to_file(
            image_file_path,
            image_file_size,
            base_offset,
            embedded_file_size,
            total_profile_header_segments,
            &path,
        )
        .map_err(NativeRecoverError::Message)?;
        cipher_stage_path = Some(path.clone());
        cipher_guard = Some(guard);
        decrypt_from_cipher_stage(
            &metadata,
            false,
            is_data_compressed,
            &path,
            &stream_stage_path,
        )?
    };

    let (decrypted_filename, output_size) = match decrypt_result {
        DecryptStatus::Success {
            decrypted_filename,
            output_size,
        } => (decrypted_filename, output_size),
        DecryptStatus::FailedPin => {
            return Err(NativeRecoverError::Message(
                "File Decryption Error: Invalid recovery PIN or file is corrupt.".to_string(),
            ))
        }
    };
    if extracted_cipher_size == 0 {
        return Err(NativeRecoverError::Message(
            "File Extraction Error: Embedded data file is empty.".to_string(),
        ));
    }

    let output_path =
        safe_recovery_path(decrypted_filename).map_err(NativeRecoverError::Message)?;
    commit_recovered_output(&stream_stage_path, &output_path)
        .map_err(NativeRecoverError::Message)?;
    stream_guard.dismiss();

    if let Some(path) = &cipher_stage_path {
        cleanup_path_no_throw(path);
    }
    if let Some(mut guard) = cipher_guard {
        guard.dismiss();
    }

    print_recovery_success(&output_path, output_size);
    Ok(())
}

pub(super) fn recover_from_bluesky_path(
    image_file_path: &Path,
    image_file_size: usize,
    jdvrif_sig_index: usize,
    jdvrif_sig: &[u8],
) -> Result<(), NativeRecoverError> {
    const FILE_SIZE_INDEX: usize = 0x1CD;
    const ENCRYPTED_FILE_START_INDEX: usize = 0x1D1;

    if ENCRYPTED_FILE_START_INDEX > image_file_size {
        return Err(NativeRecoverError::Message(
            "Image File Error: Corrupt signature metadata.".to_string(),
        ));
    }

    let mut metadata = vec![0u8; ENCRYPTED_FILE_START_INDEX];
    {
        let mut input =
            open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")
                .map_err(NativeRecoverError::Message)?;
        read_exact_at(&mut input, 0, &mut metadata).map_err(NativeRecoverError::Message)?;
    }

    if jdvrif_sig_index > metadata.len()
        || jdvrif_sig.len() > metadata.len().saturating_sub(jdvrif_sig_index)
    {
        return Err(NativeRecoverError::Message(
            "Image File Error: Corrupt signature metadata.".to_string(),
        ));
    }

    if &metadata[jdvrif_sig_index..jdvrif_sig_index + jdvrif_sig.len()] != jdvrif_sig {
        return Err(NativeRecoverError::Message(
            "Image File Error: Corrupt signature metadata.".to_string(),
        ));
    }

    if !span_has_range(metadata.len(), FILE_SIZE_INDEX, 4) {
        return Err(NativeRecoverError::Message(
            "File Extraction Error: Corrupt metadata.".to_string(),
        ));
    }

    let embedded_file_size =
        get_value(&metadata, FILE_SIZE_INDEX, 4).map_err(NativeRecoverError::Message)?;

    let stream_stage_path = temp_recovery_path(Path::new("jdvrif_recovered.bin"))
        .map_err(NativeRecoverError::Message)?;
    let mut stream_guard = TempFileGuard::new(stream_stage_path.clone());
    let mut cipher_stage_path: Option<PathBuf> = None;
    let mut cipher_guard: Option<TempFileGuard> = None;
    let mut extracted_cipher_size = 0usize;

    let decrypt_result = if metadata_has_v2_secretstream(&metadata, true) {
        decrypt_streaming_from_cipher_chunks(&metadata, true, true, &stream_stage_path, |sink| {
            let extracted = extract_bluesky_ciphertext_to_consumer(
                image_file_path,
                image_file_size,
                embedded_file_size,
                |chunk| sink(chunk),
            )?;
            extracted_cipher_size = extracted;
            Ok(extracted)
        })?
    } else {
        let path = temp_recovery_path(Path::new("jdvrif_cipher.bin"))
            .map_err(NativeRecoverError::Message)?;
        let guard = TempFileGuard::new(path.clone());
        extracted_cipher_size = extract_bluesky_ciphertext_to_file(
            image_file_path,
            image_file_size,
            embedded_file_size,
            &path,
        )
        .map_err(NativeRecoverError::Message)?;
        cipher_stage_path = Some(path.clone());
        cipher_guard = Some(guard);
        decrypt_from_cipher_stage(&metadata, true, true, &path, &stream_stage_path)?
    };

    let (decrypted_filename, output_size) = match decrypt_result {
        DecryptStatus::Success {
            decrypted_filename,
            output_size,
        } => (decrypted_filename, output_size),
        DecryptStatus::FailedPin => {
            return Err(NativeRecoverError::Message(
                "File Decryption Error: Invalid recovery PIN or file is corrupt.".to_string(),
            ))
        }
    };
    if extracted_cipher_size == 0 {
        return Err(NativeRecoverError::Message(
            "File Extraction Error: Embedded data file is empty.".to_string(),
        ));
    }

    let output_path =
        safe_recovery_path(decrypted_filename).map_err(NativeRecoverError::Message)?;
    commit_recovered_output(&stream_stage_path, &output_path)
        .map_err(NativeRecoverError::Message)?;
    stream_guard.dismiss();

    if let Some(path) = &cipher_stage_path {
        cleanup_path_no_throw(path);
    }
    if let Some(mut guard) = cipher_guard {
        guard.dismiss();
    }

    print_recovery_success(&output_path, output_size);
    Ok(())
}
