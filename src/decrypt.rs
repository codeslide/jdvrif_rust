use std::path::Path;

use super::*;

#[path = "decrypt_kdf.rs"]
mod kdf;
#[path = "decrypt_pin.rs"]
mod pin;
#[path = "decrypt_stream.rs"]
mod stream;

use kdf::{derive_secretstream_key_and_header, require_v2_secretstream};
use pin::get_pin;
use stream::{
    decrypt_ciphertext_to_stage_file, decrypt_secretstream_ciphertext_chunks_to_stage_file,
};

pub(crate) use kdf::{decrypt_offsets, metadata_has_v2_secretstream};

pub(crate) fn derive_key_from_pin(
    pin: u64,
    salt_bytes: &[u8],
) -> Result<[u8; secretbox::KEYBYTES], String> {
    let mut pin_bytes = pin.to_string().into_bytes();
    let salt = argon2id13::Salt::from_slice(salt_bytes)
        .ok_or_else(|| "KDF Error: Unable to derive encryption key.".to_string())?;

    let mut key_buf = [0u8; secretbox::KEYBYTES];
    argon2id13::derive_key(
        &mut key_buf,
        &pin_bytes,
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| "KDF Error: Unable to derive encryption key.".to_string())?;

    memzero(&mut pin_bytes);
    Ok(key_buf)
}

pub(crate) fn decrypt_streaming_from_cipher_chunks_with_pin<F>(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    stream_stage_path: &Path,
    pin: u64,
    feed_chunks: F,
) -> Result<DecryptStatus, NativeRecoverError>
where
    F: FnMut(&mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<usize, String>,
{
    let offsets = decrypt_offsets(is_bluesky_file);
    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(NativeRecoverError::Message(CORRUPT_FILE_ERROR.to_string()));
    }

    require_v2_secretstream(metadata, offsets)?;
    let (key, header) = derive_secretstream_key_and_header(metadata, offsets, pin)?;

    let output = decrypt_secretstream_ciphertext_chunks_to_stage_file(
        stream_stage_path,
        &key,
        &header,
        is_data_compressed,
        feed_chunks,
    )
    .map_err(NativeRecoverError::Message)?;

    match output {
        Some(v) => Ok(DecryptStatus::Success {
            decrypted_filename: v.decrypted_filename,
            output_size: v.output_size,
        }),
        None => Ok(DecryptStatus::FailedPin),
    }
}

pub(crate) fn decrypt_streaming_from_cipher_chunks<F>(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    stream_stage_path: &Path,
    feed_chunks: F,
) -> Result<DecryptStatus, NativeRecoverError>
where
    F: FnMut(&mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<usize, String>,
{
    decrypt_streaming_from_cipher_chunks_with_pin(
        metadata,
        is_bluesky_file,
        is_data_compressed,
        stream_stage_path,
        get_pin(),
        feed_chunks,
    )
}

pub(crate) fn decrypt_from_cipher_stage_with_pin(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
    pin: u64,
) -> Result<DecryptStatus, NativeRecoverError> {
    let offsets = decrypt_offsets(is_bluesky_file);

    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(NativeRecoverError::Message(CORRUPT_FILE_ERROR.to_string()));
    }

    require_v2_secretstream(metadata, offsets)?;
    let (key, header) = derive_secretstream_key_and_header(metadata, offsets, pin)?;

    let output = decrypt_ciphertext_to_stage_file(
        cipher_stage_path,
        stream_stage_path,
        &key,
        &header,
        is_data_compressed,
    )
    .map_err(NativeRecoverError::Message)?;

    match output {
        Some(v) => Ok(DecryptStatus::Success {
            decrypted_filename: v.decrypted_filename,
            output_size: v.output_size,
        }),
        None => Ok(DecryptStatus::FailedPin),
    }
}

pub(crate) fn decrypt_from_cipher_stage(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
) -> Result<DecryptStatus, NativeRecoverError> {
    decrypt_from_cipher_stage_with_pin(
        metadata,
        is_bluesky_file,
        is_data_compressed,
        cipher_stage_path,
        stream_stage_path,
        get_pin(),
    )
}
