use crate::binary_io::search_sig;
use crate::common::{Mode, NO_ZLIB_COMPRESSION_ID, NO_ZLIB_COMPRESSION_ID_INDEX, PIN_ATTEMPTS_RESET};
use crate::compression::zlib_func;
use crate::encryption::{
    decrypt_data_file, destroy_image_file, reassemble_bluesky_data, write_pin_attempts,
};
use anyhow::{bail, Result};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn recover_data(jpg_vec: &mut Vec<u8>, mode: Mode, image_file_path: &Path) -> Result<()> {
    const SIG_LENGTH: usize = 7;
    const INDEX_DIFF: usize = 8;

    const JDVRIF_SIG: [u8; 7] = [0xB4, 0x6A, 0x3E, 0xEA, 0x5E, 0x9D, 0xF9];
    const ICC_PROFILE_SIG: [u8; 7] = [0x6D, 0x6E, 0x74, 0x72, 0x52, 0x47, 0x42];

    let Some(jdvrif_sig_index) = search_sig(jpg_vec, &JDVRIF_SIG, 0) else {
        bail!(
            "Image File Error: Signature check failure. \
             This is not a valid jdvrif \"file-embedded\" image."
        );
    };

    let pin_attempts_offset = (jdvrif_sig_index + INDEX_DIFF - 1) as u64;
    let mut pin_attempts_val = jpg_vec[jdvrif_sig_index + INDEX_DIFF - 1];

    let mut is_bluesky_file = true;
    let mut is_data_compressed = true;

    if let Some(icc_profile_sig_index) = search_sig(jpg_vec, &ICC_PROFILE_SIG, 0) {
        const NO_ZLIB_COMPRESSION_ID_INDEX_DIFF: usize = 24;
        jpg_vec.drain(..icc_profile_sig_index - INDEX_DIFF);
        is_data_compressed = jpg_vec
            [NO_ZLIB_COMPRESSION_ID_INDEX - NO_ZLIB_COMPRESSION_ID_INDEX_DIFF]
            != NO_ZLIB_COMPRESSION_ID;
        is_bluesky_file = false;
    }

    if is_bluesky_file {
        reassemble_bluesky_data(jpg_vec, SIG_LENGTH)?;
    }

    let mut has_decryption_failed = false;
    let decrypted_filename = decrypt_data_file(jpg_vec, is_bluesky_file, &mut has_decryption_failed)?;

    if has_decryption_failed {
        if pin_attempts_val == PIN_ATTEMPTS_RESET {
            pin_attempts_val = 0;
        } else {
            pin_attempts_val += 1;
        }

        if pin_attempts_val > 2 {
            destroy_image_file(image_file_path)?;
        } else {
            write_pin_attempts(image_file_path, pin_attempts_offset, pin_attempts_val)?;
        }
        bail!("File Decryption Error: Invalid recovery PIN or file is corrupt.");
    }

    if is_data_compressed {
        zlib_func(jpg_vec, mode)?;
    }

    if jpg_vec.is_empty() {
        bail!("Zlib Compression Error: Output file is empty. Inflating file failed.");
    }

    // Reset PIN attempts counter on successful decryption.
    if pin_attempts_val != PIN_ATTEMPTS_RESET {
        write_pin_attempts(image_file_path, pin_attempts_offset, PIN_ATTEMPTS_RESET)?;
    }

    {
        let mut file = File::create(&decrypted_filename).map_err(|_| {
            anyhow::anyhow!(
                "Write Error: Unable to write to file. \
                 Make sure you have WRITE permissions for this location."
            )
        })?;
        file.write_all(jpg_vec)?;
        file.flush()?;
    }

    println!(
        "\nExtracted hidden file: {} ({} bytes).\n\nComplete! Please check your file.\n",
        decrypted_filename,
        jpg_vec.len()
    );

    Ok(())
}
