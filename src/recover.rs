#[path = "recover_modes.rs"]
mod modes;
#[path = "recover_output.rs"]
mod output;

use crate::extract::{find_signature_in_file, has_signature_at};
use std::path::Path;

use self::modes::{recover_from_bluesky_path, recover_from_icc_path};
use super::*;

pub(crate) fn run_native_recover(image_file_path: &Path) -> Result<(), NativeRecoverError> {
    const INDEX_DIFF: usize = 8;
    const ICC_SCAN_BACKWARD_WINDOW: usize = 128 * 1024;
    const JDVRIF_TO_ICC_SIG_DIFF: usize = 811;

    sodiumoxide::init()
        .map_err(|_| NativeRecoverError::Message("Libsodium initialization failed!".to_string()))?;

    let image_file_size = validate_file_for_read(image_file_path, true, false)
        .map_err(NativeRecoverError::Message)?;

    let jdvrif_sig_index = find_signature_in_file(image_file_path, &JDVRIF_SIG, 0, 0)
        .map_err(NativeRecoverError::Message)?
        .ok_or_else(|| {
            NativeRecoverError::Message(
                "Image File Error: Signature check failure. This is not a valid jdvrif \"file-embedded\" image."
                    .to_string(),
            )
        })?;

    if jdvrif_sig_index > image_file_size
        || INDEX_DIFF > image_file_size.saturating_sub(jdvrif_sig_index)
    {
        return Err(NativeRecoverError::Message(
            "Image File Error: Corrupt signature metadata.".to_string(),
        ));
    }

    let mut input =
        open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")
            .map_err(NativeRecoverError::Message)?;

    let mut icc_opt = None;
    if jdvrif_sig_index >= JDVRIF_TO_ICC_SIG_DIFF {
        let icc_candidate = jdvrif_sig_index - JDVRIF_TO_ICC_SIG_DIFF;

        if has_signature_at(&mut input, image_file_size, icc_candidate, &ICC_PROFILE_SIG)
            .map_err(NativeRecoverError::Message)?
        {
            icc_opt = Some(icc_candidate);
        } else {
            let icc_scan_start = jdvrif_sig_index.saturating_sub(ICC_SCAN_BACKWARD_WINDOW);
            let icc_scan_end = jdvrif_sig_index + 1;
            icc_opt = find_signature_in_file(
                image_file_path,
                &ICC_PROFILE_SIG,
                icc_scan_end,
                icc_scan_start,
            )
            .map_err(NativeRecoverError::Message)?;
        }
    }

    if let Some(icc_profile_sig_index) = icc_opt {
        recover_from_icc_path(image_file_path, image_file_size, icc_profile_sig_index)?;
        return Ok(());
    }

    recover_from_bluesky_path(
        image_file_path,
        image_file_size,
        jdvrif_sig_index,
        &JDVRIF_SIG,
    )
}
