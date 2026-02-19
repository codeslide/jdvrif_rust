use crate::common::FileTypeCheck;
use anyhow::{bail, Result};
use std::fs;
use std::path::Path;

/// Check that a filename contains only safe characters.
pub fn has_valid_filename(path: &Path) -> bool {
    let Some(filename) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    if filename.is_empty() {
        return false;
    }
    filename.bytes().all(|c| {
        c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_' || c == b'@' || c == b'%'
    })
}

/// Check if a file path has one of the given extensions (case-insensitive).
pub fn has_file_extension(path: &Path, exts: &[&str]) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext_lower = format!(".{}", ext.to_ascii_lowercase());
    exts.iter().any(|&e| ext_lower == e)
}

/// Read a file into a Vec<u8>, with validation based on FileTypeCheck.
pub fn read_file(path: &Path, file_type: FileTypeCheck) -> Result<Vec<u8>> {
    if !has_valid_filename(path) {
        bail!("Invalid Input Error: Unsupported characters in filename arguments.");
    }

    if !path.exists() || !path.is_file() {
        bail!(
            "Error: File \"{}\" not found or not a regular file.",
            path.display()
        );
    }

    let file_size = fs::metadata(path)?.len() as usize;

    if file_size == 0 {
        bail!("Error: File is empty.");
    }

    match file_type {
        FileTypeCheck::CoverImage | FileTypeCheck::EmbeddedImage => {
            if !has_file_extension(path, &[".png", ".jpg", ".jpeg", ".jfif"]) {
                bail!("File Type Error: Invalid image extension. Only expecting \".jpg\", \".jpeg\", \".jfif\" or \".png\".");
            }
            if file_type == FileTypeCheck::CoverImage {
                const MINIMUM_IMAGE_SIZE: usize = 134;
                if file_size < MINIMUM_IMAGE_SIZE {
                    bail!("File Error: Invalid image file size.");
                }
                const MAX_IMAGE_SIZE: usize = 8 * 1024 * 1024;
                if file_size > MAX_IMAGE_SIZE {
                    bail!("Image File Error: Cover image file exceeds maximum size limit.");
                }
            }
        }
        FileTypeCheck::DataFile => {}
    }

    const MAX_FILE_SIZE: usize = 3 * 1024 * 1024 * 1024;
    if file_size > MAX_FILE_SIZE {
        bail!("Error: File exceeds program size limit.");
    }

    let data = fs::read(path)?;
    if data.len() != file_size {
        bail!("Failed to read full file: partial read");
    }
    Ok(data)
}
