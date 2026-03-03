use super::*;

fn is_valid_filename_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b'@' | b'%')
}

pub(crate) fn has_valid_filename(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes.iter().copied().all(is_valid_filename_char)
}

pub(crate) fn has_file_extension(path: &Path, exts: &[&str]) -> bool {
    let ext = path
        .extension()
        .map(|v| v.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    exts.iter().any(|e| ext == *e)
}

pub(crate) fn validate_file_for_read(
    path: &Path,
    is_image: bool,
    is_cover_image: bool,
) -> Result<usize, String> {
    if !has_valid_filename(path) {
        return Err(
            "Invalid Input Error: Unsupported characters in filename arguments.".to_string(),
        );
    }

    let metadata = fs::metadata(path).map_err(|_| {
        format!(
            "Error: File \"{}\" not found or not a regular file.",
            path.to_string_lossy()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "Error: File \"{}\" not found or not a regular file.",
            path.to_string_lossy()
        ));
    }

    let file_size = metadata.len();
    if file_size == 0 {
        return Err("Error: File is empty.".to_string());
    }

    if is_image {
        if !has_file_extension(path, &["png", "jpg", "jpeg", "jfif"]) {
            return Err("File Type Error: Invalid image extension. Only expecting \".jpg\", \".jpeg\", \".jfif\" or \".png\".".to_string());
        }

        if is_cover_image {
            if file_size < MINIMUM_IMAGE_SIZE {
                return Err("File Error: Invalid image file size.".to_string());
            }
            if file_size > MAX_IMAGE_SIZE {
                return Err(
                    "Image File Error: Cover image file exceeds maximum size limit.".to_string(),
                );
            }
        }
    }

    if file_size > MAX_FILE_SIZE {
        return Err("Error: File exceeds program size limit.".to_string());
    }

    usize::try_from(file_size).map_err(|_| "Error: File is too large for this build.".to_string())
}

pub(crate) fn checked_file_size(
    path: &Path,
    error_message: &str,
    require_non_empty: bool,
) -> Result<usize, String> {
    let size = fs::metadata(path)
        .map_err(|_| error_message.to_string())?
        .len();
    let size_usize = usize::try_from(size).map_err(|_| error_message.to_string())?;
    if require_non_empty && size_usize == 0 {
        return Err(error_message.to_string());
    }
    Ok(size_usize)
}

pub(crate) fn open_binary_input_or_throw(path: &Path, error_message: &str) -> Result<File, String> {
    File::open(path).map_err(|_| error_message.to_string())
}

pub(crate) fn open_binary_output_for_write_or_throw(path: &Path) -> Result<File, String> {
    File::create(path).map_err(|_| {
        "Write Error: Unable to write to file. Make sure you have WRITE permissions for this location.".to_string()
    })
}

pub(crate) fn cleanup_path_no_throw(path: &Path) {
    let _ = fs::remove_file(path);
}

pub(crate) fn span_has_range(data_len: usize, index: usize, length: usize) -> bool {
    index <= data_len && length <= data_len.saturating_sub(index)
}

pub(crate) fn get_value(data: &[u8], index: usize, length: usize) -> Result<usize, String> {
    if !span_has_range(data.len(), index, length) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let val = match length {
        2 => u16::from_be_bytes([data[index], data[index + 1]]) as usize,
        4 => u32::from_be_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]) as usize,
        8 => u64::from_be_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
            data[index + 4],
            data[index + 5],
            data[index + 6],
            data[index + 7],
        ]) as usize,
        _ => return Err(CORRUPT_FILE_ERROR.to_string()),
    };

    Ok(val)
}

pub(crate) fn update_value(
    data: &mut [u8],
    index: usize,
    value: usize,
    length: usize,
) -> Result<(), String> {
    if !span_has_range(data.len(), index, length) {
        return Err("Internal Error: Segment metadata index out of range.".to_string());
    }

    match length {
        2 => {
            let v = u16::try_from(value)
                .map_err(|_| "Internal Error: Segment value overflow.".to_string())?;
            data[index..index + 2].copy_from_slice(&v.to_be_bytes());
        }
        4 => {
            let v = u32::try_from(value)
                .map_err(|_| "Internal Error: Segment value overflow.".to_string())?;
            data[index..index + 4].copy_from_slice(&v.to_be_bytes());
        }
        8 => {
            let v = u64::try_from(value)
                .map_err(|_| "Internal Error: Segment value overflow.".to_string())?;
            data[index..index + 8].copy_from_slice(&v.to_be_bytes());
        }
        _ => return Err("Internal Error: Unsupported metadata field length.".to_string()),
    }

    Ok(())
}
