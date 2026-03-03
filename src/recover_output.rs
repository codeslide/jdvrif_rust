use crate::paths::unique_randomized_path_or_throw;
use std::path::Path;

use super::*;

pub(super) fn temp_recovery_path(output_path: &Path) -> Result<PathBuf, String> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new(""));
    let parent_dir = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let stem = output_path
        .file_stem()
        .unwrap_or_else(|| OsStr::new("output"))
        .to_string_lossy();
    let ext = output_path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    unique_randomized_path_or_throw(
        parent_dir,
        &format!(".{}.tmp.", stem),
        &ext,
        MAX_PATH_ATTEMPTS,
        "Write Error: Could not create temporary recovery output path.",
    )
}

pub(super) fn safe_recovery_path(decrypted_filename: String) -> Result<PathBuf, String> {
    let mut file_name = Path::new(&decrypted_filename)
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_else(|| OsString::from("recovered_data.bin"));
    if file_name.as_os_str().is_empty() {
        file_name = OsString::from("recovered_data.bin");
    }

    let mut normalized = PathBuf::new();
    for component in Path::new(&file_name).components() {
        if let Component::Normal(part) = component {
            normalized.push(part);
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized = PathBuf::from("recovered_data.bin");
    }

    let mut output_path = PathBuf::from(&normalized);
    if !has_valid_filename(&output_path) {
        output_path = PathBuf::from("recovered_data.bin");
    }

    if output_path.exists() {
        let ext = output_path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let stem = output_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "recovered_data".to_string());
        output_path = unique_randomized_path_or_throw(
            Path::new("."),
            &format!("{}_", stem),
            &ext,
            1,
            "Write Error: Could not allocate unique recovered output path.",
        )?;
    }

    Ok(output_path)
}

pub(super) fn commit_recovered_output(
    staged_path: &Path,
    output_path: &Path,
) -> Result<(), String> {
    fs::rename(staged_path, output_path)
        .map_err(|_| "Write Error: Failed to save recovered output file.".to_string())
}

pub(super) fn print_recovery_success(output_path: &Path, output_size: usize) {
    println!(
        "\nExtracted hidden file: {} ({} bytes).\n\nComplete! Please check your file.\n",
        output_path.to_string_lossy(),
        output_size
    );
}
