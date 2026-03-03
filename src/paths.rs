use std::path::{Path, PathBuf};

use super::*;

fn make_unique_randomized_path(
    parent_dir: &Path,
    prefix: &str,
    suffix: &str,
    max_attempts: usize,
) -> Option<PathBuf> {
    if max_attempts == 0 {
        return None;
    }

    for _ in 0..max_attempts {
        let rand_num = 100000u32 + randombytes_uniform(900000u32);
        let filename = format!("{prefix}{rand_num}{suffix}");
        let candidate = if parent_dir.as_os_str().is_empty() {
            PathBuf::from(filename)
        } else {
            parent_dir.join(filename)
        };

        if !candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

pub(crate) fn unique_randomized_path_or_throw(
    parent_dir: &Path,
    prefix: &str,
    suffix: &str,
    max_attempts: usize,
    error_message: &str,
) -> Result<PathBuf, String> {
    make_unique_randomized_path(parent_dir, prefix, suffix, max_attempts)
        .ok_or_else(|| error_message.to_string())
}
