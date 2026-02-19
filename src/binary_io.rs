use anyhow::{bail, Result};

/// Search for a byte signature within `data`, optionally limited to the first `limit` bytes.
/// Returns the index of the first match, or None.
pub fn search_sig(data: &[u8], sig: &[u8], limit: usize) -> Option<usize> {
    let search_range = if limit == 0 || limit > data.len() {
        data
    } else {
        &data[..limit]
    };
    search_range
        .windows(sig.len())
        .position(|w| w == sig)
}

/// Write a big-endian value of `length` bytes into `data` at `index`.
pub fn update_value(data: &mut [u8], index: usize, value: usize, length: usize) -> Result<()> {
    if index + length > data.len() {
        bail!("update_value: index {} + length {} out of bounds (len {})", index, length, data.len());
    }
    match length {
        2 => data[index..index + 2].copy_from_slice(&(value as u16).to_be_bytes()),
        4 => data[index..index + 4].copy_from_slice(&(value as u32).to_be_bytes()),
        8 => data[index..index + 8].copy_from_slice(&(value as u64).to_be_bytes()),
        _ => bail!("update_value: unsupported length {}", length),
    }
    Ok(())
}

/// Read a big-endian value of `length` bytes from `data` at `index`.
pub fn get_value(data: &[u8], index: usize, length: usize) -> Result<usize> {
    if index + length > data.len() {
        bail!("get_value: index {} + length {} out of bounds (len {})", index, length, data.len());
    }
    let val = match length {
        2 => {
            let arr: [u8; 2] = data[index..index + 2].try_into().unwrap();
            u16::from_be_bytes(arr) as usize
        }
        4 => {
            let arr: [u8; 4] = data[index..index + 4].try_into().unwrap();
            u32::from_be_bytes(arr) as usize
        }
        8 => {
            let arr: [u8; 8] = data[index..index + 8].try_into().unwrap();
            u64::from_be_bytes(arr) as usize
        }
        _ => bail!("get_value: unsupported length {}", length),
    };
    Ok(val)
}
