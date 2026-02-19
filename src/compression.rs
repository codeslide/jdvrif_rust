use crate::common::Mode;
use anyhow::{bail, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Compress (conceal mode) or decompress (recover mode) data using zlib.
pub fn zlib_func(data: &mut Vec<u8>, mode: Mode) -> Result<()> {
    match mode {
        Mode::Conceal => {
            let input_size = data.len();

            const THRESHOLD_BEST_SPEED: usize = 500 * 1024 * 1024;
            const THRESHOLD_DEFAULT: usize = 250 * 1024 * 1024;

            let level = if input_size > THRESHOLD_BEST_SPEED {
                Compression::fast()
            } else if input_size > THRESHOLD_DEFAULT {
                Compression::default()
            } else {
                Compression::best()
            };

            let mut encoder = ZlibEncoder::new(Vec::with_capacity(input_size), level);
            encoder.write_all(data)?;
            *data = encoder.finish()?;
        }
        Mode::Recover => {
            let mut decoder = ZlibDecoder::new(data.as_slice());
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).map_err(|e| {
                anyhow::anyhow!("zlib inflate error: {}", e)
            })?;
            if output.is_empty() {
                bail!("Zlib Compression Error: Output file is empty. Inflating file failed.");
            }
            *data = output;
        }
    }
    Ok(())
}
