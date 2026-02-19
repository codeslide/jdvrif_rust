// JPG Data Vehicle (jdvrif v7.5) Created by Nicholas Cleasby (@CleasbyCode) 10/04/2023
// Rust port

mod args;
mod base64;
mod binary_io;
mod common;
mod compression;
mod conceal;
mod encryption;
mod file_utils;
mod jpeg_utils;
mod pin_input;
mod recover;
mod segmentation;

use args::ProgramArgs;
use common::{FileTypeCheck, Mode};
use file_utils::read_file;

fn main() {
    if let Err(e) = run() {
        eprintln!("\n{}\n", e);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    sodiumoxide::init().map_err(|()| anyhow::anyhow!("Libsodium initialization failed!"))?;

    let args: Vec<String> = std::env::args().collect();
    let Some(parsed) = ProgramArgs::parse(&args)? else {
        return Ok(());
    };

    let file_type = if parsed.mode == Mode::Conceal {
        FileTypeCheck::CoverImage
    } else {
        FileTypeCheck::EmbeddedImage
    };

    let mut jpg_vec = read_file(&parsed.image_file_path, file_type)?;

    match parsed.mode {
        Mode::Conceal => {
            conceal::conceal_data(&mut jpg_vec, parsed.mode, parsed.option, &parsed.data_file_path)?;
        }
        Mode::Recover => {
            recover::recover_data(&mut jpg_vec, parsed.mode, &parsed.image_file_path)?;
        }
    }

    Ok(())
}
