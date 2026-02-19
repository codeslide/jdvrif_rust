use crate::common::{Mode, Option_};
use anyhow::{bail, Result};
use std::path::PathBuf;

pub struct ProgramArgs {
    pub mode: Mode,
    pub option: Option_,
    pub image_file_path: PathBuf,
    pub data_file_path: PathBuf,
}

pub fn display_info() {
    print!(
        r#"

JPG Data Vehicle (jdvrif v7.5)
Created by Nicholas Cleasby (@CleasbyCode) 10/04/2023

jdvrif is a metadata "steganography-like" command-line tool used for concealing and extracting
any file type within and from a JPG image.

──────────────────────────
Build & install (Linux)
──────────────────────────

  Requirements: Rust toolchain (rustup), libsodium-dev, libturbojpeg0-dev, pkg-config.

  $ sudo apt install libsodium-dev libturbojpeg0-dev pkg-config
  $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

  $ cargo build --release

  Build complete. Binary at 'target/release/jdvrif'.

  $ sudo cp target/release/jdvrif /usr/bin
  $ jdvrif

──────────────────────────
Usage
──────────────────────────

  jdvrif conceal [-b|-r] <cover_image> <secret_file>
  jdvrif recover <cover_image>
  jdvrif --info

──────────────────────────
Platform compatibility & size limits
──────────────────────────

Share your "file-embedded" JPG image on the following compatible sites.

Platforms where size limit is measured by the combined size of cover image + compressed data file:

	• Flickr    (200 MB)
	• ImgPile   (100 MB)
	• ImgBB     (32 MB)
	• PostImage (32 MB)
	• Reddit    (20 MB) — (use -r option).
	• Pixelfed  (15 MB)

Limit measured by compressed data file size only:

	• Mastodon  (~6 MB)
	• Tumblr    (~64 KB)
	• X-Twitter (~10 KB)

For example, on Mastodon, even if your cover image is 1 MB, you can still embed a data file
up to the ~6 MB Mastodon size limit.

Other:

Bluesky - Separate size limits for cover image and data file - (use -b option).
  • Cover image: 800 KB
  • Secret data file (compressed): ~171 KB

Even though jdvrif compresses the data file, you may want to compress it yourself first
(zip, rar, 7z, etc.) so that you know the exact compressed file size.

Platforms with small size limits, like X-Twitter (~10 KB), are best suited for data that
compress especially well, such as text files.

──────────────────────────
Modes
──────────────────────────

conceal - *Compresses, encrypts and embeds your secret data file within a JPG cover image.
recover - Decrypts, uncompresses and extracts the concealed data file from a JPG cover image
          (recovery PIN required).

(*Compression: If data file is already a compressed file type (based on file extension: e.g. ".zip")
 and the file is greater than 10MB, skip compression).

──────────────────────────
Platform options for conceal mode
──────────────────────────

-b (Bluesky) : Creates compatible "file-embedded" JPG images for posting on Bluesky.

$ jdvrif conceal -b my_image.jpg hidden.doc

These images are only compatible for posting on Bluesky.

You must use the Python script "bsky_post.py" (in the repo's src folder) to post to Bluesky.
Posting via the Bluesky website or mobile app will NOT work.

You also need to create an app password for your Bluesky account: https://bsky.app/settings/app-passwords

Here are some basic usage examples for the bsky_post.py Python script:

Standard image post to your profile/account.

$ python3 bsky_post.py --handle you.bsky.social --password xxxx-xxxx-xxxx-xxxx
--image your_image.jpg --alt-text "alt-text here [optional]" "standard post text here [required]"

If you want to post multiple images (Max. 4):

$ python3 bsky_post.py --handle you.bsky.social --password xxxx-xxxx-xxxx-xxxx
--image img1.jpg --image img2.jpg --alt-text "alt_here" "standard post text..."

If you want to post an image as a reply to another thread:

$ python3 bsky_post.py --handle you.bsky.social --password xxxx-xxxx-xxxx-xxxx
--image your_image.jpg --alt-text "alt_here"
--reply-to https://bsky.app/profile/someone.bsky.social/post/8m2tgw6cgi23i
"standard post text..."

Bluesky size limits: Cover 800 KB / Secret data file (compressed) ~171 KB

-r (Reddit) : Creates compatible "file-embedded" JPG images for posting on Reddit.

$ jdvrif conceal -r my_image.jpg secret.mp3

From the Reddit site, click "Create Post", then select the "Images & Video" tab to attach the JPG image.
These images are only compatible for posting on Reddit.

To correctly download images from X-Twitter or Reddit, click image within the post to fully expand it before saving.

    "#
    );
}

impl ProgramArgs {
    pub fn parse(args: &[String]) -> Result<Option<ProgramArgs>> {
        let prog = std::path::Path::new(&args[0])
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("jdvrif");

        let prefix = "Usage: ";
        let indent = " ".repeat(prefix.len());
        let usage = format!(
            "{prefix}{prog} conceal [-b|-r] <cover_image> <secret_file>\n\
             {indent}{prog} recover <cover_image>\n\
             {indent}{prog} --info"
        );

        if args.len() < 2 {
            bail!("{}", usage);
        }

        if args.len() == 2 && args[1] == "--info" {
            display_info();
            return Ok(None);
        }

        let mode_str = &args[1];

        if mode_str == "conceal" {
            let mut i = 2;
            let mut option = Option_::None;

            if i < args.len() && args[i] == "-b" {
                option = Option_::Bluesky;
                i += 1;
            } else if i < args.len() && args[i] == "-r" {
                option = Option_::Reddit;
                i += 1;
            }

            if args.len() != i + 2 {
                bail!("{}", usage);
            }

            return Ok(Some(ProgramArgs {
                mode: Mode::Conceal,
                option,
                image_file_path: PathBuf::from(&args[i]),
                data_file_path: PathBuf::from(&args[i + 1]),
            }));
        }

        if mode_str == "recover" {
            if args.len() != 3 {
                bail!("{}", usage);
            }
            return Ok(Some(ProgramArgs {
                mode: Mode::Recover,
                option: Option_::None,
                image_file_path: PathBuf::from(&args[2]),
                data_file_path: PathBuf::new(),
            }));
        }

        bail!("{}", usage);
    }
}
