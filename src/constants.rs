pub(crate) const INFO_TEXT: &str = r#"

JPG Data Vehicle (jdvrif v7.6)
Created by Nicholas Cleasby (@CleasbyCode) 10/04/2023

jdvrif is a metadata "steganography-like" command-line tool used for concealing and extracting
any file type within and from a JPG image.

──────────────────────────
Compile & run (Linux)
──────────────────────────

  $ sudo apt install libsodium-dev libturbojpeg0-dev pkg-config
  $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  $ cargo build --release

  Build complete. Binary at 'target/release/jdvrif-rs'.

  $ sudo cp target/release/jdvrif-rs /usr/bin
  $ jdvrif-rs

──────────────────────────
Usage
──────────────────────────

  jdvrif-rs conceal [-b|-r] <cover_image> <secret_file>
  jdvrif-rs recover <cover_image>
  jdvrif-rs --info

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

$ jdvrif-rs conceal -b my_image.jpg hidden.doc

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

$ jdvrif-rs conceal -r my_image.jpg secret.mp3

From the Reddit site, click "Create Post", then select the "Images & Video" tab to attach the JPG image.
These images are only compatible for posting on Reddit.

To correctly download images from X-Twitter or Reddit, click image within the post to fully expand it before saving.

    "#;

pub(crate) const PIN_ATTEMPTS_RESET: u8 = 0x90;
pub(crate) const NO_ZLIB_COMPRESSION_ID: u8 = 0x58;
pub(crate) const NO_ZLIB_COMPRESSION_ID_INDEX: usize = 0x80;

pub(crate) const MAX_FILE_SIZE: u64 = 3 * 1024 * 1024 * 1024;
pub(crate) const MINIMUM_IMAGE_SIZE: u64 = 134;
pub(crate) const MAX_IMAGE_SIZE: u64 = 8 * 1024 * 1024;

pub(crate) const WRITE_COMPLETE_ERROR: &str = "Write Error: Failed to write complete output file.";
pub(crate) const CORRUPT_FILE_ERROR: &str = "File Extraction Error: Embedded data file is corrupt!";

pub(crate) const JDVRIF_SIG: [u8; 7] = [0xB4, 0x6A, 0x3E, 0xEA, 0x5E, 0x9D, 0xF9];
pub(crate) const ICC_PROFILE_SIG: [u8; 7] = [0x6D, 0x6E, 0x74, 0x72, 0x52, 0x47, 0x42];

pub(crate) const KDF_METADATA_MAGIC_V2: [u8; 4] = *b"KDF2";
pub(crate) const KDF_METADATA_REGION_BYTES: usize = 56;
pub(crate) const KDF_MAGIC_OFFSET: usize = 0;
pub(crate) const KDF_ALG_OFFSET: usize = 4;
pub(crate) const KDF_SENTINEL_OFFSET: usize = 5;
pub(crate) const KDF_SALT_OFFSET: usize = 8;
pub(crate) const KDF_NONCE_OFFSET: usize = 24;
pub(crate) const KDF_ALG_ARGON2ID13: u8 = 1;
pub(crate) const KDF_SENTINEL: u8 = 0xA5;

pub(crate) const STREAM_FRAME_LEN_BYTES: usize = 4;
pub(crate) const STREAM_INFLATE_MAX_OUTPUT: usize = 3 * 1024 * 1024 * 1024;
pub(crate) const MAX_PATH_ATTEMPTS: usize = 1024;
pub(crate) const DATA_FILENAME_MAX_LENGTH: usize = 20;
pub(crate) const LARGE_FILE_SIZE: usize = 300 * 1024 * 1024;
pub(crate) const COMPRESS_BYPASS_SIZE: usize = 10 * 1024 * 1024;
pub(crate) const MAX_SIZE_CONCEAL: usize = 2 * 1024 * 1024 * 1024;
pub(crate) const MAX_SIZE_REDDIT: usize = 20 * 1024 * 1024;
pub(crate) const MAX_SIZE_REDDIT_PADDING: usize = 8000;
pub(crate) const SEGMENT_DATA_SIZE: usize = 65519;
pub(crate) const SEGMENT_HEADER_LENGTH: usize = 16;
pub(crate) const SOI_SIG_LENGTH: usize = 2;
pub(crate) const SEGMENT_SIG_LENGTH: usize = 2;
pub(crate) const PROFILE_DATA_SIZE: usize = 851;
pub(crate) const PROFILE_SIZE_DIFF: usize = 16;
pub(crate) const SEGMENT_HEADER_SIZE_INDEX: usize = 0x04;
pub(crate) const PROFILE_SIZE_INDEX: usize = 0x16;
pub(crate) const SEGMENTS_TOTAL_VAL_INDEX: usize = 0x2E0;
pub(crate) const DEFLATED_DATA_FILE_SIZE_INDEX: usize = 0x2E2;
pub(crate) const TOTAL_SEGMENTS_INDEX: usize = 0x2E0;
pub(crate) const FIRST_SEGMENT_SIZE_INDEX: usize = 0x04;
pub(crate) const DEFAULT_DECRYPT_KDF_METADATA_INDEX: usize = 0x2FB;
pub(crate) const DEFAULT_KDF_METADATA_INDEX: usize = 0x313;
pub(crate) const DEFAULT_METADATA_PREFIX_BYTES: usize = 0x353;
pub(crate) const BASE_OFFSET_DEFAULT: usize = 24;
pub(crate) const DEFAULT_ICC_SIG_INDEX_ABS: usize = BASE_OFFSET_DEFAULT + 8;
pub(crate) const DEFAULT_JDVRIF_SIG_INDEX_ABS: usize = BASE_OFFSET_DEFAULT + 0x333;
pub(crate) const DEFAULT_PIN_ATTEMPTS_INDEX_ABS: usize =
    DEFAULT_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len();
pub(crate) const PADDING_START: u8 = 33;
pub(crate) const PADDING_RANGE: u32 = 94;
pub(crate) const STREAM_CHUNK_SIZE: usize = 1024 * 1024;
pub(crate) const MAX_DATA_SIZE_BLUESKY: usize = 2 * 1024 * 1024;

pub(crate) const BLUESKY_EXIF_SEGMENT_DATA_INSERT_INDEX: usize = 0x1D1;
pub(crate) const BLUESKY_COMPRESSED_FILE_SIZE_INDEX: usize = 0x1CD;
pub(crate) const BLUESKY_EXIF_SEGMENT_SIZE_INDEX: usize = 0x04;
pub(crate) const BLUESKY_ARTIST_FIELD_SIZE_INDEX: usize = 0x4A;
pub(crate) const BLUESKY_ARTIST_FIELD_SIZE_DIFF: usize = 140;
pub(crate) const BLUESKY_KDF_METADATA_INDEX: usize = 0x18D;

pub(crate) const DEFAULT_ICC_TEMPLATE: &[u8] = include_bytes!("templates/default_icc_template.bin");
pub(crate) const BLUESKY_EXIF_TEMPLATE: &[u8] =
    include_bytes!("templates/bluesky_exif_template.bin");
pub(crate) const PHOTOSHOP_SEGMENT_TEMPLATE: &[u8] =
    include_bytes!("templates/photoshop_segment_template.bin");
pub(crate) const XMP_SEGMENT_TEMPLATE: &[u8] = include_bytes!("templates/xmp_segment_template.bin");
