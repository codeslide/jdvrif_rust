// JPG Data Vehicle (jdvrif v7.5) Created by Nicholas Cleasby (@CleasbyCode) 10/04/2023

pub const NO_ZLIB_COMPRESSION_ID_INDEX: usize = 0x80;
pub const NO_ZLIB_COMPRESSION_ID: u8 = 0x58; // 'X'
pub const PIN_ATTEMPTS_RESET: u8 = 0x90;
#[allow(dead_code)]
pub const TAG_BYTES: usize = 16; // crypto_secretbox_MACBYTES

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Conceal,
    Recover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Option_ {
    None,
    Bluesky,
    Reddit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTypeCheck {
    CoverImage,
    EmbeddedImage,
    DataFile,
}

pub struct PlatformLimits {
    pub name: &'static str,
    pub max_image_size: usize,
    pub max_first_segment: usize,
    pub max_segments: u16,
}

pub const PLATFORM_LIMITS: &[PlatformLimits] = &[
    PlatformLimits { name: "X-Twitter",  max_image_size: 5   * 1024 * 1024, max_first_segment: 10 * 1024,    max_segments: u16::MAX },
    PlatformLimits { name: "Tumblr",     max_image_size: usize::MAX,        max_first_segment: 65534,        max_segments: u16::MAX },
    PlatformLimits { name: "Mastodon",   max_image_size: 16  * 1024 * 1024, max_first_segment: usize::MAX,   max_segments: 100 },
    PlatformLimits { name: "Pixelfed",   max_image_size: 15  * 1024 * 1024, max_first_segment: usize::MAX,   max_segments: u16::MAX },
    PlatformLimits { name: "PostImage",  max_image_size: 32  * 1024 * 1024, max_first_segment: usize::MAX,   max_segments: u16::MAX },
    PlatformLimits { name: "ImgBB",      max_image_size: 32  * 1024 * 1024, max_first_segment: usize::MAX,   max_segments: u16::MAX },
    PlatformLimits { name: "ImgPile",    max_image_size: 100 * 1024 * 1024, max_first_segment: usize::MAX,   max_segments: u16::MAX },
    PlatformLimits { name: "Flickr",     max_image_size: 200 * 1024 * 1024, max_first_segment: usize::MAX,   max_segments: u16::MAX },
];
