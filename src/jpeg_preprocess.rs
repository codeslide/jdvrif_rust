use libc::{self, c_void};
use std::cmp;
use std::ffi::CStr;
use std::fs;
use std::path::Path;

const PROGRESSIVE_SOURCE_LIMIT: usize = 2 * 1024 * 1024;
const MAX_OPTIMIZED_IMAGE_SIZE: usize = 4 * 1024 * 1024;
const MAX_OPTIMIZED_BLUESKY_IMG: usize = 805 * 1024;
const DQT_SEARCH_LIMIT: usize = 100;
const EXIF_SEARCH_LIMIT: usize = 4096;
const EXIF_HEADER_SIZE: usize = 6;
const TIFF_HEADER_SIZE: usize = 8;
const IFD_ENTRY_SIZE: usize = 12;
const DQT_QUALITY_SEARCH_LIMIT: usize = 32768;
const DQT_8BIT_TABLE_SIZE: usize = 64;
const DQT_16BIT_TABLE_SIZE: usize = 128;
const DEFAULT_QUALITY_ESTIMATE: i32 = 80;
const MIN_COVER_DIMENSION: i32 = 400;
const MAX_ALLOWED_QUALITY: i32 = 97;
const TAG_ORIENTATION: u16 = 0x0112;
const APP1_SIG: [u8; 2] = [0xFF, 0xE1];
const EXIF_SIG: [u8; 6] = [b'E', b'x', b'i', b'f', 0x00, 0x00];
const DQT_SIG: [u8; 2] = [0xFF, 0xDB];
const DQT1_SIG: [u8; 4] = [0xFF, 0xDB, 0x00, 0x43];
const DQT2_SIG: [u8; 4] = [0xFF, 0xDB, 0x00, 0x84];

const STD_LUMINANCE_SUMS: [i32; 101] = [
    0, 16320, 16315, 15946, 15277, 14655, 14073, 13623, 13230, 12859, 12560, 12240, 11861, 11456,
    11081, 10714, 10360, 10027, 9679, 9368, 9056, 8680, 8331, 7995, 7668, 7376, 7084, 6823, 6562,
    6345, 6125, 5939, 5756, 5571, 5421, 5240, 5086, 4976, 4829, 4719, 4616, 4463, 4393, 4280, 4166,
    4092, 3980, 3909, 3835, 3755, 3688, 3621, 3541, 3467, 3396, 3323, 3247, 3170, 3096, 3021, 2952,
    2874, 2804, 2727, 2657, 2583, 2509, 2437, 2362, 2290, 2211, 2136, 2068, 1996, 1915, 1858, 1773,
    1692, 1620, 1552, 1477, 1398, 1326, 1251, 1179, 1109, 1031, 961, 884, 814, 736, 667, 592, 518,
    441, 369, 292, 221, 151, 86, 64,
];

const TJXOP_NONE: i32 = 0;
const TJXOP_HFLIP: i32 = 1;
const TJXOP_VFLIP: i32 = 2;
const TJXOP_TRANSPOSE: i32 = 3;
const TJXOP_TRANSVERSE: i32 = 4;
const TJXOP_ROT90: i32 = 5;
const TJXOP_ROT180: i32 = 6;
const TJXOP_ROT270: i32 = 7;
const TJXOPT_TRIM: i32 = 2;
const TJXOPT_PROGRESSIVE: i32 = 32;
const TJXOPT_COPYNONE: i32 = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct TjRegion {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

type TjCustomFilter = Option<
    unsafe extern "C" fn(
        coeffs: *mut i16,
        array_region: TjRegion,
        plane_region: TjRegion,
        component_index: i32,
        transform_index: i32,
        transform: *mut TjTransform,
    ) -> i32,
>;

#[repr(C)]
#[derive(Clone, Copy)]
struct TjTransform {
    r: TjRegion,
    op: i32,
    options: i32,
    data: *mut c_void,
    custom_filter: TjCustomFilter,
}

#[link(name = "turbojpeg")]
unsafe extern "C" {
    fn tjInitTransform() -> *mut c_void;
    fn tjDecompressHeader3(
        handle: *mut c_void,
        jpeg_buf: *const u8,
        jpeg_size: libc::c_ulong,
        width: *mut i32,
        height: *mut i32,
        jpeg_subsamp: *mut i32,
        jpeg_colorspace: *mut i32,
    ) -> i32;
    fn tjTransform(
        handle: *mut c_void,
        jpeg_buf: *const u8,
        jpeg_size: libc::c_ulong,
        n: i32,
        dst_bufs: *mut *mut u8,
        dst_sizes: *mut libc::c_ulong,
        transforms: *mut TjTransform,
        flags: i32,
    ) -> i32;
    fn tjDestroy(handle: *mut c_void) -> i32;
    fn tjFree(buffer: *mut u8);
    fn tjGetErrorStr2(handle: *mut c_void) -> *mut libc::c_char;
}

struct TurboJpegHandle {
    raw: *mut c_void,
}

impl TurboJpegHandle {
    fn new_transformer() -> Result<Self, String> {
        // SAFETY: tjInitTransform has no preconditions.
        let raw = unsafe { tjInitTransform() };
        if raw.is_null() {
            return Err("tjInitTransform() failed".to_string());
        }
        Ok(Self { raw })
    }

    fn as_ptr(&self) -> *mut c_void {
        self.raw
    }
}

impl Drop for TurboJpegHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: handle was returned by tjInitTransform and is dropped once.
            let _ = unsafe { tjDestroy(self.raw) };
            self.raw = std::ptr::null_mut();
        }
    }
}

struct TurboJpegBuffer {
    raw: *mut u8,
}

impl Drop for TurboJpegBuffer {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: buffer was allocated by TurboJPEG and must be released with tjFree.
            unsafe { tjFree(self.raw) };
            self.raw = std::ptr::null_mut();
        }
    }
}

fn span_has_range(data_len: usize, index: usize, length: usize) -> bool {
    index <= data_len && length <= data_len.saturating_sub(index)
}

fn search_sig(data: &[u8], sig: &[u8]) -> Option<usize> {
    if sig.is_empty() || data.len() < sig.len() {
        return None;
    }
    data.windows(sig.len()).position(|w| w == sig)
}

fn turbojpeg_error_string(handle: *mut c_void) -> String {
    // SAFETY: returned pointer is managed by TurboJPEG and valid for immediate conversion.
    let ptr = unsafe { tjGetErrorStr2(handle) };
    if ptr.is_null() {
        return "Unknown TurboJPEG error.".to_string();
    }
    // SAFETY: TurboJPEG returns a NUL-terminated error string.
    unsafe { CStr::from_ptr(ptr.cast::<libc::c_char>()) }
        .to_string_lossy()
        .into_owned()
}

fn exif_payload(jpg: &[u8]) -> Option<&[u8]> {
    let app1_pos = search_sig(jpg, &APP1_SIG)?;
    if app1_pos > EXIF_SEARCH_LIMIT || !span_has_range(jpg.len(), app1_pos, 4) {
        return None;
    }

    let segment_length = u16::from_be_bytes([jpg[app1_pos + 2], jpg[app1_pos + 3]]) as usize;
    if segment_length < 2 || !span_has_range(jpg.len(), app1_pos + 2, segment_length) {
        return None;
    }

    let payload_offset = app1_pos + 4;
    let payload_size = segment_length - 2;
    if !span_has_range(jpg.len(), payload_offset, payload_size) {
        return None;
    }
    Some(&jpg[payload_offset..payload_offset + payload_size])
}

fn read_tiff_u16(tiff: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    if !span_has_range(tiff.len(), offset, 2) {
        return None;
    }
    let raw = [tiff[offset], tiff[offset + 1]];
    Some(if little_endian {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn read_tiff_u32(tiff: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    if !span_has_range(tiff.len(), offset, 4) {
        return None;
    }
    let raw = [
        tiff[offset],
        tiff[offset + 1],
        tiff[offset + 2],
        tiff[offset + 3],
    ];
    Some(if little_endian {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

fn exif_orientation_from_tiff(tiff: &[u8]) -> Option<u16> {
    if tiff.len() < TIFF_HEADER_SIZE {
        return None;
    }

    let little_endian = match (tiff[0], tiff[1]) {
        (b'I', b'I') => true,
        (b'M', b'M') => false,
        _ => return None,
    };

    let magic = read_tiff_u16(tiff, 2, little_endian)?;
    if magic != 0x002A {
        return None;
    }

    let ifd_offset = usize::try_from(read_tiff_u32(tiff, 4, little_endian)?).ok()?;
    if !span_has_range(tiff.len(), ifd_offset, 2) {
        return None;
    }

    let entry_count = read_tiff_u16(tiff, ifd_offset, little_endian)?;
    let mut entry_pos = ifd_offset + 2;
    for _ in 0..entry_count {
        if !span_has_range(tiff.len(), entry_pos, IFD_ENTRY_SIZE) {
            return None;
        }
        let tag_id = read_tiff_u16(tiff, entry_pos, little_endian)?;
        if tag_id == TAG_ORIENTATION {
            return read_tiff_u16(tiff, entry_pos + 8, little_endian);
        }
        entry_pos += IFD_ENTRY_SIZE;
    }
    None
}

fn exif_orientation(jpg: &[u8]) -> Option<u16> {
    let payload = exif_payload(jpg)?;
    if payload.len() < EXIF_HEADER_SIZE || payload[..EXIF_HEADER_SIZE] != EXIF_SIG {
        return None;
    }
    exif_orientation_from_tiff(&payload[EXIF_HEADER_SIZE..])
}

fn get_transform_op(orientation: u16) -> i32 {
    match orientation {
        2 => TJXOP_HFLIP,
        3 => TJXOP_ROT180,
        4 => TJXOP_VFLIP,
        5 => TJXOP_TRANSPOSE,
        6 => TJXOP_ROT90,
        7 => TJXOP_TRANSVERSE,
        8 => TJXOP_ROT270,
        _ => TJXOP_NONE,
    }
}

fn quality_from_luminance_sum(sum: i32) -> i32 {
    if sum <= 64 {
        return 100;
    }
    if sum >= 16320 {
        return 1;
    }

    for q in 1..STD_LUMINANCE_SUMS.len() {
        if sum >= STD_LUMINANCE_SUMS[q] {
            if q > 1 {
                let diff_current = sum - STD_LUMINANCE_SUMS[q];
                let diff_prev = STD_LUMINANCE_SUMS[q - 1] - sum;
                if diff_prev < diff_current {
                    return (q - 1) as i32;
                }
            }
            return q as i32;
        }
    }
    100
}

fn estimate_image_quality(jpg: &[u8]) -> i32 {
    let Some(dqt_pos) = search_sig(
        &jpg[..cmp::min(jpg.len(), DQT_QUALITY_SEARCH_LIMIT)],
        &DQT_SIG,
    ) else {
        return DEFAULT_QUALITY_ESTIMATE;
    };

    if !span_has_range(jpg.len(), dqt_pos, 4) {
        return DEFAULT_QUALITY_ESTIMATE;
    }

    let length = ((jpg[dqt_pos + 2] as usize) << 8) | (jpg[dqt_pos + 3] as usize);
    let end = dqt_pos + 2 + length;
    if end > jpg.len() {
        return DEFAULT_QUALITY_ESTIMATE;
    }

    let mut pos = dqt_pos + 4;
    while pos < end {
        let header = jpg[pos];
        pos += 1;

        let precision = (header >> 4) & 0x0F;
        let table_id = header & 0x0F;
        if precision > 1 {
            break;
        }

        let table_size = if precision == 0 {
            DQT_8BIT_TABLE_SIZE
        } else {
            DQT_16BIT_TABLE_SIZE
        };
        if pos + table_size > end {
            break;
        }

        if table_id == 0 {
            let mut sum = 0i32;
            for i in 0..64usize {
                if precision == 0 {
                    sum += i32::from(jpg[pos + i]);
                } else {
                    let hi = i32::from(jpg[pos + i * 2]);
                    let lo = i32::from(jpg[pos + i * 2 + 1]);
                    sum += (hi << 8) | lo;
                }
            }
            return quality_from_luminance_sum(sum);
        }

        pos += table_size;
    }

    DEFAULT_QUALITY_ESTIMATE
}

fn optimize_image_with_turbojpeg(
    jpg_vec: &mut Vec<u8>,
    is_progressive: bool,
) -> Result<(), String> {
    if jpg_vec.is_empty() {
        return Err("JPG image is empty!".to_string());
    }

    let transformer = TurboJpegHandle::new_transformer()?;
    let transformer_raw = transformer.as_ptr();
    let jpeg_size = libc::c_ulong::try_from(jpg_vec.len())
        .map_err(|_| "Image Error: Input JPEG too large.".to_string())?;

    let mut width = 0i32;
    let mut height = 0i32;
    let mut jpeg_subsamp = 0i32;
    let mut jpeg_colorspace = 0i32;

    // SAFETY: pointers passed reference valid buffers/variables for TurboJPEG output.
    let header_rc = unsafe {
        tjDecompressHeader3(
            transformer_raw,
            jpg_vec.as_ptr(),
            jpeg_size,
            &mut width,
            &mut height,
            &mut jpeg_subsamp,
            &mut jpeg_colorspace,
        )
    };
    if header_rc != 0 {
        return Err(format!(
            "Image Error: {}",
            turbojpeg_error_string(transformer_raw)
        ));
    }

    if width < MIN_COVER_DIMENSION || height < MIN_COVER_DIMENSION {
        return Err(format!(
            "Image Error: Dimensions {}x{} are too small.\nFor platform compatibility, cover image must be at least {}px for both width and height.",
            width, height, MIN_COVER_DIMENSION
        ));
    }

    let xop = exif_orientation(jpg_vec)
        .map(get_transform_op)
        .unwrap_or(TJXOP_NONE);

    let mut xform = TjTransform {
        r: TjRegion {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        },
        op: xop,
        options: TJXOPT_COPYNONE
            | TJXOPT_TRIM
            | if is_progressive {
                TJXOPT_PROGRESSIVE
            } else {
                0
            },
        data: std::ptr::null_mut(),
        custom_filter: None,
    };

    let mut dst_buf: *mut u8 = std::ptr::null_mut();
    let mut dst_size: libc::c_ulong = 0;

    // SAFETY: dst buffer pointers and transform struct are valid for the call lifetime.
    let transform_rc = unsafe {
        tjTransform(
            transformer_raw,
            jpg_vec.as_ptr(),
            jpeg_size,
            1,
            &mut dst_buf,
            &mut dst_size,
            &mut xform,
            0,
        )
    };
    if transform_rc != 0 {
        return Err(format!(
            "tjTransform: {}",
            turbojpeg_error_string(transformer_raw)
        ));
    }
    if dst_buf.is_null() {
        return Err("tjTransform: produced an empty output buffer.".to_string());
    }

    let dst_len = usize::try_from(dst_size)
        .map_err(|_| "Image Error: Transformed JPEG size overflow.".to_string())?;
    let dst_guard = TurboJpegBuffer { raw: dst_buf };

    // SAFETY: dst_guard owns a valid TurboJPEG-allocated buffer of dst_len bytes.
    let result = unsafe { std::slice::from_raw_parts(dst_guard.raw, dst_len) };
    let estimated_quality = estimate_image_quality(result);
    if estimated_quality > MAX_ALLOWED_QUALITY {
        return Err(format!(
            "Image Error: Estimated quality {} exceeds maximum ({}).\nFor platform compatibility, cover image quality must be {} or lower.",
            estimated_quality, MAX_ALLOWED_QUALITY, MAX_ALLOWED_QUALITY
        ));
    }

    jpg_vec.clear();
    jpg_vec.extend_from_slice(result);
    Ok(())
}

pub fn prepare_cover_image_for_conceal(
    image_file_path: &Path,
    source_data_size: usize,
    has_no_option: bool,
    has_bluesky_option: bool,
) -> Result<Vec<u8>, String> {
    let mut jpg_vec = fs::read(image_file_path)
        .map_err(|_| format!("Failed to open file: {}", image_file_path.display()))?;

    let is_progressive = source_data_size < PROGRESSIVE_SOURCE_LIMIT && has_no_option;
    optimize_image_with_turbojpeg(&mut jpg_vec, is_progressive)?;

    let limit = cmp::min(DQT_SEARCH_LIMIT, jpg_vec.len());
    let dqt_pos = search_sig(&jpg_vec[..limit], &DQT1_SIG)
        .or_else(|| search_sig(&jpg_vec[..limit], &DQT2_SIG))
        .ok_or_else(|| {
            "Image File Error: No DQT segment found (corrupt or unsupported JPG).".to_string()
        })?;
    jpg_vec.drain(0..dqt_pos);

    if jpg_vec.len() > MAX_OPTIMIZED_IMAGE_SIZE {
        return Err("Image File Error: Cover image file exceeds maximum size limit.".to_string());
    }

    if has_bluesky_option && jpg_vec.len() > MAX_OPTIMIZED_BLUESKY_IMG {
        return Err(
            "File Size Error: Image file exceeds maximum size limit for the Bluesky platform."
                .to_string(),
        );
    }

    Ok(jpg_vec)
}
