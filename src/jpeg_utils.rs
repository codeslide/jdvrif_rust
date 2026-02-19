use crate::binary_io::search_sig;
use anyhow::{bail, Result};

/// Parse EXIF orientation tag from JPEG data.
pub fn exif_orientation(jpg: &[u8]) -> Option<u16> {
    const EXIF_SEARCH_LIMIT: usize = 4096;
    const APP1_SIG: [u8; 2] = [0xFF, 0xE1];

    let pos = search_sig(jpg, &APP1_SIG, EXIF_SEARCH_LIMIT)?;
    if pos + 4 > jpg.len() {
        return None;
    }

    let segment_length = u16::from_be_bytes([jpg[pos + 2], jpg[pos + 3]]) as usize;
    let exif_end = pos + 2 + segment_length;
    if exif_end > jpg.len() {
        return None;
    }

    let payload = &jpg[pos + 4..pos + 2 + segment_length];
    const EXIF_SIG: [u8; 6] = [b'E', b'x', b'i', b'f', 0, 0];
    if payload.len() < 6 || payload[..6] != EXIF_SIG {
        return None;
    }

    let tiff = &payload[6..];
    if tiff.len() < 8 {
        return None;
    }

    let is_le = if tiff[0] == b'I' && tiff[1] == b'I' {
        true
    } else if tiff[0] == b'M' && tiff[1] == b'M' {
        false
    } else {
        return None;
    };

    let read16 = |offset: usize| -> Option<u16> {
        if offset + 2 > tiff.len() {
            return None;
        }
        let val = u16::from_be_bytes([tiff[offset], tiff[offset + 1]]);
        Some(if is_le { val.swap_bytes() } else { val })
    };

    let read32 = |offset: usize| -> Option<u32> {
        if offset + 4 > tiff.len() {
            return None;
        }
        let val = u32::from_be_bytes([
            tiff[offset],
            tiff[offset + 1],
            tiff[offset + 2],
            tiff[offset + 3],
        ]);
        Some(if is_le { val.swap_bytes() } else { val })
    };

    let magic = read16(2)?;
    if magic != 0x002A {
        return None;
    }

    let ifd_offset = read32(4)? as usize;
    if ifd_offset < 8 || ifd_offset >= tiff.len() {
        return None;
    }

    let entry_count = read16(ifd_offset)?;
    const TAG_ORIENTATION: u16 = 0x0112;
    const ENTRY_SIZE: usize = 12;

    let mut entry_pos = ifd_offset + 2;
    for _ in 0..entry_count {
        if entry_pos + ENTRY_SIZE > tiff.len() {
            return None;
        }
        let tag_id = read16(entry_pos)?;
        if tag_id == TAG_ORIENTATION {
            return read16(entry_pos + 8);
        }
        entry_pos += ENTRY_SIZE;
    }
    None
}

/// Map EXIF orientation to turbojpeg TransformOp.
pub fn get_transform_op(orientation: u16) -> turbojpeg::TransformOp {
    match orientation {
        2 => turbojpeg::TransformOp::Hflip,
        3 => turbojpeg::TransformOp::Rot180,
        4 => turbojpeg::TransformOp::Vflip,
        5 => turbojpeg::TransformOp::Transpose,
        6 => turbojpeg::TransformOp::Rot90,
        7 => turbojpeg::TransformOp::Transverse,
        8 => turbojpeg::TransformOp::Rot270,
        _ => turbojpeg::TransformOp::None,
    }
}

/// Estimate JPEG quality from DQT tables.
pub fn estimate_image_quality(jpg: &[u8]) -> i32 {
    const DEFAULT_QUALITY_ESTIMATE: i32 = 80;

    #[rustfmt::skip]
    const STD_LUMINANCE_SUMS: [i32; 101] = [
        0,
        16320, 16315, 15946, 15277, 14655, 14073, 13623, 13230, 12859, 12560,
        12240, 11861, 11456, 11081, 10714, 10360, 10027, 9679,  9368,  9056,
        8680,  8331,  7995,  7668,  7376,  7084,  6823,  6562,  6345,  6125,
        5939,  5756,  5571,  5421,  5240,  5086,  4976,  4829,  4719,  4616,
        4463,  4393,  4280,  4166,  4092,  3980,  3909,  3835,  3755,  3688,
        3621,  3541,  3467,  3396,  3323,  3247,  3170,  3096,  3021,  2952,
        2874,  2804,  2727,  2657,  2583,  2509,  2437,  2362,  2290,  2211,
        2136,  2068,  1996,  1915,  1858,  1773,  1692,  1620,  1552,  1477,
        1398,  1326,  1251,  1179,  1109,  1031,  961,   884,   814,   736,
        667,   592,   518,   441,   369,   292,   221,   151,   86,    64,
    ];

    const DQT_SIG: [u8; 2] = [0xFF, 0xDB];
    const DQT_SEARCH_LIMIT: usize = 32768;

    let Some(dqt_pos) = search_sig(jpg, &DQT_SIG, DQT_SEARCH_LIMIT) else {
        return DEFAULT_QUALITY_ESTIMATE;
    };

    if dqt_pos + 4 > jpg.len() {
        return DEFAULT_QUALITY_ESTIMATE;
    }

    let length = ((jpg[dqt_pos + 2] as usize) << 8) | jpg[dqt_pos + 3] as usize;
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
        let table_size: usize = if precision == 0 { 64 } else { 128 };

        if pos + table_size > end {
            break;
        }

        if table_id == 0 {
            let mut sum: i32 = 0;
            for i in 0..64 {
                sum += if precision == 0 {
                    jpg[pos + i] as i32
                } else {
                    ((jpg[pos + i * 2] as i32) << 8) | jpg[pos + i * 2 + 1] as i32
                };
            }

            if sum <= 64 {
                return 100;
            }
            if sum >= 16320 {
                return 1;
            }

            for q in 1..=100 {
                if sum >= STD_LUMINANCE_SUMS[q as usize] {
                    if q > 1 {
                        let diff_current = sum - STD_LUMINANCE_SUMS[q as usize];
                        let diff_prev = STD_LUMINANCE_SUMS[(q - 1) as usize] - sum;
                        if diff_prev < diff_current {
                            return q - 1;
                        }
                    }
                    return q;
                }
            }
            return 100;
        }
        pos += table_size;
    }
    DEFAULT_QUALITY_ESTIMATE
}

/// Optimize a JPEG image: apply EXIF orientation, strip metadata, optionally make progressive.
pub fn optimize_image(jpg_vec: &mut Vec<u8>, is_progressive: bool) -> Result<()> {
    if jpg_vec.is_empty() {
        bail!("JPG image is empty!");
    }

    let header = turbojpeg::read_header(jpg_vec.as_slice())
        .map_err(|e| anyhow::anyhow!("Image Error: {}", e))?;

    const MIN_DIMENSION: usize = 400;
    if header.width < MIN_DIMENSION || header.height < MIN_DIMENSION {
        bail!(
            "Image Error: Dimensions {}x{} are too small.\n\
             For platform compatibility, cover image must be \
             at least {}px for both width and height.",
            header.width,
            header.height,
            MIN_DIMENSION
        );
    }

    let op = match exif_orientation(jpg_vec) {
        Some(ori) => get_transform_op(ori),
        None => turbojpeg::TransformOp::None,
    };

    let mut xform = turbojpeg::Transform::op(op);
    xform.trim = true;
    xform.copy_none = true;
    xform.progressive = is_progressive;

    let output = turbojpeg::transform(&xform, jpg_vec.as_slice())
        .map_err(|e| anyhow::anyhow!("tjTransform: {}", e))?;

    const MAX_ALLOWED_QUALITY: i32 = 97;
    let estimated_quality = estimate_image_quality(&output);

    if estimated_quality > MAX_ALLOWED_QUALITY {
        bail!(
            "Image Error: Estimated quality {} exceeds maximum ({}).\n\
             For platform compatibility, cover image quality \
             must be {} or lower.",
            estimated_quality,
            MAX_ALLOWED_QUALITY,
            MAX_ALLOWED_QUALITY
        );
    }

    *jpg_vec = output.to_vec();
    Ok(())
}
