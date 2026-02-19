use crate::binary_io::update_value;
use crate::common::PLATFORM_LIMITS;
use anyhow::Result;
use sodiumoxide::randombytes::randombytes_uniform;

/// Build multi-segment ICC profiles for data that exceeds a single segment.
pub fn build_multi_segment_icc(segment_vec: &mut Vec<u8>, soi_bytes: &[u8]) -> Result<Vec<u8>> {
    const SOI_SIG_LENGTH: usize = 2;
    const SEGMENT_SIG_LENGTH: usize = 2;
    const SEGMENT_HEADER_LENGTH: usize = 16;
    const SEGMENT_DATA_SIZE: usize = 65519;
    const SEGMENTS_TOTAL_VAL_INDEX: usize = 0x2E0;

    let adjusted_size = segment_vec.len() - SEGMENT_HEADER_LENGTH;
    let remainder_data = adjusted_size % SEGMENT_DATA_SIZE;
    let header_overhead = SOI_SIG_LENGTH + SEGMENT_SIG_LENGTH;
    let segment_remainder_size = if remainder_data > header_overhead {
        remainder_data - header_overhead
    } else {
        0
    };
    let total_segments = adjusted_size / SEGMENT_DATA_SIZE;
    let segments_required = total_segments + if segment_remainder_size > 0 { 1 } else { 0 };

    update_value(segment_vec, SEGMENTS_TOTAL_VAL_INDEX, segments_required, 2)?;

    // Remove the SOI + segment sig + header from the front.
    let remove_count = SOI_SIG_LENGTH + SEGMENT_SIG_LENGTH + SEGMENT_HEADER_LENGTH;
    segment_vec.drain(..remove_count);

    let mut result =
        Vec::with_capacity(adjusted_size + segments_required * (SEGMENT_SIG_LENGTH + SEGMENT_HEADER_LENGTH));

    #[rustfmt::skip]
    let icc_header_template: [u8; 18] = [
        0xFF, 0xE2, 0x00, 0x00,
        b'I', b'C', b'C', b'_', b'P', b'R', b'O', b'F', b'I', b'L', b'E',
        0x00, 0x00, 0x01,
    ];

    let default_segment_length = (SEGMENT_DATA_SIZE + SEGMENT_HEADER_LENGTH) as u16;
    let last_segment_length = (segment_remainder_size + SEGMENT_HEADER_LENGTH) as u16;

    let mut offset = 0;
    for seg in 1..=segments_required {
        let is_last = seg == segments_required;
        let data_size = if is_last {
            segment_vec.len() - offset
        } else {
            SEGMENT_DATA_SIZE
        };
        let seg_length = if is_last {
            last_segment_length
        } else {
            default_segment_length
        };

        let mut header = icc_header_template;
        header[2] = (seg_length >> 8) as u8;
        header[3] = (seg_length & 0xFF) as u8;
        // Use 2-byte big-endian sequence number for >255 segment support.
        header[15] = (seg >> 8) as u8;
        header[16] = (seg & 0xFF) as u8;

        result.extend_from_slice(&header);
        result.extend_from_slice(&segment_vec[offset..offset + data_size]);
        offset += data_size;
    }

    // Free segment_vec memory — it's been consumed.
    segment_vec.clear();
    segment_vec.shrink_to_fit();

    // Restore SOI at the front.
    let mut final_result = Vec::with_capacity(SOI_SIG_LENGTH + result.len());
    final_result.extend_from_slice(&soi_bytes[..SOI_SIG_LENGTH]);
    final_result.extend(result);
    Ok(final_result)
}

/// Build a single-segment ICC profile (data fits within one segment).
pub fn build_single_segment_icc(segment_vec: &mut Vec<u8>) -> Result<Vec<u8>> {
    const SOI_SIG_LENGTH: usize = 2;
    const SEGMENT_SIG_LENGTH: usize = 2;
    const SEGMENT_HEADER_SIZE_INDEX: usize = 0x04;
    const PROFILE_SIZE_INDEX: usize = 0x16;
    const PROFILE_SIZE_DIFF: usize = 16;

    let segment_size = segment_vec.len() - (SOI_SIG_LENGTH + SEGMENT_SIG_LENGTH);
    let profile_size = segment_size - PROFILE_SIZE_DIFF;

    update_value(segment_vec, SEGMENT_HEADER_SIZE_INDEX, segment_size, 2)?;
    update_value(segment_vec, PROFILE_SIZE_INDEX, profile_size, 4)?;

    Ok(std::mem::take(segment_vec))
}

/// Apply Reddit-specific padding bytes to protect against download truncation.
pub fn apply_reddit_padding(
    jpg_vec: &mut Vec<u8>,
    data_vec: &mut Vec<u8>,
    soi_bytes: &[u8],
) -> Result<()> {
    const SOI_SIG_LENGTH: usize = 2;
    const EOI_SIG_LENGTH: usize = 2;
    const PADDING_SIZE: usize = 8000;
    const PADDING_START: u8 = 33;
    const PADDING_RANGE: u32 = 94;

    // Insert SOI at start of jpg_vec.
    let soi = &soi_bytes[..SOI_SIG_LENGTH];
    jpg_vec.splice(0..0, soi.iter().copied());

    // Build padding segment.
    let mut padding_vec: Vec<u8> = vec![0xFF, 0xE2, 0x1F, 0x42];
    padding_vec.reserve(PADDING_SIZE);
    for _ in 0..PADDING_SIZE {
        padding_vec.push(PADDING_START + randombytes_uniform(PADDING_RANGE) as u8);
    }

    // Insert padding before EOI.
    let insert_pos = jpg_vec.len() - EOI_SIG_LENGTH;
    jpg_vec.reserve(padding_vec.len() + data_vec.len());
    jpg_vec.splice(
        insert_pos..insert_pos,
        padding_vec.into_iter(),
    );

    // Insert data (skipping SOI) before EOI.
    let insert_pos = jpg_vec.len() - EOI_SIG_LENGTH;
    jpg_vec.splice(
        insert_pos..insert_pos,
        data_vec[SOI_SIG_LENGTH..].iter().copied(),
    );

    Ok(())
}

/// Segment the data file into ICC profiles and assemble the output.
pub fn segment_data_file(
    segment_vec: &mut Vec<u8>,
    data_vec: &mut Vec<u8>,
    jpg_vec: &mut Vec<u8>,
    platforms_vec: &mut Vec<String>,
    has_reddit_option: bool,
) -> Result<()> {
    const SOI_SIG_LENGTH: usize = 2;
    const SEGMENT_SIG_LENGTH: usize = 2;
    const SEGMENT_HEADER_LENGTH: usize = 16;
    const SEGMENT_DATA_SIZE: usize = 65519;
    const PROFILE_DATA_SIZE: usize = 851;
    const DEFLATED_DATA_FILE_SIZE_INDEX: usize = 0x2E2;
    const VALUE_BYTE_LENGTH: usize = 4;

    let max_first_segment_size =
        SEGMENT_DATA_SIZE + SOI_SIG_LENGTH + SEGMENT_SIG_LENGTH + SEGMENT_HEADER_LENGTH;

    // Preserve SOI bytes before any changes.
    let soi_bytes: Vec<u8> = segment_vec[..SOI_SIG_LENGTH].to_vec();

    if segment_vec.len() > max_first_segment_size {
        *data_vec = build_multi_segment_icc(segment_vec, &soi_bytes)?;
    } else {
        *data_vec = build_single_segment_icc(segment_vec)?;
    }

    let deflated_size = data_vec.len() - PROFILE_DATA_SIZE;
    update_value(
        data_vec,
        DEFLATED_DATA_FILE_SIZE_INDEX,
        deflated_size,
        VALUE_BYTE_LENGTH,
    )?;

    if has_reddit_option {
        apply_reddit_padding(jpg_vec, data_vec, &soi_bytes)?;

        // Keep only the Reddit compatibility report entry.
        let reddit_entry = platforms_vec[5].clone();
        platforms_vec.clear();
        platforms_vec.push(reddit_entry);
    } else {
        *segment_vec = std::mem::take(data_vec);

        // Remove Bluesky and Reddit from the compatibility report.
        if platforms_vec.len() > 5 {
            platforms_vec.remove(5);
        }
        if platforms_vec.len() > 2 {
            platforms_vec.remove(2);
        }

        // Small files: merge now. Large files: leave separate for split write.
        const SIZE_THRESHOLD: usize = 20 * 1024 * 1024;
        if segment_vec.len() < SIZE_THRESHOLD {
            segment_vec.reserve(jpg_vec.len());
            segment_vec.extend_from_slice(jpg_vec);
            *jpg_vec = std::mem::take(segment_vec);
        }
    }

    data_vec.clear();
    data_vec.shrink_to_fit();
    Ok(())
}

/// Filter platforms based on image size, first segment size, and total segments.
pub fn filter_platforms(
    platforms_vec: &mut Vec<String>,
    embedded_size: usize,
    first_segment_size: u16,
    total_segments: u16,
) {
    platforms_vec.retain(|platform| {
        for pl in PLATFORM_LIMITS {
            if platform == pl.name {
                return embedded_size <= pl.max_image_size
                    && (first_segment_size as usize) <= pl.max_first_segment
                    && total_segments <= pl.max_segments;
            }
        }
        true
    });

    if platforms_vec.is_empty() {
        platforms_vec.push(
            "\x08\x08Unknown!\n\n Due to the large file size of the output JPG image, \
             I'm unaware of any\n compatible platforms that this image can be \
             posted on. Local use only?"
                .to_string(),
        );
    }
}
