use std::path::Path;

use super::*;

struct FilenamePrefixExtractor {
    has_length: bool,
    expected_len: usize,
    filename: Vec<u8>,
}

impl FilenamePrefixExtractor {
    fn new() -> Self {
        Self {
            has_length: false,
            expected_len: 0,
            filename: Vec::new(),
        }
    }

    fn consume<F>(&mut self, chunk: &[u8], mut payload_consume: F) -> Result<(), String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        let mut pos = 0usize;

        if !self.has_length {
            if chunk.is_empty() {
                return Ok(());
            }
            self.expected_len = chunk[pos] as usize;
            pos += 1;
            self.has_length = true;

            if self.expected_len == 0 {
                return Err(CORRUPT_FILE_ERROR.to_string());
            }
            self.filename.reserve(self.expected_len);
        }

        if self.filename.len() < self.expected_len {
            let need = self.expected_len - self.filename.len();
            let take = cmp::min(need, chunk.len().saturating_sub(pos));
            if take > 0 {
                self.filename.extend_from_slice(&chunk[pos..pos + take]);
                pos += take;
            }
        }

        if pos < chunk.len() {
            payload_consume(&chunk[pos..])?;
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.has_length && self.filename.len() == self.expected_len
    }

    fn into_filename(self) -> Result<String, String> {
        if !self.is_complete() {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }
        String::from_utf8(self.filename).map_err(|_| CORRUPT_FILE_ERROR.to_string())
    }
}

fn decrypt_with_secretstream_file_input_chunks<F>(
    encrypted_input_path: &Path,
    key: &secretstream::Key,
    header: &secretstream::Header,
    mut consume: F,
) -> Result<bool, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    const MAX_SECRETSTREAM_FRAME_BYTES: usize = STREAM_CHUNK_SIZE + secretstream::ABYTES;

    let mut input = open_binary_input_or_throw(
        encrypted_input_path,
        "Read Error: Failed to open encrypted stream input.",
    )?;

    let encrypted_input_size = checked_file_size(
        encrypted_input_path,
        "Read Error: Invalid encrypted stream input size.",
        true,
    )?;

    let mut stream = match secretstream::Stream::init_pull(header, key) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    let mut left = encrypted_input_size;
    let mut has_final_tag = false;
    let mut cipher_chunk = vec![0u8; MAX_SECRETSTREAM_FRAME_BYTES];

    while left > 0 {
        if left < STREAM_FRAME_LEN_BYTES {
            return Ok(false);
        }

        let mut len_buf = [0u8; STREAM_FRAME_LEN_BYTES];
        if input.read_exact(&mut len_buf).is_err() {
            return Ok(false);
        }
        left -= STREAM_FRAME_LEN_BYTES;

        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len < secretstream::ABYTES
            || frame_len > left
            || frame_len > MAX_SECRETSTREAM_FRAME_BYTES
        {
            return Ok(false);
        }

        if input.read_exact(&mut cipher_chunk[..frame_len]).is_err() {
            return Ok(false);
        }
        left -= frame_len;

        let (plain_chunk, tag) = match stream.pull(&cipher_chunk[..frame_len], None) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        if !plain_chunk.is_empty() {
            consume(&plain_chunk)?;
        }

        if tag == secretstream::Tag::Final {
            has_final_tag = true;
            break;
        }
    }

    if !has_final_tag {
        return Ok(false);
    }

    let mut extra = [0u8; 1];
    let trailing = input
        .read(&mut extra)
        .map_err(|_| "Read Error: Failed while decrypting encrypted payload stream.".to_string())?;

    Ok(trailing == 0)
}

struct SecretstreamFrameParser {
    stream: secretstream::Stream<secretstream::Pull>,
    pending: Vec<u8>,
    pending_start: usize,
    has_final_tag: bool,
}

impl SecretstreamFrameParser {
    const MAX_SECRETSTREAM_FRAME_BYTES: usize = STREAM_CHUNK_SIZE + secretstream::ABYTES;

    fn new(key: &secretstream::Key, header: &secretstream::Header) -> Option<Self> {
        let stream = secretstream::Stream::init_pull(header, key).ok()?;
        Some(Self {
            stream,
            pending: Vec::with_capacity(STREAM_CHUNK_SIZE + STREAM_FRAME_LEN_BYTES),
            pending_start: 0,
            has_final_tag: false,
        })
    }

    fn available(&self) -> usize {
        self.pending.len().saturating_sub(self.pending_start)
    }

    fn compact_pending(&mut self) {
        if self.pending_start > 0 && self.pending_start * 2 >= self.pending.len() {
            self.pending.copy_within(self.pending_start.., 0);
            self.pending.truncate(self.available());
            self.pending_start = 0;
        }
    }

    fn push<F>(&mut self, bytes: &[u8], mut consume_plain: F) -> Result<bool, String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        if !bytes.is_empty() {
            self.pending.extend_from_slice(bytes);
        }

        loop {
            if self.has_final_tag {
                return Ok(self.available() == 0);
            }

            if self.available() < STREAM_FRAME_LEN_BYTES {
                break;
            }

            let idx = self.pending_start;
            let frame_len = u32::from_be_bytes([
                self.pending[idx],
                self.pending[idx + 1],
                self.pending[idx + 2],
                self.pending[idx + 3],
            ]) as usize;

            if !(secretstream::ABYTES..=Self::MAX_SECRETSTREAM_FRAME_BYTES).contains(&frame_len) {
                return Ok(false);
            }

            let needed = STREAM_FRAME_LEN_BYTES + frame_len;
            if self.available() < needed {
                break;
            }

            let frame_start = idx + STREAM_FRAME_LEN_BYTES;
            let frame_end = frame_start + frame_len;
            let (plain_chunk, tag) = match self
                .stream
                .pull(&self.pending[frame_start..frame_end], None)
            {
                Ok(v) => v,
                Err(_) => return Ok(false),
            };

            if !plain_chunk.is_empty() {
                consume_plain(&plain_chunk)?;
            }

            self.pending_start += needed;
            self.compact_pending();

            if tag == secretstream::Tag::Final {
                self.has_final_tag = true;
                if self.available() != 0 {
                    return Ok(false);
                }
                break;
            }
        }

        Ok(true)
    }

    fn finish(self) -> bool {
        self.has_final_tag && self.available() == 0
    }
}

pub(super) struct StageDecryptOutput {
    pub(super) decrypted_filename: String,
    pub(super) output_size: usize,
}

pub(super) fn decrypt_secretstream_ciphertext_chunks_to_stage_file<F>(
    stream_stage_path: &Path,
    key: &secretstream::Key,
    header: &secretstream::Header,
    is_data_compressed: bool,
    mut feed_chunks: F,
) -> Result<Option<StageDecryptOutput>, String>
where
    F: FnMut(&mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<usize, String>,
{
    const STREAM_AUTH_FAIL_SENTINEL: &str = "__JDVRIF_STREAM_AUTH_FAIL__";

    let mut parser = match SecretstreamFrameParser::new(key, header) {
        Some(v) => v,
        None => return Ok(None),
    };
    let mut prefix_extractor = FilenamePrefixExtractor::new();

    if is_data_compressed {
        let output_file = open_binary_output_for_write_or_throw(stream_stage_path)?;
        let writer = BufWriter::new(output_file);
        let mut decoder = ZlibDecoder::new(writer);

        {
            let mut sink = |chunk: &[u8]| -> Result<(), String> {
                let ok = parser.push(chunk, |plain_chunk| {
                    prefix_extractor.consume(plain_chunk, |payload_chunk| {
                        decoder
                            .write_all(payload_chunk)
                            .map_err(|_| "zlib inflate error: inflate failed".to_string())
                    })
                })?;
                if ok {
                    Ok(())
                } else {
                    Err(STREAM_AUTH_FAIL_SENTINEL.to_string())
                }
            };

            match feed_chunks(&mut sink) {
                Ok(_) => {}
                Err(e) if e == STREAM_AUTH_FAIL_SENTINEL => return Ok(None),
                Err(e) => return Err(e),
            }
        }

        if !parser.finish() || !prefix_extractor.is_complete() {
            return Ok(None);
        }

        let mut writer = decoder
            .finish()
            .map_err(|_| "zlib inflate error: inflate failed".to_string())?;
        writer
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

        let output_size = checked_file_size(
            stream_stage_path,
            "Zlib Compression Error: Output file is empty. Inflating file failed.",
            true,
        )?;
        if output_size > STREAM_INFLATE_MAX_OUTPUT {
            return Err("zlib inflate error: output exceeds safe size limit".to_string());
        }

        return Ok(Some(StageDecryptOutput {
            decrypted_filename: prefix_extractor.into_filename()?,
            output_size,
        }));
    }

    let output_file = open_binary_output_for_write_or_throw(stream_stage_path)?;
    let mut output = BufWriter::new(output_file);
    let mut output_size = 0usize;

    {
        let mut sink = |chunk: &[u8]| -> Result<(), String> {
            let ok = parser.push(chunk, |plain_chunk| {
                prefix_extractor.consume(plain_chunk, |payload_chunk| {
                    output
                        .write_all(payload_chunk)
                        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
                    output_size =
                        output_size
                            .checked_add(payload_chunk.len())
                            .ok_or_else(|| {
                                "File Size Error: Decrypted output size overflow.".to_string()
                            })?;
                    Ok(())
                })
            })?;
            if ok {
                Ok(())
            } else {
                Err(STREAM_AUTH_FAIL_SENTINEL.to_string())
            }
        };

        match feed_chunks(&mut sink) {
            Ok(_) => {}
            Err(e) if e == STREAM_AUTH_FAIL_SENTINEL => return Ok(None),
            Err(e) => return Err(e),
        }
    }

    if !parser.finish() || !prefix_extractor.is_complete() {
        return Ok(None);
    }

    output
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

    if output_size == 0 {
        return Err("File Extraction Error: Output file is empty.".to_string());
    }

    Ok(Some(StageDecryptOutput {
        decrypted_filename: prefix_extractor.into_filename()?,
        output_size,
    }))
}

pub(super) fn decrypt_ciphertext_to_stage_file(
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
    key: &secretstream::Key,
    header: &secretstream::Header,
    is_data_compressed: bool,
) -> Result<Option<StageDecryptOutput>, String> {
    let mut prefix_extractor = FilenamePrefixExtractor::new();

    if is_data_compressed {
        let output_file = open_binary_output_for_write_or_throw(stream_stage_path)?;
        let writer = BufWriter::new(output_file);
        let mut decoder = ZlibDecoder::new(writer);

        let ok =
            decrypt_with_secretstream_file_input_chunks(cipher_stage_path, key, header, |chunk| {
                prefix_extractor.consume(chunk, |payload_chunk| {
                    decoder
                        .write_all(payload_chunk)
                        .map_err(|_| "zlib inflate error: inflate failed".to_string())
                })
            })?;

        if !ok || !prefix_extractor.is_complete() {
            return Ok(None);
        }

        let mut writer = decoder
            .finish()
            .map_err(|_| "zlib inflate error: inflate failed".to_string())?;
        writer
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

        let output_size = checked_file_size(
            stream_stage_path,
            "Zlib Compression Error: Output file is empty. Inflating file failed.",
            true,
        )?;
        if output_size > STREAM_INFLATE_MAX_OUTPUT {
            return Err("zlib inflate error: output exceeds safe size limit".to_string());
        }

        return Ok(Some(StageDecryptOutput {
            decrypted_filename: prefix_extractor.into_filename()?,
            output_size,
        }));
    }

    let output_file = open_binary_output_for_write_or_throw(stream_stage_path)?;
    let mut output = BufWriter::new(output_file);
    let mut output_size = 0usize;

    let ok =
        decrypt_with_secretstream_file_input_chunks(cipher_stage_path, key, header, |chunk| {
            prefix_extractor.consume(chunk, |payload_chunk| {
                output
                    .write_all(payload_chunk)
                    .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
                output_size = output_size
                    .checked_add(payload_chunk.len())
                    .ok_or_else(|| {
                        "File Size Error: Decrypted output size overflow.".to_string()
                    })?;
                Ok(())
            })
        })?;

    if !ok || !prefix_extractor.is_complete() {
        return Ok(None);
    }

    output
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

    if output_size == 0 {
        return Err("File Extraction Error: Output file is empty.".to_string());
    }

    Ok(Some(StageDecryptOutput {
        decrypted_filename: prefix_extractor.into_filename()?,
        output_size,
    }))
}
