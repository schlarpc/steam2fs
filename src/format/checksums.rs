//! The per-version checksum / file-id table (blob key 4).
//!
//! ```text
//! header (0x20 bytes, 8 x u32):
//!   magic 0x34457234, version (0|1), num_fileblocks, num_items,
//!   offset1 (=0x20), offset2 (=0x20 + 0x10*num_fileblocks), blocksize (0x8000),
//!   largest_num_blocks
//! fileblock table (0x10 bytes each): fileid_start, filecount, offset, unused
//! per file (in fileblock order):
//!   v0: u32 size, u32 offset, u32 mode<<24 | num_blocks
//!   v1: u64 size, u64 offset, u32 mode<<24 | num_blocks
//!   then num_blocks x (u32 compressed_size, u32 checksum)
//! footer: u32 magic
//! ```
//!
//! Every file listed here is stored, whole, in this version's dat at
//! `offset`, as consecutive blocks of `BLOCK_SIZE` decompressed bytes.

use super::{malformed, u32_at, u64_at, Result, BLOCK_SIZE};

pub const MAGIC: u32 = 0x3445_7234;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Plain = 0,
    Compressed = 1,
    CompressedEncrypted = 2,
    Encrypted = 3,
}

impl Mode {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Plain),
            1 => Some(Self::Compressed),
            2 => Some(Self::CompressedEncrypted),
            3 => Some(Self::Encrypted),
            _ => None,
        }
    }
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::CompressedEncrypted | Self::Encrypted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub compressed_size: u32,
    pub checksum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    pub file_id: u32,
    pub mode: Mode,
    /// Byte offset of the first block in the dat.
    pub offset: u64,
    /// Decompressed size.
    pub size: u64,
    pub blocks: Vec<Block>,
}

impl FileRecord {
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Decompressed byte range covered by block `i`.
    pub fn block_range(&self, i: usize) -> (u64, u64) {
        let start = i as u64 * BLOCK_SIZE;
        (start, (start + BLOCK_SIZE).min(self.size))
    }
}

pub fn parse(t: &[u8]) -> Result<Vec<FileRecord>> {
    let h = |i: usize| u32_at(t, i * 4);
    if h(0)? != MAGIC {
        return Err(malformed("checksum table: bad magic"));
    }
    let version = h(1)?;
    let num_fileblocks = h(2)? as usize;
    let num_items = h(3)? as usize;
    let offset1 = h(4)? as usize;
    let offset2 = h(5)? as usize;
    let blocksize = h(6)?;
    let largest_num_blocks = h(7)?;
    if version > 1 {
        return Err(malformed(format!(
            "checksum table: unknown version {version}"
        )));
    }
    if u64::from(blocksize) != BLOCK_SIZE {
        return Err(malformed(format!(
            "checksum table: block size {blocksize:#x}"
        )));
    }
    if offset1 != 0x20 || offset2 != 0x20 + 0x10 * num_fileblocks {
        return Err(malformed("checksum table: unexpected table offsets"));
    }

    let mut pos = offset2;
    let mut out = Vec::with_capacity(num_items);
    let mut max_blocks = 0u32;
    for fb in 0..num_fileblocks {
        let base = 0x20 + fb * 0x10;
        let fileid_start = u32_at(t, base)?;
        let filecount = u32_at(t, base + 4)?;
        let offset = u32_at(t, base + 8)? as usize;
        if pos != offset {
            return Err(malformed(format!(
                "checksum table: fileblock {fb} offset {offset:#x} != cursor {pos:#x}"
            )));
        }
        for k in 0..filecount {
            let file_id = fileid_start
                .checked_add(k)
                .ok_or_else(|| malformed("checksum table: file id overflow"))?;
            let (size, offset, packed) = if version == 0 {
                let r = (
                    u64::from(u32_at(t, pos)?),
                    u64::from(u32_at(t, pos + 4)?),
                    u32_at(t, pos + 8)?,
                );
                pos += 12;
                r
            } else {
                let r = (u64_at(t, pos)?, u64_at(t, pos + 8)?, u32_at(t, pos + 16)?);
                pos += 20;
                r
            };
            let mode = Mode::from_u32(packed >> 24).ok_or_else(|| {
                malformed(format!(
                    "checksum table: file {file_id} mode {}",
                    packed >> 24
                ))
            })?;
            let num_blocks = packed & 0x00ff_ffff;
            max_blocks = max_blocks.max(num_blocks);
            let mut blocks = Vec::with_capacity(num_blocks as usize);
            for _ in 0..num_blocks {
                blocks.push(Block {
                    compressed_size: u32_at(t, pos)?,
                    checksum: u32_at(t, pos + 4)?,
                });
                pos += 8;
            }
            out.push(FileRecord {
                file_id,
                mode,
                offset,
                size,
                blocks,
            });
        }
    }
    if u32_at(t, pos)? != MAGIC {
        return Err(malformed("checksum table: bad footer magic"));
    }
    if out.len() != num_items {
        return Err(malformed(format!(
            "checksum table: {} files but header says {num_items}",
            out.len()
        )));
    }
    if max_blocks != largest_num_blocks {
        return Err(malformed("checksum table: largest block count mismatch"));
    }
    Ok(out)
}
