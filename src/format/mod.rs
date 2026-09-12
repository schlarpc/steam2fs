//! On-disk formats of the Steam2 content server dump: blobs, manifests,
//! checksum tables and dat chunks.

pub mod blob;
pub mod checksums;
pub mod chunk;
pub mod manifest;

/// Decompressed size of every dat block except a file's last one.
pub const BLOCK_SIZE: u64 = 0x8000;

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("{0}")]
    Malformed(String),
    #[error("zlib: {0}")]
    Zlib(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, FormatError>;

pub(crate) fn malformed(msg: impl Into<String>) -> FormatError {
    FormatError::Malformed(msg.into())
}

pub(crate) fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| malformed(format!("truncated u16 at {off}")))
}

pub(crate) fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| malformed(format!("truncated u32 at {off}")))
}

pub(crate) fn u64_at(b: &[u8], off: usize) -> Result<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| malformed(format!("truncated u64 at {off}")))
}
