//! Steam2 "blob" key/value container.
//!
//! Layout of an uncompressed blob (magic `0x5001`):
//!
//! ```text
//! u16 magic = 0x5001
//! u32 total_size      // including this 10-byte header
//! u32 slack_size      // padding after the entries
//! repeated: u16 key_len, u32 value_len, key bytes, value bytes
//! ```
//!
//! A compressed blob (magic `0x4301`) wraps a zlib stream:
//!
//! ```text
//! u16 magic = 0x4301
//! u64 packed_size
//! u64 unpacked_size
//! u16 compression_level
//! zlib data
//! ```
//!
//! Keys in the content-server blobs are little-endian `u32`s stored as raw
//! bytes; nested values are themselves blobs.

// Sizes and offsets in this format are 32-bit on disk; the casts below are bounded by it.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::io::Read;

use super::{malformed, u16_at, u32_at, u64_at, Result};

pub const MAGIC_PLAIN: u16 = 0x5001;
pub const MAGIC_COMPRESSED: u16 = 0x4301;

/// Well-known top-level keys of a `<depot>_<version>_<crc>_<sha>.blob` file.
#[allow(dead_code)] // documented for completeness; not all are read
pub mod keys {
    /// u32 format code: 3 (u32 dat size) or 4 (u64 dat size).
    pub const FORMAT: u32 = 0;
    /// NUL-terminated version string.
    pub const VERSION_STRING: u32 = 1;
    /// u32, equals the manifest header's fingerprint.
    pub const MANIFEST_FINGERPRINT: u32 = 2;
    /// Compressed blob whose key 0 holds the binary manifest.
    pub const MANIFEST: u32 = 3;
    /// Raw checksum / file-id table.
    pub const CHECKSUMS: u32 = 4;
    /// Nested blob: key N -> file ids to fetch when updating from version N
    /// (a changed file gets a new file id, so this is "ids newer than N").
    pub const ADDED_SINCE: u32 = 5;
    /// Nested blob: key N -> file ids present in version N that are gone now.
    pub const REMOVED_SINCE: u32 = 6;
    /// u32 CRC of the paired dat file (third filename component).
    pub const DAT_CRC: u32 = 7;
    /// 128-byte signature.
    pub const SIGNATURE: u32 = 9;
    /// u32 crc32 of this whole blob file with this value zeroed (third
    /// filename component).
    pub const OWN_CRC: u32 = 10;
    /// u32 previous version number, 0xffffffff for a root.
    pub const PREV_VERSION: u32 = 11;
    /// u32 CRC of the previous blob, 0 for a root.
    pub const PREV_CRC: u32 = 12;
    /// dat size: u32 when FORMAT == 3, u64 when FORMAT == 4.
    pub const DAT_SIZE: u32 = 13;
}

/// A parsed view over a plain blob's entries.
#[derive(Debug, Clone)]
pub struct Blob<'a> {
    entries: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> Blob<'a> {
    /// Parse a plain (`0x5001`) blob.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let magic = u16_at(data, 0)?;
        if magic != MAGIC_PLAIN {
            return Err(malformed(format!("bad blob magic {magic:#06x}")));
        }
        let total = u32_at(data, 2)? as usize;
        if total > data.len() {
            return Err(malformed(format!(
                "blob total_size {total} exceeds buffer {}",
                data.len()
            )));
        }
        let mut pos = 10;
        let mut entries = Vec::new();
        while pos < total {
            let klen = u16_at(data, pos)? as usize;
            let vlen = u32_at(data, pos + 2)? as usize;
            pos += 6;
            let key = data
                .get(pos..pos + klen)
                .ok_or_else(|| malformed("blob key truncated"))?;
            let value = data
                .get(pos + klen..pos + klen + vlen)
                .ok_or_else(|| malformed("blob value truncated"))?;
            entries.push((key, value));
            pos += klen + vlen;
        }
        Ok(Self { entries })
    }

    /// Parse either a plain blob or a compressed one (decompressing into `scratch`).
    #[allow(dead_code)]
    pub fn parse_any(data: &'a [u8], scratch: &'a mut Vec<u8>) -> Result<Self> {
        match u16_at(data, 0)? {
            MAGIC_PLAIN => Self::parse(data),
            MAGIC_COMPRESSED => {
                *scratch = decompress(data)?;
                Self::parse(scratch)
            }
            m => Err(malformed(format!("bad blob magic {m:#06x}"))),
        }
    }

    #[allow(dead_code)]
    pub fn entries(&self) -> &[(&'a [u8], &'a [u8])] {
        &self.entries
    }

    pub fn get(&self, key: &[u8]) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }

    pub fn get_u32_key(&self, key: u32) -> Option<&'a [u8]> {
        self.get(&key.to_le_bytes())
    }

    pub fn require(&self, key: u32) -> Result<&'a [u8]> {
        self.get_u32_key(key)
            .ok_or_else(|| malformed(format!("blob is missing key {key}")))
    }

    pub fn u32(&self, key: u32) -> Result<u32> {
        let v = self.require(key)?;
        if v.len() != 4 {
            return Err(malformed(format!(
                "key {key}: expected 4 bytes, got {}",
                v.len()
            )));
        }
        u32_at(v, 0)
    }

    #[allow(dead_code)]
    pub fn u64(&self, key: u32) -> Result<u64> {
        let v = self.require(key)?;
        if v.len() != 8 {
            return Err(malformed(format!(
                "key {key}: expected 8 bytes, got {}",
                v.len()
            )));
        }
        u64_at(v, 0)
    }

    /// Read a value that is a u32 (format 3) or u64 (format 4).
    pub fn u32_or_u64(&self, key: u32) -> Result<u64> {
        let v = self.require(key)?;
        match v.len() {
            4 => Ok(u64::from(u32_at(v, 0)?)),
            8 => u64_at(v, 0),
            n => Err(malformed(format!(
                "key {key}: expected 4 or 8 bytes, got {n}"
            ))),
        }
    }
}

/// Decompress a `0x4301` compressed blob into its plain form.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let magic = u16_at(data, 0)?;
    if magic != MAGIC_COMPRESSED {
        return Err(malformed(format!("bad compressed blob magic {magic:#06x}")));
    }
    // `packed` counts this 20-byte header too.
    let packed = u64_at(data, 2)? as usize;
    let unpacked = u64_at(data, 10)? as usize;
    if packed != data.len() {
        tracing::debug!(
            "compressed blob: packed size {packed} vs buffer {}",
            data.len()
        );
    }
    let body = data
        .get(20..packed.min(data.len()))
        .ok_or_else(|| malformed("compressed blob body truncated"))?;
    let mut out = Vec::with_capacity(unpacked);
    flate2::read::ZlibDecoder::new(body).read_to_end(&mut out)?;
    if out.len() != unpacked {
        return Err(malformed(format!(
            "compressed blob: expected {unpacked} bytes, got {}",
            out.len()
        )));
    }
    Ok(out)
}

/// Metadata read from a version blob's top level (everything except the
/// manifest and checksum table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMeta {
    pub format: u32,
    pub own_crc: u32,
    pub dat_crc: u32,
    pub dat_size: u64,
    /// `None` for a root (previous version 0xffffffff).
    pub prev: Option<(u32, u32)>,
}

impl VersionMeta {
    pub fn from_blob(blob: &Blob<'_>) -> Result<Self> {
        let prev_version = blob.u32(keys::PREV_VERSION)?;
        let prev_crc = blob.u32(keys::PREV_CRC)?;
        Ok(Self {
            format: blob.u32(keys::FORMAT)?,
            own_crc: blob.u32(keys::OWN_CRC)?,
            dat_crc: blob.u32(keys::DAT_CRC)?,
            dat_size: blob.u32_or_u64(keys::DAT_SIZE)?,
            prev: (prev_version != u32::MAX).then_some((prev_version, prev_crc)),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn entry(key: u32, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&(value.len() as u32).to_le_bytes());
        v.extend_from_slice(&key.to_le_bytes());
        v.extend_from_slice(value);
        v
    }

    fn build(entries: &[(u32, &[u8])]) -> Vec<u8> {
        let body: Vec<u8> = entries.iter().flat_map(|(k, v)| entry(*k, v)).collect();
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC_PLAIN.to_le_bytes());
        out.extend_from_slice(&((body.len() + 10) as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parses_entries() {
        let data = build(&[(0, &3u32.to_le_bytes()), (13, &7u64.to_le_bytes())]);
        let blob = Blob::parse(&data).unwrap();
        assert_eq!(blob.u32(0).unwrap(), 3);
        assert_eq!(blob.u32_or_u64(13).unwrap(), 7);
        assert!(blob.get_u32_key(99).is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(Blob::parse(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn round_trips_compressed() {
        let plain = build(&[(1, b"x\0")]);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, &plain).unwrap();
        let packed = z.finish().unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC_COMPRESSED.to_le_bytes());
        data.extend_from_slice(&((packed.len() + 20) as u64).to_le_bytes());
        data.extend_from_slice(&(plain.len() as u64).to_le_bytes());
        data.extend_from_slice(&9u16.to_le_bytes());
        data.extend_from_slice(&packed);
        let mut scratch = Vec::new();
        let blob = Blob::parse_any(&data, &mut scratch).unwrap();
        assert_eq!(blob.get_u32_key(1).unwrap(), b"x\0");
    }
}
