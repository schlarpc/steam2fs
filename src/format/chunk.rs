//! Decoding of one dat block.
//!
//! * `Plain`: stored bytes.
//! * `Compressed`: one zlib stream.
//! * `CompressedEncrypted`: `u32 encrypted_size, u32 decompressed_size`, then
//!   AES-128-CFB (zero IV, fresh per block) over a zlib stream.
//! * `Encrypted`: AES-128-CFB (zero IV) over the stored bytes.
//!
//! Each block's checksum is `adler32(seed 0) ^ crc32` of the decoded bytes.

// Sizes and offsets in this format are 32-bit on disk; the casts below are bounded by it.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::io::Read;

use aes::cipher::KeyIvInit;

use super::checksums::Mode;
use super::{malformed, u32_at, Result, BLOCK_SIZE};

pub type Key = [u8; 16];

type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

pub fn checksum(data: &[u8]) -> u32 {
    let mut a = adler2::Adler32::from_checksum(0);
    a.write_slice(data);
    a.checksum() ^ crc32fast::hash(data)
}

fn inflate(z: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(BLOCK_SIZE as usize);
    flate2::read::ZlibDecoder::new(z)
        .take(BLOCK_SIZE + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > BLOCK_SIZE {
        return Err(malformed("block inflates past BLOCK_SIZE"));
    }
    Ok(out)
}

fn decrypt(key: &Key, buf: &mut [u8]) {
    Aes128CfbDec::new(key.into(), &[0u8; 16].into()).decrypt(buf);
}

/// Decode one stored block. `key` is required for the encrypted modes.
pub fn decode(mode: Mode, raw: &[u8], key: Option<&Key>) -> Result<Vec<u8>> {
    let need_key = || key.ok_or_else(|| malformed("encrypted block but no depot key"));
    match mode {
        Mode::Plain => Ok(raw.to_vec()),
        Mode::Compressed => inflate(raw),
        Mode::CompressedEncrypted => {
            let key = need_key()?;
            let encrypted_size = u32_at(raw, 0)? as usize;
            let decompressed_size = u32_at(raw, 4)? as usize;
            if decompressed_size as u64 > BLOCK_SIZE {
                return Err(malformed(
                    "encrypted block header: decompressed size too large",
                ));
            }
            if encrypted_size != raw.len().saturating_sub(8) {
                return Err(malformed(format!(
                    "encrypted block header says {encrypted_size} bytes, stored {}",
                    raw.len().saturating_sub(8)
                )));
            }
            let body = raw
                .get(8..)
                .ok_or_else(|| malformed("encrypted block truncated"))?;
            let mut buf = body.to_vec();
            decrypt(key, &mut buf);
            let out = inflate(&buf)?;
            if out.len() != decompressed_size {
                return Err(malformed(format!(
                    "encrypted block: inflated {} bytes, header says {decompressed_size}",
                    out.len()
                )));
            }
            Ok(out)
        }
        Mode::Encrypted => {
            let key = need_key()?;
            let mut buf = raw.to_vec();
            decrypt(key, &mut buf);
            Ok(buf)
        }
    }
}

/// Decode a block whose stored bytes we own. Plain and encrypted blocks
/// are the same length decoded, so they need no second buffer.
pub fn decode_owned(mode: Mode, raw: Vec<u8>, key: Option<&Key>) -> Result<Vec<u8>> {
    match mode {
        Mode::Plain => Ok(raw),
        Mode::Encrypted => {
            let key = key.ok_or_else(|| malformed("encrypted block but no depot key"))?;
            let mut buf = raw;
            decrypt(key, &mut buf);
            Ok(buf)
        }
        Mode::Compressed | Mode::CompressedEncrypted => decode(mode, &raw, key),
    }
}

/// Decode and check a block against its stored checksum in one step.
pub fn decode_verified(
    mode: Mode,
    raw: &[u8],
    key: Option<&Key>,
    expected: u32,
) -> Result<Vec<u8>> {
    let out = decode(mode, raw, key)?;
    let actual = checksum(&out);
    if actual != expected {
        return Err(malformed(format!(
            "checksum {actual:08x} != stored {expected:08x}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn checksum_matches_reference_convention() {
        // adler32 seeded with 0 (not 1) xor crc32, as HLLib does for GCF.
        let data = b"hello";
        let mut a = adler2::Adler32::from_checksum(0);
        a.write_slice(data);
        assert_eq!(checksum(data), a.checksum() ^ crc32fast::hash(data));
        assert_ne!(
            checksum(data),
            adler2::adler32_slice(data) ^ crc32fast::hash(data)
        );
    }

    #[test]
    fn plain_and_compressed_round_trip() {
        let payload = vec![7u8; 1000];
        assert_eq!(decode(Mode::Plain, &payload, None).unwrap(), payload);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut z, &payload).unwrap();
        let packed = z.finish().unwrap();
        assert_eq!(decode(Mode::Compressed, &packed, None).unwrap(), payload);
    }

    #[test]
    fn encrypted_requires_key() {
        assert!(decode(Mode::Encrypted, &[0u8; 16], None).is_err());
        assert!(decode_owned(Mode::Encrypted, vec![0u8; 16], None).is_err());
    }

    #[test]
    fn decode_owned_matches_decode() {
        let payload = vec![7u8; 1000];
        let key = [3u8; 16];
        for mode in [Mode::Plain, Mode::Encrypted] {
            assert_eq!(
                decode_owned(mode, payload.clone(), Some(&key)).unwrap(),
                decode(mode, &payload, Some(&key)).unwrap()
            );
        }
    }
}
