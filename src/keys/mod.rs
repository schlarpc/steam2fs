//! Depot AES keys: a built-in table plus user overrides.

mod table;

use std::collections::HashMap;

use crate::format::chunk::Key;

#[derive(Debug, Default, Clone)]
pub struct KeyStore {
    overrides: HashMap<u32, Key>,
    /// Keys that apply to one specific blob (depot, blob crc): a republished
    /// depot can use a different key than the rest of the depot.
    blob_overrides: HashMap<(u32, u32), Key>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, depot: u32, key: Key) {
        self.overrides.insert(depot, key);
    }

    pub fn insert_for_blob(&mut self, depot: u32, blob_crc: u32, key: Key) {
        self.blob_overrides.insert((depot, blob_crc), key);
    }

    /// Parse `DEPOT=HEX` or `DEPOT@BLOBCRC=HEX` (32 hex digits).
    pub fn insert_spec(&mut self, spec: &str) -> anyhow::Result<()> {
        let (target, hex) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("key spec {spec:?} is not DEPOT[@CRC]=HEX"))?;
        let key = parse_hex(hex.trim())?;
        match target.trim().split_once('@') {
            Some((depot, crc)) => {
                self.insert_for_blob(depot.parse()?, u32::from_str_radix(crc, 16)?, key);
            }
            None => self.insert(target.trim().parse()?, key),
        }
        Ok(())
    }

    /// Load a file of `DEPOT=HEX` lines (`#` comments and blank lines ignored).
    pub fn load_file(&mut self, path: &std::path::Path) -> anyhow::Result<()> {
        let text = std::fs::read_to_string(path)?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.insert_spec(line)?;
        }
        Ok(())
    }

    pub fn get(&self, depot: u32) -> Option<Key> {
        if let Some(k) = self.overrides.get(&depot) {
            return Some(*k);
        }
        table::TABLE
            .binary_search_by_key(&depot, |(d, _)| *d)
            .ok()
            .map(|i| table::TABLE[i].1)
    }

    /// The key for one blob: a blob-specific override wins over the depot key.
    pub fn get_for_blob(&self, depot: u32, blob_crc: u32) -> Option<Key> {
        self.blob_overrides
            .get(&(depot, blob_crc))
            .copied()
            .or_else(|| self.get(depot))
    }

    /// Every key known, for brute-force discovery: overrides first, then the
    /// built-in table. Yields (label, key).
    pub fn candidates(&self) -> impl Iterator<Item = (String, Key)> + '_ {
        self.blob_overrides
            .iter()
            .map(|((d, c), k)| (format!("{d}@{c:08x}"), *k))
            .chain(self.overrides.iter().map(|(d, k)| (d.to_string(), *k)))
            .chain(table::TABLE.iter().map(|(d, k)| (d.to_string(), *k)))
    }

    #[allow(dead_code)]
    pub fn builtin_count() -> usize {
        table::TABLE.len()
    }
}

pub fn parse_hex(hex: &str) -> anyhow::Result<Key> {
    let bytes = hex::decode(hex)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 16 bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(table::TABLE.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn builtin_lookup() {
        let ks = KeyStore::new();
        assert_eq!(ks.get(0).unwrap()[0], 0xa1);
        assert!(ks.get(u32::MAX).is_none());
    }

    #[test]
    fn override_wins() {
        let mut ks = KeyStore::new();
        ks.insert_spec("0=000102030405060708090a0b0c0d0e0f")
            .unwrap();
        assert_eq!(ks.get(0).unwrap()[15], 0x0f);
        assert!(ks.insert_spec("0=abc").is_err());
        ks.insert_spec("0@deadbeef=ff0102030405060708090a0b0c0d0e0f")
            .unwrap();
        assert_eq!(ks.get_for_blob(0, 0xdead_beef).unwrap()[0], 0xff);
        assert_eq!(ks.get_for_blob(0, 1).unwrap()[0], 0x00);
    }
}
