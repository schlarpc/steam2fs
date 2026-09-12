//! Inventory of a dump: which blob and dat files exist, parsed from their
//! names alone. Nothing here reads blob contents.
//!
//! File names look like `<depot>_<version>_<crc32 hex>_<sha256 hex>.blob`
//! and `<depot>_<version>_<crc32 hex>_<sha256 hex>.dat`; a qBittorrent
//! download in progress carries a trailing `.!qB`.

// Sizes and offsets in this format are 32-bit on disk; the casts below are bounded by it.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;

use crate::backend::Backend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DatId(pub u32);

#[derive(Debug, Clone)]
pub struct BlobEntry {
    /// Path relative to the dump root.
    pub path: String,
    pub file_name: String,
    pub depot: u32,
    pub version: u32,
    pub crc: u32,
    pub size: u64,
    /// From `blobs_dates.txt`, when present.
    pub date: Option<SystemTime>,
    /// Hex sha256 of the file contents, from the fourth name component.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DatEntry {
    pub path: String,
    pub depot: u32,
    pub version: u32,
    pub crc: u32,
    pub size: u64,
    pub incomplete: bool,
}

#[derive(Debug, Default)]
pub struct Depot {
    /// Sorted by (version, crc).
    pub blobs: Vec<BlobId>,
    /// Directory name -> blob, e.g. `12` or `12-0050a99e` when forked.
    names: Vec<(String, BlobId)>,
}

impl Depot {
    pub fn version_names(&self) -> &[(String, BlobId)] {
        &self.names
    }
    pub fn lookup_name(&self, name: &str) -> Option<BlobId> {
        self.names.iter().find(|(n, _)| n == name).map(|(_, b)| *b)
    }
    pub fn name_of(&self, id: BlobId) -> Option<&str> {
        self.names
            .iter()
            .find(|(_, b)| *b == id)
            .map(|(n, _)| n.as_str())
    }
}

#[derive(Debug, Default)]
pub struct Index {
    pub blobs: Vec<BlobEntry>,
    pub dats: Vec<DatEntry>,
    depots: BTreeMap<u32, Depot>,
    blob_by_key: HashMap<(u32, u32, u32), BlobId>,
    dat_by_key: HashMap<(u32, u32, u32), DatId>,
}

#[derive(Debug, Clone, Copy)]
struct ParsedName {
    depot: u32,
    version: u32,
    crc: u32,
}

fn parse_name<'a>(name: &'a str, ext: &str) -> Option<(ParsedName, &'a str)> {
    let stem = name.strip_suffix(ext)?;
    let mut it = stem.splitn(4, '_');
    let depot = it.next()?.parse().ok()?;
    let version = it.next()?.parse().ok()?;
    let crc = u32::from_str_radix(it.next()?, 16).ok()?;
    let sha = it.next()?;
    Some((
        ParsedName {
            depot,
            version,
            crc,
        },
        sha,
    ))
}

/// `YYYY-MM-DD+HH:MM:SS[.fraction]` (as written by the dump's date lists),
/// interpreted as UTC.
pub fn parse_date(s: &str) -> Option<SystemTime> {
    let (date, time) = s.split_once('+')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, u32, u32) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let mut t = time.split(':');
    let (h, mi): (u64, u64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    let sec_str = t.next()?;
    let (s_int, frac) = sec_str.split_once('.').unwrap_or((sec_str, ""));
    let sec: u64 = s_int.parse().ok()?;
    let nanos: u32 = if frac.is_empty() {
        0
    } else {
        let f: String = frac.chars().take(9).collect();
        let n: u32 = f.parse().ok()?;
        n * 10u32.pow(9 - f.len() as u32)
    };
    let days = days_from_civil(y, m, day);
    if days < 0 {
        return None;
    }
    let secs = days as u64 * 86_400 + h * 3600 + mi * 60 + sec;
    Some(UNIX_EPOCH + Duration::new(secs, nanos))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

impl Index {
    pub fn load(backend: &dyn Backend) -> anyhow::Result<Self> {
        let mut idx = Index::default();

        let dates = match backend.read_all("blobs_dates.txt") {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let mut m = HashMap::new();
                for line in text.lines() {
                    if let Some((name, date)) = line.split_once('\t') {
                        if let Some(t) = parse_date(date.trim()) {
                            m.insert(name.trim().to_string(), t);
                        }
                    }
                }
                tracing::info!(count = m.len(), "loaded blob dates");
                m
            }
            Err(e) => {
                tracing::warn!("no blobs_dates.txt ({e:#}); versions will have no dates");
                HashMap::new()
            }
        };

        let blob_entries = backend.list_dir("blobs").context("listing blobs/")?;
        for e in blob_entries {
            let Some((p, sha)) = parse_name(&e.name, ".blob") else {
                if !e.is_dir {
                    tracing::debug!(name = e.name, "ignoring non-blob file");
                }
                continue;
            };
            let id = BlobId(idx.blobs.len() as u32);
            idx.blob_by_key.insert((p.depot, p.version, p.crc), id);
            idx.blobs.push(BlobEntry {
                path: format!("blobs/{}", e.name),
                date: dates.get(&e.name).copied(),
                sha256: (sha.len() == 64).then(|| sha.to_string()),
                file_name: e.name,
                depot: p.depot,
                version: p.version,
                crc: p.crc,
                size: e.size,
            });
            idx.depots.entry(p.depot).or_default().blobs.push(id);
        }

        let dat_entries = backend.list_dir("dats").context("listing dats/")?;
        for e in dat_entries {
            let (name, incomplete) = match e.name.strip_suffix(".!qB") {
                Some(n) => (n, true),
                None => (e.name.as_str(), false),
            };
            let Some((p, _)) = parse_name(name, ".dat") else {
                continue;
            };
            let id = DatId(idx.dats.len() as u32);
            if let Some(prev) = idx.dat_by_key.insert((p.depot, p.version, p.crc), id) {
                // Prefer a complete file over an in-progress one with the same identity.
                if !idx.dats[prev.0 as usize].incomplete {
                    idx.dat_by_key.insert((p.depot, p.version, p.crc), prev);
                }
            }
            idx.dats.push(DatEntry {
                path: format!("dats/{}", e.name),
                depot: p.depot,
                version: p.version,
                crc: p.crc,
                size: e.size,
                incomplete,
            });
        }

        for depot in idx.depots.values_mut() {
            depot
                .blobs
                .sort_by_key(|b| (idx.blobs[b.0 as usize].version, idx.blobs[b.0 as usize].crc));
            let mut counts: HashMap<u32, usize> = HashMap::new();
            for b in &depot.blobs {
                *counts.entry(idx.blobs[b.0 as usize].version).or_default() += 1;
            }
            depot.names = depot
                .blobs
                .iter()
                .map(|b| {
                    let e = &idx.blobs[b.0 as usize];
                    let name = if counts[&e.version] > 1 {
                        format!("{}-{:08x}", e.version, e.crc)
                    } else {
                        e.version.to_string()
                    };
                    (name, *b)
                })
                .collect();
        }

        tracing::info!(
            depots = idx.depots.len(),
            blobs = idx.blobs.len(),
            dats = idx.dats.len(),
            incomplete_dats = idx.dats.iter().filter(|d| d.incomplete).count(),
            "indexed dump"
        );
        Ok(idx)
    }

    pub fn blob(&self, id: BlobId) -> &BlobEntry {
        &self.blobs[id.0 as usize]
    }

    pub fn dat(&self, id: DatId) -> &DatEntry {
        &self.dats[id.0 as usize]
    }

    pub fn depots(&self) -> impl Iterator<Item = (u32, &Depot)> {
        self.depots.iter().map(|(k, v)| (*k, v))
    }

    pub fn depot(&self, depot: u32) -> Option<&Depot> {
        self.depots.get(&depot)
    }

    pub fn find_blob(&self, depot: u32, version: u32, crc: u32) -> Option<BlobId> {
        self.blob_by_key.get(&(depot, version, crc)).copied()
    }

    /// All blobs of a depot with the given version number.
    pub fn blobs_with_version(&self, depot: u32, version: u32) -> Vec<BlobId> {
        self.depot(depot).map_or_else(Vec::new, |d| {
            d.blobs
                .iter()
                .copied()
                .filter(|b| self.blob(*b).version == version)
                .collect()
        })
    }

    pub fn find_dat(&self, depot: u32, version: u32, crc: u32) -> Option<DatId> {
        self.dat_by_key.get(&(depot, version, crc)).copied()
    }

    /// The most plausible "current" blob of a depot: highest version, and
    /// among forks the most recently dated one.
    pub fn latest(&self, depot: u32) -> Option<BlobId> {
        let d = self.depot(depot)?;
        let max_version = self.blob(*d.blobs.last()?).version;
        self.blobs_with_version(depot, max_version)
            .into_iter()
            .max_by_key(|b| self.blob(*b).date)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_names() {
        let (p, sha) = parse_name("102021_18_ef45a233_3dedcb2f.blob", ".blob").unwrap();
        assert_eq!((p.depot, p.version, p.crc), (102021, 18, 0xef45_a233));
        assert_eq!(sha, "3dedcb2f");
        assert!(parse_name("readme.txt", ".blob").is_none());
    }

    #[test]
    fn parses_dates() {
        let t = parse_date("2003-09-10+13:11:59.0156250000").unwrap();
        let secs = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(secs.as_secs(), 1_063_199_519);
        assert_eq!(secs.subsec_nanos(), 15_625_000);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }
}
