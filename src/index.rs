//! Inventory of a dump: which blob and dat files exist, parsed from their
//! names alone. Nothing here reads blob contents.
//!
//! File names look like `<depot>_<version>_<crc32 hex>_<sha256 hex>.blob`
//! and `<depot>_<version>_<crc32 hex>_<sha256 hex>.dat`; a qBittorrent
//! download in progress carries a trailing `.!qB`.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Parallel to `blobs`: the version directory name (`12`, or
    /// `12-0050a99e` when several blobs share a version number) and the
    /// `by-date/` link name. Both are built once, at index time.
    names: Vec<(String, String)>,
    by_name: HashMap<String, BlobId>,
    by_date_link: HashMap<String, BlobId>,
    /// `blobs` in `by-date/` listing order.
    date_order: Vec<BlobId>,
    index_of: HashMap<BlobId, usize>,
}

impl Depot {
    /// Version directory names, oldest first.
    pub fn versions(&self) -> impl Iterator<Item = (&str, BlobId)> + '_ {
        self.names
            .iter()
            .map(|(n, _)| n.as_str())
            .zip(self.blobs.iter().copied())
    }

    /// `by-date/` link names, in listing order.
    pub fn date_links(&self) -> impl Iterator<Item = (&str, BlobId)> + '_ {
        self.date_order
            .iter()
            .map(|b| (self.date_link_of(*b).unwrap_or(""), *b))
    }

    pub fn lookup_name(&self, name: &str) -> Option<BlobId> {
        self.by_name.get(name).copied()
    }

    pub fn lookup_date_link(&self, name: &str) -> Option<BlobId> {
        self.by_date_link.get(name).copied()
    }

    fn nth(&self, id: BlobId) -> Option<&(String, String)> {
        self.names.get(*self.index_of.get(&id)?)
    }

    pub fn name_of(&self, id: BlobId) -> Option<&str> {
        self.nth(id).map(|n| n.0.as_str())
    }

    pub fn date_link_of(&self, id: BlobId) -> Option<&str> {
        self.nth(id).map(|n| n.1.as_str())
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
    // Dates before 1970 have no SystemTime to offset from here.
    let days = u64::try_from(days_from_civil(y, m, day)).ok()?;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec;
    Some(UNIX_EPOCH + Duration::new(secs, nanos))
}

/// `YYYY-MM-DDTHH-MM-SS` for a unix timestamp (UTC).
pub fn format_stamp(secs: u64) -> String {
    // Saturating is unreachable for any real timestamp: i64 days is
    // twenty-five billion years.
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}-{:02}-{:02}",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// The inverse of `days_from_civil` (Howard Hinnant).
// `doy` is a day of the year and `mp` a shifted month, both non-negative by
// construction, so the day and month fall in 1..=31 and 1..=12.
#[allow(clippy::cast_sign_loss)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
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

        let started = Instant::now();
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
                tracing::info!(
                    count = m.len(),
                    elapsed = ?started.elapsed(),
                    "read blobs_dates.txt"
                );
                m
            }
            Err(e) => {
                tracing::warn!("no blobs_dates.txt ({e:#}); versions will have no dates");
                HashMap::new()
            }
        };

        let started = Instant::now();
        let blob_entries = backend.list_dir("blobs").context("listing blobs/")?;
        tracing::info!(
            entries = blob_entries.len(),
            elapsed = ?started.elapsed(),
            "listed blobs/"
        );
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

        let started = Instant::now();
        let dat_entries = backend.list_dir("dats").context("listing dats/")?;
        tracing::info!(
            entries = dat_entries.len(),
            elapsed = ?started.elapsed(),
            "listed dats/"
        );
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
                    let stamp = e
                        .date
                        .and_then(|d| d.duration_since(UNIX_EPOCH).ok())
                        .map_or_else(|| "unknown".to_string(), |d| format_stamp(d.as_secs()));
                    let link = format!("{stamp}_v{name}");
                    (name, link)
                })
                .collect();
            depot.index_of = depot
                .blobs
                .iter()
                .enumerate()
                .map(|(i, b)| (*b, i))
                .collect();
            depot.by_name = depot
                .names
                .iter()
                .zip(&depot.blobs)
                .map(|((n, _), b)| (n.clone(), *b))
                .collect();
            depot.by_date_link = depot
                .names
                .iter()
                .zip(&depot.blobs)
                .map(|((_, l), b)| (l.clone(), *b))
                .collect();
            let mut order: Vec<usize> = (0..depot.blobs.len()).collect();
            order.sort_by(|&a, &b| depot.names[a].1.cmp(&depot.names[b].1));
            let ordered: Vec<BlobId> = order.into_iter().map(|i| depot.blobs[i]).collect();
            depot.date_order = ordered;
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

    #[test]
    fn formats_stamps() {
        assert_eq!(format_stamp(0), "1970-01-01T00-00-00");
        assert_eq!(format_stamp(1_063_199_519), "2003-09-10T13-11-59");
        // civil_from_days is the inverse of days_from_civil over a long run
        // of dates, including leap days and century boundaries.
        for day in 0..40_000i64 {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day, "day {day} -> {y}-{m}-{d}");
        }
    }
}
