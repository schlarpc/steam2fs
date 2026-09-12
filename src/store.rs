//! Ties the pieces together: fetches and parses blobs (with an on-disk
//! cache), follows version chains, builds per-version file tables, and
//! serves decoded file bytes out of dats through two LRU caches.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use parking_lot::Mutex;

use crate::backend::Backend;
use crate::cache::{ByteLru, SingleFlight};
use crate::format::blob::{self, Blob, VersionMeta};
use crate::format::checksums::{self, FileRecord};
use crate::format::chunk::{self, Key};
use crate::format::manifest::Manifest;
use crate::format::BLOCK_SIZE;
use crate::index::{BlobId, DatId, Index};
use crate::keys::KeyStore;
use sha2::Digest;

/// Raw dat bytes are fetched in aligned windows this large.
pub const RAW_WINDOW: u64 = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("no file record for file id {0} in this version chain")]
    MissingRecord(u32),
    #[error("dat file for depot {depot} version {version} crc {crc:08x} is not in the dump")]
    MissingDat { depot: u32, version: u32, crc: u32 },
    #[error("no AES key known for depot {0}")]
    NoKey(u32),
    #[error("depot {depot} blob {crc:08x}: no known key decrypts it (tried {tried})")]
    NoWorkingKey { depot: u32, crc: u32, tried: usize },
    #[error("block {block} of file id {file_id}: checksum mismatch (expected {expected:08x}, got {actual:08x})")]
    Checksum {
        file_id: u32,
        block: usize,
        expected: u32,
        actual: u32,
    },
    #[error("block {block} of file id {file_id}: short read from dat ({got} of {want} bytes)")]
    ShortRead {
        file_id: u32,
        block: usize,
        want: usize,
        got: usize,
    },
    #[error("file id {file_id} has no block {block} (it has {blocks})")]
    NoSuchBlock {
        file_id: u32,
        block: usize,
        blocks: usize,
    },
    #[error("block {block} of file id {file_id} decoded to {got} bytes, expected {want}")]
    BlockSize {
        file_id: u32,
        block: usize,
        want: u64,
        got: usize,
    },
    #[error("file id {file_id} has no blocks, so its key cannot be probed")]
    NoBlocksToProbe { file_id: u32 },
    #[error(transparent)]
    Format(#[from] crate::format::FormatError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ReadError {
    pub fn errno(&self) -> i32 {
        match self {
            ReadError::MissingRecord(_) | ReadError::MissingDat { .. } => libc::ENXIO,
            ReadError::NoKey(_) | ReadError::NoWorkingKey { .. } => libc::ENOKEY,
            ReadError::Checksum { .. }
            | ReadError::ShortRead { .. }
            | ReadError::NoSuchBlock { .. }
            | ReadError::BlockSize { .. }
            | ReadError::NoBlocksToProbe { .. } => libc::EIO,
            ReadError::Format(_) => libc::EBADMSG,
            ReadError::Other(_) => libc::EIO,
        }
    }
}

pub type Result<T> = std::result::Result<T, ReadError>;

/// Everything parsed out of one version blob.
pub struct ParsedBlob {
    pub meta: VersionMeta,
    pub manifest: Arc<Manifest>,
    pub records: Vec<FileRecord>,
}

/// Where one file id's bytes live, as seen from some version.
pub struct FileLoc {
    /// The blob whose dat holds the data (the version that last changed it).
    pub source: BlobId,
    pub dat: Option<DatId>,
    pub record: FileRecord,
    /// Absolute dat offset of each block; `offsets[i+1]` is the end of block `i`.
    pub offsets: Vec<u64>,
}

impl FileLoc {
    /// Stored byte range of block `i` in the dat.
    fn block_span(&self, i: usize) -> Option<(u64, u64)> {
        Some((*self.offsets.get(i)?, *self.offsets.get(i + 1)?))
    }

    fn no_such_block(&self, i: usize) -> ReadError {
        ReadError::NoSuchBlock {
            file_id: self.record.file_id,
            block: i,
            blocks: self.record.num_blocks(),
        }
    }
}

/// A version's file table, stored as the records that version introduced
/// layered over its parent's table. Building it costs only this version's
/// records, and two versions of a depot share everything they inherit.
pub struct FileTable {
    /// Records this version introduced, by file id.
    own: HashMap<u32, Arc<FileLoc>>,
    /// The parent version's table; the chain is acyclic by construction
    /// (`chain` breaks cycles), so lookups always terminate.
    parent: Option<Arc<FileTable>>,
}

impl FileTable {
    pub fn get(&self, file_id: u32) -> Option<&Arc<FileLoc>> {
        let mut cur = self;
        loop {
            if let Some(loc) = cur.own.get(&file_id) {
                return Some(loc);
            }
            cur = cur.parent.as_deref()?;
        }
    }

    pub fn contains(&self, file_id: u32) -> bool {
        self.get(file_id).is_some()
    }
}

pub struct StoreConfig {
    pub blob_cache_dir: Option<PathBuf>,
    pub raw_cache_bytes: usize,
    pub block_cache_bytes: usize,
    pub verify: bool,
    /// When the depot's key fails, try every known key against the block.
    pub key_search: bool,
}

/// Outcome of resolving the key for one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyResolution {
    /// The configured key for the depot (or a blob-specific override) works.
    Configured(Key),
    /// Found by trying every known key; the u32 is the depot it belongs to.
    Discovered(Key, u32),
    /// Nothing decrypts this blob's data.
    None { tried: usize },
}

pub struct Store {
    backend: Arc<dyn Backend>,
    pub index: Index,
    keys: KeyStore,
    cfg: StoreConfig,
    parsed: Mutex<lru::LruCache<BlobId, Arc<ParsedBlob>>>,
    tables: Mutex<lru::LruCache<BlobId, Arc<FileTable>>>,
    raw: ByteLru<(DatId, u64)>,
    blocks: ByteLru<(DatId, u64)>,
    /// Keeps concurrent misses from parsing the same blob, rebuilding the
    /// same file table, or fetching the same dat window twice over.
    blob_flight: SingleFlight<BlobId>,
    table_flight: SingleFlight<BlobId>,
    window_flight: SingleFlight<(DatId, u64)>,
    /// Per source blob: which key actually decrypts it (resolved lazily).
    resolved_keys: Mutex<HashMap<BlobId, KeyResolution>>,
}

impl Store {
    pub fn new(backend: Arc<dyn Backend>, index: Index, keys: KeyStore, cfg: StoreConfig) -> Self {
        let cap = |n: usize| NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN);
        Self {
            raw: ByteLru::new(cfg.raw_cache_bytes),
            blocks: ByteLru::new(cfg.block_cache_bytes),
            backend,
            index,
            keys,
            cfg,
            parsed: Mutex::new(lru::LruCache::new(cap(512))),
            tables: Mutex::new(lru::LruCache::new(cap(256))),
            resolved_keys: Mutex::new(HashMap::new()),
            blob_flight: SingleFlight::new(),
            table_flight: SingleFlight::new(),
            window_flight: SingleFlight::new(),
        }
    }

    #[allow(dead_code)]
    pub fn backend(&self) -> &dyn Backend {
        &*self.backend
    }

    pub fn key_for(&self, depot: u32) -> Option<Key> {
        self.keys.get(depot)
    }

    // ---- blobs -----------------------------------------------------------

    /// Raw bytes of a blob, via the on-disk cache when configured. A blob's
    /// name embeds the sha256 of its contents, so a cache entry is keyed by
    /// what it should contain and is checked against it on the way out; a
    /// name without a full hash falls back to a size check.
    pub fn blob_bytes(&self, id: BlobId) -> anyhow::Result<Vec<u8>> {
        let entry = self.index.blob(id);
        let cached = self
            .cfg
            .blob_cache_dir
            .as_ref()
            .map(|d| d.join(&entry.file_name));
        if let Some(p) = &cached {
            if let Ok(bytes) = std::fs::read(p) {
                match check_contents(entry, &bytes) {
                    Ok(()) => return Ok(bytes),
                    Err(e) => tracing::warn!(
                        path = %p.display(),
                        "ignoring cached blob: {e:#}"
                    ),
                }
            }
        }
        let bytes = self.backend.read_all(&entry.path)?;
        check_contents(entry, &bytes)?;
        if let Some(p) = &cached {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let tmp = p.with_extension("blob.tmp");
            if std::fs::write(&tmp, &bytes)
                .and_then(|()| std::fs::rename(&tmp, p))
                .is_err()
            {
                let _ = std::fs::remove_file(&tmp);
            }
        }
        Ok(bytes)
    }

    pub fn parsed(&self, id: BlobId) -> Result<Arc<ParsedBlob>> {
        if let Some(p) = self.parsed.lock().get(&id) {
            return Ok(p.clone());
        }
        self.blob_flight.dedupe(&id, || self.parse_uncached(id))
    }

    fn parse_uncached(&self, id: BlobId) -> Result<Arc<ParsedBlob>> {
        if let Some(p) = self.parsed.lock().get(&id) {
            return Ok(p.clone());
        }
        let bytes = self.blob_bytes(id)?;
        let entry = self.index.blob(id);
        let parsed =
            Arc::new(parse_blob(&bytes).with_context(|| format!("parsing {}", entry.file_name))?);
        // Cross-checks between the pieces of a blob and its file name.
        if parsed.meta.own_crc != entry.crc {
            tracing::warn!(
                blob = entry.file_name,
                "blob key 10 {:08x} != name crc",
                parsed.meta.own_crc
            );
        }
        if parsed.manifest.version_id != entry.version {
            tracing::warn!(
                blob = entry.file_name,
                "manifest version id {} != name",
                parsed.manifest.version_id
            );
        }
        let stored: u64 = parsed
            .records
            .iter()
            .flat_map(|r| r.blocks.iter().map(|b| u64::from(b.compressed_size)))
            .sum();
        if stored != parsed.meta.dat_size {
            tracing::warn!(
                blob = entry.file_name,
                "blocks total {stored} bytes but blob says the dat is {}",
                parsed.meta.dat_size
            );
        }
        if let Some(d) = self
            .index
            .find_dat(entry.depot, entry.version, parsed.meta.dat_crc)
        {
            let de = self.index.dat(d);
            if de.size != parsed.meta.dat_size {
                tracing::warn!(
                    dat = de.path,
                    "dat is {} bytes on disk, blob says {}{}",
                    de.size,
                    parsed.meta.dat_size,
                    if de.incomplete {
                        " (download in progress)"
                    } else {
                        ""
                    }
                );
            }
        }
        self.parsed.lock().put(id, parsed.clone());
        Ok(parsed)
    }

    /// The parent blob, resolved by the (version, crc) recorded in `id`.
    /// Falls back to a unique blob with the parent's version number if the
    /// exact crc is absent from the dump.
    pub fn parent(&self, id: BlobId) -> Result<Option<BlobId>> {
        let meta = self.parsed(id)?.meta;
        let entry = self.index.blob(id);
        let Some((pver, pcrc)) = meta.prev else {
            return Ok(None);
        };
        if let Some(p) = self.index.find_blob(entry.depot, pver, pcrc) {
            return Ok(Some(p));
        }
        let candidates = self.index.blobs_with_version(entry.depot, pver);
        match candidates.as_slice() {
            [only] => {
                tracing::warn!(
                    blob = entry.file_name,
                    "parent crc {pcrc:08x} not found; using the only version-{pver} blob"
                );
                Ok(Some(*only))
            }
            [] => {
                tracing::warn!(
                    blob = entry.file_name,
                    "parent version {pver} is missing from the dump"
                );
                Ok(None)
            }
            _ => {
                tracing::warn!(
                    blob = entry.file_name,
                    "parent crc {pcrc:08x} not found and version {pver} is ambiguous"
                );
                Ok(None)
            }
        }
    }

    /// Root-first chain of blobs ending at `id`.
    pub fn chain(&self, id: BlobId) -> Result<Vec<BlobId>> {
        let mut out = vec![id];
        let mut cur = id;
        while let Some(p) = self.parent(cur)? {
            if out.contains(&p) || out.len() > 100_000 {
                tracing::error!("version chain cycle at {}", self.index.blob(p).file_name);
                break;
            }
            out.push(p);
            cur = p;
        }
        out.reverse();
        Ok(out)
    }

    // ---- file tables ------------------------------------------------------

    /// File id -> location, as of version `id`: the records it introduced
    /// layered over its parent's table.
    ///
    /// Built by walking the version chain root-first rather than recursing,
    /// so a dump whose blobs point at each other cannot overflow the stack.
    pub fn table(&self, id: BlobId) -> Result<Arc<FileTable>> {
        if let Some(t) = self.tables.lock().get(&id) {
            return Ok(t.clone());
        }
        self.table_flight.dedupe(&id, || self.build_table(id))
    }

    fn build_table(&self, id: BlobId) -> Result<Arc<FileTable>> {
        if let Some(t) = self.tables.lock().get(&id) {
            return Ok(t.clone());
        }
        let mut parent: Option<Arc<FileTable>> = None;
        for b in self.chain(id)? {
            if let Some(t) = self.tables.lock().get(&b) {
                parent = Some(t.clone());
                continue;
            }
            let t = Arc::new(self.own_table(b, parent.take())?);
            self.tables.lock().put(b, t.clone());
            parent = Some(t);
        }
        // `chain` always ends at `id` itself, so the last layer is its table.
        parent.ok_or_else(|| ReadError::Other(anyhow::anyhow!("empty version chain")))
    }

    /// One layer: the records blob `id` introduced, over `parent`.
    fn own_table(&self, id: BlobId, parent: Option<Arc<FileTable>>) -> Result<FileTable> {
        let parsed = self.parsed(id)?;
        let entry = self.index.blob(id);
        let dat = self
            .index
            .find_dat(entry.depot, entry.version, parsed.meta.dat_crc);
        if dat.is_none() && !parsed.records.is_empty() {
            tracing::warn!(
                blob = entry.file_name,
                "dat with crc {:08x} is missing; {} files unreadable",
                parsed.meta.dat_crc,
                parsed.records.len()
            );
        }
        let mut own = HashMap::with_capacity(parsed.records.len());
        for r in &parsed.records {
            let mut offsets = Vec::with_capacity(r.blocks.len() + 1);
            let mut off = r.offset;
            offsets.push(off);
            for b in &r.blocks {
                off += u64::from(b.compressed_size);
                offsets.push(off);
            }
            own.insert(
                r.file_id,
                Arc::new(FileLoc {
                    source: id,
                    dat,
                    record: r.clone(),
                    offsets,
                }),
            );
        }
        Ok(FileTable { own, parent })
    }

    pub fn locate(&self, id: BlobId, file_id: u32) -> Result<Arc<FileLoc>> {
        self.table(id)?
            .get(file_id)
            .cloned()
            .ok_or(ReadError::MissingRecord(file_id))
    }

    // ---- data ------------------------------------------------------------

    fn raw_window(&self, dat: DatId, idx: u64) -> Result<Arc<Vec<u8>>> {
        let key = (dat, idx);
        if let Some(w) = self.raw.get(&key) {
            return Ok(w);
        }
        // A window is a megabyte off a possibly remote disk; two threads
        // reading neighbouring blocks should not fetch it twice.
        self.window_flight
            .dedupe(&key, || self.fetch_window(dat, idx))
    }

    fn fetch_window(&self, dat: DatId, idx: u64) -> Result<Arc<Vec<u8>>> {
        let key = (dat, idx);
        if let Some(w) = self.raw.get(&key) {
            return Ok(w);
        }
        let entry = self.index.dat(dat);
        let start = idx * RAW_WINDOW;
        let len = RAW_WINDOW.min(entry.size.saturating_sub(start)) as usize;
        let bytes = if len == 0 {
            Vec::new()
        } else {
            self.backend.read_at(&entry.path, start, len)?
        };
        let w = Arc::new(bytes);
        self.raw.insert(key, w.clone());
        Ok(w)
    }

    /// Stored bytes `[start, end)` of a dat, assembled from cached windows.
    fn dat_bytes(&self, dat: DatId, start: u64, end: u64) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity((end - start) as usize);
        let mut pos = start;
        while pos < end {
            let idx = pos / RAW_WINDOW;
            let w = self.raw_window(dat, idx)?;
            let in_w = (pos - idx * RAW_WINDOW) as usize;
            if in_w >= w.len() {
                break;
            }
            let take = ((end - pos) as usize).min(w.len() - in_w);
            out.extend_from_slice(&w[in_w..in_w + take]);
            pos += take as u64;
        }
        Ok(out)
    }

    /// Which key decrypts data stored by blob `source`, resolving it on the
    /// first encrypted block seen. `sample` is one raw encrypted block with
    /// its mode and stored checksum, used to test candidates.
    fn resolve_key(&self, source: BlobId, sample: (checksums::Mode, &[u8], u32)) -> KeyResolution {
        if let Some(r) = self.resolved_keys.lock().get(&source) {
            return *r;
        }
        let entry = self.index.blob(source);
        let (mode, raw, expected) = sample;
        let works = |k: &Key| chunk::decode_verified(mode, raw, Some(k), expected).is_ok();

        let mut result = KeyResolution::None { tried: 0 };
        if let Some(k) = self.keys.get_for_blob(entry.depot, entry.crc) {
            if works(&k) {
                result = KeyResolution::Configured(k);
            } else {
                tracing::warn!(
                    blob = entry.file_name,
                    "configured key for depot {} does not decrypt this blob",
                    entry.depot
                );
            }
        }
        if matches!(result, KeyResolution::None { .. }) && self.cfg.key_search {
            let mut tried = 0;
            for (label, k) in self.keys.candidates() {
                tried += 1;
                if works(&k) {
                    let from: u32 = label
                        .split('@')
                        .next()
                        .and_then(|d| d.parse().ok())
                        .unwrap_or(0);
                    tracing::info!(
                        blob = entry.file_name,
                        "key search: depot {label}'s key decrypts it; add `{}@{:08x}={}` to a keys file",
                        entry.depot,
                        entry.crc,
                        hex::encode(k)
                    );
                    result = KeyResolution::Discovered(k, from);
                    break;
                }
            }
            if matches!(result, KeyResolution::None { .. }) {
                tracing::warn!(
                    blob = entry.file_name,
                    "key search: none of {tried} known keys decrypt this blob"
                );
                result = KeyResolution::None { tried };
            }
        }
        self.resolved_keys.lock().insert(source, result);
        result
    }

    /// Resolve the key for an encrypted file by reading its first block.
    pub fn probe_key(&self, loc: &FileLoc) -> Result<KeyResolution> {
        let dat = loc.dat.ok_or_else(|| self.missing_dat(loc))?;
        // An empty file stores nothing, so there is no ciphertext to test a
        // candidate key against.
        let (Some(first), Some((start, end))) = (loc.record.blocks.first(), loc.block_span(0))
        else {
            return Err(ReadError::NoBlocksToProbe {
                file_id: loc.record.file_id,
            });
        };
        let raw = self.dat_bytes(dat, start, end)?;
        if raw.len() as u64 != end - start {
            return Err(ReadError::ShortRead {
                file_id: loc.record.file_id,
                block: 0,
                want: (end - start) as usize,
                got: raw.len(),
            });
        }
        Ok(self.resolve_key(loc.source, (loc.record.mode, &raw, first.checksum)))
    }

    fn missing_dat(&self, loc: &FileLoc) -> ReadError {
        let e = self.index.blob(loc.source);
        ReadError::MissingDat {
            depot: e.depot,
            version: e.version,
            crc: self.parsed(loc.source).map(|p| p.meta.dat_crc).unwrap_or(0),
        }
    }

    /// Decoded bytes of block `i` of a file.
    pub fn block(&self, loc: &FileLoc, i: usize) -> Result<Arc<Vec<u8>>> {
        let dat = loc.dat.ok_or_else(|| {
            let e = self.index.blob(loc.source);
            ReadError::MissingDat {
                depot: e.depot,
                version: e.version,
                crc: self.parsed(loc.source).map(|p| p.meta.dat_crc).unwrap_or(0),
            }
        })?;
        let (Some(block_meta), Some((start, end))) = (loc.record.blocks.get(i), loc.block_span(i))
        else {
            return Err(loc.no_such_block(i));
        };
        let key = (dat, start);
        if let Some(b) = self.blocks.get(&key) {
            return Ok(b);
        }
        let rec = &loc.record;
        let raw = self.dat_bytes(dat, start, end)?;
        if raw.len() as u64 != end - start {
            return Err(ReadError::ShortRead {
                file_id: rec.file_id,
                block: i,
                want: (end - start) as usize,
                got: raw.len(),
            });
        }
        let entry = self.index.blob(loc.source);
        let key_bytes = if rec.mode.is_encrypted() {
            match self.resolve_key(loc.source, (rec.mode, &raw, block_meta.checksum)) {
                KeyResolution::Configured(k) | KeyResolution::Discovered(k, _) => Some(k),
                KeyResolution::None { tried: 0 } => return Err(ReadError::NoKey(entry.depot)),
                KeyResolution::None { tried } => {
                    return Err(ReadError::NoWorkingKey {
                        depot: entry.depot,
                        crc: entry.crc,
                        tried,
                    })
                }
            }
        } else {
            None
        };
        let decoded = chunk::decode_owned(rec.mode, raw, key_bytes.as_ref())?;
        if self.cfg.verify {
            let actual = chunk::checksum(&decoded);
            let expected = block_meta.checksum;
            if actual != expected {
                return Err(ReadError::Checksum {
                    file_id: rec.file_id,
                    block: i,
                    expected,
                    actual,
                });
            }
        }
        // The block table and the file size have to agree, or `read` would
        // have to paper over a hole with silently truncated data.
        let (bs, be) = rec.block_range(i);
        if decoded.len() as u64 != be - bs {
            return Err(ReadError::BlockSize {
                file_id: rec.file_id,
                block: i,
                want: be - bs,
                got: decoded.len(),
            });
        }
        let decoded = Arc::new(decoded);
        // A plain block's decoded bytes are exactly its stored bytes, which
        // the raw-window cache already holds; caching them again would spend
        // the block cache storing a second copy of the raw one.
        if rec.mode != checksums::Mode::Plain {
            self.blocks.insert(key, decoded.clone());
        }
        Ok(decoded)
    }

    /// Read `len` decoded bytes of a file starting at `offset`.
    pub fn read(&self, loc: &FileLoc, offset: u64, len: usize) -> Result<Vec<u8>> {
        let size = loc.record.size;
        if offset >= size || len == 0 {
            return Ok(Vec::new());
        }
        let end = (offset + len as u64).min(size);
        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut pos = offset;
        while pos < end {
            // Every byte below `size` is covered by a block, so a missing or
            // short block is corruption, not end of file: report it rather
            // than handing back a silently truncated read.
            let i = (pos / BLOCK_SIZE) as usize;
            let block = self.block(loc, i)?;
            let in_block = (pos % BLOCK_SIZE) as usize;
            if in_block >= block.len() {
                return Err(loc.no_such_block(i));
            }
            let take = ((end - pos) as usize).min(block.len() - in_block);
            out.extend_from_slice(&block[in_block..in_block + take]);
            pos += take as u64;
        }
        Ok(out)
    }

    #[allow(dead_code)]
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.raw.bytes(), self.blocks.bytes())
    }
}

/// Check bytes against what a blob's file name says they should be: its
/// sha256 when the name carries the full hash, its size otherwise.
fn check_contents(entry: &crate::index::BlobEntry, bytes: &[u8]) -> anyhow::Result<()> {
    match entry.sha256.as_deref() {
        Some(expected) => {
            let actual = hex::encode(sha2::Sha256::digest(bytes));
            anyhow::ensure!(
                actual == expected,
                "{}: sha256 {actual} does not match its name",
                entry.file_name
            );
        }
        None => anyhow::ensure!(
            bytes.len() as u64 == entry.size,
            "{}: {} bytes, expected {}",
            entry.file_name,
            bytes.len(),
            entry.size
        ),
    }
    Ok(())
}

pub fn parse_blob(bytes: &[u8]) -> anyhow::Result<ParsedBlob> {
    let top = Blob::parse(bytes)?;
    let meta = VersionMeta::from_blob(&top)?;
    let manifest_wrapper = blob::decompress(top.require(blob::keys::MANIFEST)?)?;
    let inner = Blob::parse(&manifest_wrapper)?;
    let manifest = Manifest::parse(inner.require(0)?)?;
    let fingerprint = top.u32(blob::keys::MANIFEST_FINGERPRINT)?;
    anyhow::ensure!(
        fingerprint == manifest.fingerprint,
        "blob key 2 {fingerprint:08x} != manifest fingerprint {:08x}",
        manifest.fingerprint
    );
    // Key 10 is the crc32 of the whole blob with its own value zeroed.
    let own = top.require(blob::keys::OWN_CRC)?;
    anyhow::ensure!(own.len() == 4, "key 10 is {} bytes, not 4", own.len());
    let off = top.value_offset(blob::keys::OWN_CRC)?;
    let mut h = crc32fast::Hasher::new();
    h.update(&bytes[..off]);
    h.update(&[0u8; 4]);
    h.update(&bytes[off + 4..]);
    let crc = h.finalize();
    anyhow::ensure!(
        crc == meta.own_crc,
        "blob crc {crc:08x} != key 10 {:08x}",
        meta.own_crc
    );
    let records = checksums::parse(top.require(blob::keys::CHECKSUMS)?)?;
    Ok(ParsedBlob {
        meta,
        manifest: Arc::new(manifest),
        records,
    })
}
