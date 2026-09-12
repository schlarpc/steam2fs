//! The virtual tree the filesystem frontends serve, with no FUSE or WinFsp
//! in it.
//!
//! ```text
//! /<depot>/                      one directory per depot id
//! /<depot>/<version>/            the tree as of that version
//! /<depot>/<version>-<crc>/      when several blobs share a version number
//! /<depot>/latest -> <version>   symlink to the newest version
//! /<depot>/by-date/<timestamp>_<version> -> ../<version>
//! ```
//!
//! Every node is named by a [`Key`], which is small, copyable and hashable,
//! so a frontend can intern it (inodes on FUSE) or carry it in an open file
//! context (WinFsp) as it likes.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::format::manifest::{flags, Manifest, Node, NO_NODE};
use crate::index::{format_stamp, BlobId};
use crate::store::{FileLoc, ReadError, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Root,
    Depot(u32),
    Latest(u32),
    ByDate(u32),
    DateLink(BlobId),
    /// Root of a version's tree.
    Version(BlobId),
    /// Any other manifest node.
    Node(BlobId, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
    Symlink,
}

/// What a frontend needs to answer a stat: everything else it invents.
#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub kind: Kind,
    pub size: u64,
    pub mtime: SystemTime,
}

/// One entry of a directory listing. Names are bytes because manifests
/// store them that way; only the frontends decide how to spell them.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: Vec<u8>,
    pub key: Key,
    pub kind: Kind,
}

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("no such entry")]
    NotFound,
    #[error("not a directory")]
    NotADirectory,
    #[error(transparent)]
    Read(#[from] ReadError),
}

/// The tree over one [`Store`].
pub struct Tree {
    pub store: Arc<Store>,
}

impl Tree {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    fn blob_date(&self, id: BlobId) -> SystemTime {
        self.store.index.blob(id).date.unwrap_or(UNIX_EPOCH)
    }

    fn manifest(&self, id: BlobId) -> Result<Arc<Manifest>, ReadError> {
        Ok(self.store.parsed(id)?.manifest.clone())
    }

    /// Key for a manifest node, mapping the root node to `Version`.
    fn node_key(&self, blob: BlobId, m: &Manifest, idx: u32) -> Key {
        if idx == m.root() {
            Key::Version(blob)
        } else {
            Key::Node(blob, idx)
        }
    }

    /// The manifest node a key names, for the two keys that have one.
    fn node_index(key: Key, m: &Manifest) -> Option<u32> {
        match key {
            Key::Version(_) => Some(m.root()),
            Key::Node(_, idx) => Some(idx),
            _ => None,
        }
    }

    /// Metadata for a manifest node; file mtimes come from the version that
    /// last changed the file when its table is available.
    fn node_meta(&self, blob: BlobId, m: &Manifest, idx: u32) -> Meta {
        let n = m.node(idx).copied().unwrap_or_default_node();
        if n.is_dir() {
            return Meta {
                kind: Kind::Dir,
                size: 0,
                mtime: self.blob_date(blob),
            };
        }
        let (size, mtime) = match self.store.locate(blob, n.file_id) {
            Ok(loc) => (loc.record.size, self.blob_date(loc.source)),
            Err(_) => (u64::from(n.count_or_size), self.blob_date(blob)),
        };
        Meta {
            kind: Kind::File,
            size,
            mtime,
        }
    }

    pub fn meta(&self, key: Key) -> Result<Meta, TreeError> {
        let dir = |mtime| Meta {
            kind: Kind::Dir,
            size: 0,
            mtime,
        };
        Ok(match key {
            Key::Root => dir(UNIX_EPOCH),
            Key::Depot(d) => {
                let latest = self.store.index.latest(d);
                dir(latest.map_or(UNIX_EPOCH, |b| self.blob_date(b)))
            }
            Key::ByDate(_) => dir(UNIX_EPOCH),
            Key::Latest(d) => {
                let target = self.store.index.latest(d).ok_or(TreeError::NotFound)?;
                let name = self.link_target(key).unwrap_or_default();
                Meta {
                    kind: Kind::Symlink,
                    size: name.len() as u64,
                    mtime: self.blob_date(target),
                }
            }
            Key::DateLink(b) => {
                let name = self.link_target(key).unwrap_or_default();
                Meta {
                    kind: Kind::Symlink,
                    size: name.len() as u64,
                    mtime: self.blob_date(b),
                }
            }
            Key::Version(b) => dir(self.blob_date(b)),
            Key::Node(b, idx) => {
                let m = self.manifest(b)?;
                self.node_meta(b, &m, idx)
            }
        })
    }

    /// Where a symlink points, relative to its own directory.
    pub fn link_target(&self, key: Key) -> Option<String> {
        let idx = &self.store.index;
        match key {
            Key::Latest(d) => idx
                .latest(d)
                .and_then(|b| idx.depot(d).and_then(|x| x.name_of(b)))
                .map(str::to_string),
            Key::DateLink(b) => idx
                .depot(idx.blob(b).depot)
                .and_then(|x| x.name_of(b))
                .map(|n| format!("../{n}")),
            _ => None,
        }
    }

    /// The directory a key lives in. Anything without a real parent (or
    /// whose manifest will not load) reports the nearest sensible one.
    pub fn parent(&self, key: Key) -> Key {
        match key {
            Key::Root | Key::Depot(_) | Key::ByDate(_) | Key::Latest(_) | Key::DateLink(_) => {
                Key::Root
            }
            Key::Version(b) => Key::Depot(self.store.index.blob(b).depot),
            Key::Node(b, i) => match self.manifest(b) {
                Ok(m) => m
                    .node(i)
                    .map_or(Key::Version(b), |n| self.node_key(b, &m, n.parent)),
                Err(_) => Key::Version(b),
            },
        }
    }

    /// A directory's children, without `.` and `..`.
    pub fn entries(&self, key: Key) -> Result<Vec<Entry>, TreeError> {
        let idx = &self.store.index;
        let mut out: Vec<Entry> = Vec::new();
        let push = |out: &mut Vec<Entry>, name: &str, key: Key, kind: Kind| {
            out.push(Entry {
                name: name.as_bytes().to_vec(),
                key,
                kind,
            });
        };
        match key {
            Key::Root => {
                for (d, _) in idx.depots() {
                    push(&mut out, &d.to_string(), Key::Depot(d), Kind::Dir);
                }
            }
            Key::Depot(d) => {
                if let Some(dep) = idx.depot(d) {
                    for (name, b) in dep.versions() {
                        push(&mut out, name, Key::Version(b), Kind::Dir);
                    }
                    if idx.latest(d).is_some() {
                        push(&mut out, "latest", Key::Latest(d), Kind::Symlink);
                    }
                    push(&mut out, "by-date", Key::ByDate(d), Kind::Dir);
                }
            }
            Key::ByDate(d) => {
                if let Some(dep) = idx.depot(d) {
                    for (name, b) in dep.date_links() {
                        push(&mut out, name, Key::DateLink(b), Kind::Symlink);
                    }
                }
            }
            Key::Version(b) | Key::Node(b, _) => {
                let m = self.manifest(b).inspect_err(|e| {
                    tracing::warn!("listing a directory: {e}");
                })?;
                let dir = Self::node_index(key, &m).ok_or(TreeError::NotADirectory)?;
                if !m.node(dir).is_some_and(Node::is_dir) {
                    return Err(TreeError::NotADirectory);
                }
                for c in m.children(dir) {
                    let kind = if m.node(c).is_some_and(Node::is_dir) {
                        Kind::Dir
                    } else {
                        Kind::File
                    };
                    out.push(Entry {
                        name: m.name(c).to_vec(),
                        key: self.node_key(b, &m, c),
                        kind,
                    });
                }
            }
            Key::Latest(_) | Key::DateLink(_) => return Err(TreeError::NotADirectory),
        }
        Ok(out)
    }

    /// One child by name. `None` means "no such name here", which is
    /// distinct from the directory itself being unreadable.
    pub fn lookup(&self, parent: Key, name: &[u8]) -> Result<Option<Key>, TreeError> {
        let idx = &self.store.index;
        let name_str = String::from_utf8_lossy(name);
        Ok(match parent {
            Key::Root => name_str
                .parse::<u32>()
                .ok()
                .filter(|d| idx.depot(*d).is_some())
                .map(Key::Depot),
            Key::Depot(d) => match name_str.as_ref() {
                "latest" => idx.latest(d).map(|_| Key::Latest(d)),
                "by-date" => Some(Key::ByDate(d)),
                n => idx
                    .depot(d)
                    .and_then(|dep| dep.lookup_name(n))
                    .map(Key::Version),
            },
            Key::ByDate(d) => idx
                .depot(d)
                .and_then(|dep| dep.lookup_date_link(&name_str))
                .map(Key::DateLink),
            Key::Version(b) | Key::Node(b, _) => {
                let m = self.manifest(b).inspect_err(|e| {
                    tracing::warn!("looking up {name_str:?}: {e}");
                })?;
                let dir = Self::node_index(parent, &m).ok_or(TreeError::NotADirectory)?;
                m.child_by_name(dir, name).map(|c| self.node_key(b, &m, c))
            }
            Key::Latest(_) | Key::DateLink(_) => None,
        })
    }

    /// Where a file's bytes are. Only `Key::Node` can have any.
    pub fn locate(&self, key: Key) -> Result<Arc<FileLoc>, TreeError> {
        let Key::Node(b, idx) = key else {
            return Err(TreeError::NotFound);
        };
        let m = self.manifest(b)?;
        let n = m.node(idx).ok_or(TreeError::NotFound)?;
        if n.is_dir() {
            return Err(TreeError::NotFound);
        }
        Ok(self.store.locate(b, n.file_id)?)
    }

    pub fn read(&self, loc: &FileLoc, offset: u64, len: usize) -> Result<Vec<u8>, TreeError> {
        Ok(self.store.read(loc, offset, len)?)
    }

    /// Everything we know about a node, as name/value pairs. FUSE serves
    /// these as extended attributes; WinFsp does not serve them at all.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn xattrs(&self, key: Key) -> Vec<(&'static str, String)> {
        let idx = &self.store.index;
        let mut out = Vec::new();
        let blob_attrs = |out: &mut Vec<(&'static str, String)>, b: BlobId| {
            let e = idx.blob(b);
            out.push(("user.steam2.depot", e.depot.to_string()));
            out.push(("user.steam2.version", e.version.to_string()));
            out.push(("user.steam2.blob", e.file_name.clone()));
            if let Some(d) = e.date.and_then(|d| d.duration_since(UNIX_EPOCH).ok()) {
                out.push(("user.steam2.date", format_stamp(d.as_secs())));
            }
            if let Ok(p) = self.store.parsed(b) {
                out.push(("user.steam2.app_id", p.manifest.app_id.to_string()));
                out.push(("user.steam2.dat_crc", format!("{:08x}", p.meta.dat_crc)));
                if let Some((v, c)) = p.meta.prev {
                    out.push(("user.steam2.parent", format!("{v}-{c:08x}")));
                }
            }
        };
        match key {
            Key::Depot(d) => out.push(("user.steam2.depot", d.to_string())),
            Key::Version(b) => blob_attrs(&mut out, b),
            Key::Node(b, i) => {
                blob_attrs(&mut out, b);
                if let Ok(m) = self.manifest(b) {
                    if let Some(n) = m.node(i) {
                        out.push(("user.steam2.flags", format!("{:#06x}", n.flags)));
                        out.push(("user.steam2.flags_decoded", flags::describe(n.flags)));
                        if !n.is_dir() {
                            out.push(("user.steam2.file_id", n.file_id.to_string()));
                            if let Ok(loc) = self.store.locate(b, n.file_id) {
                                out.push(("user.steam2.mode", format!("{:?}", loc.record.mode)));
                                out.push((
                                    "user.steam2.source_version",
                                    idx.blob(loc.source).version.to_string(),
                                ));
                                out.push((
                                    "user.steam2.blocks",
                                    loc.record.num_blocks().to_string(),
                                ));
                                match loc.dat {
                                    Some(d) => {
                                        let de = idx.dat(d);
                                        out.push(("user.steam2.dat", de.path.clone()));
                                        out.push((
                                            "user.steam2.dat_offset",
                                            loc.record.offset.to_string(),
                                        ));
                                        if de.incomplete {
                                            out.push(("user.steam2.dat_incomplete", "1".into()));
                                        }
                                    }
                                    None => out.push(("user.steam2.dat", "missing".into())),
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        out
    }
}

trait NodeDefault {
    fn unwrap_or_default_node(self) -> Node;
}
impl NodeDefault for Option<Node> {
    fn unwrap_or_default_node(self) -> Node {
        self.unwrap_or(Node {
            name_offset: 0,
            count_or_size: 0,
            file_id: NO_NODE,
            flags: 0,
            parent: NO_NODE,
            next_sibling: NO_NODE,
            first_child: NO_NODE,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::backend::local::LocalBackend;
    use crate::index::Index;
    use crate::keys::KeyStore;
    use crate::store::{Store, StoreConfig};

    /// The sample dump, when this checkout has one (see `tests/cli.rs`).
    fn sample() -> Option<PathBuf> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../samples/dump");
        if p.join("blobs").is_dir() && p.join("dats").is_dir() {
            return Some(p);
        }
        eprintln!("skipping: no sample dump at {}", p.display());
        None
    }

    fn tree(root: &Path) -> Tree {
        let backend: Arc<dyn crate::backend::Backend> =
            Arc::new(LocalBackend::new(root.to_path_buf()).unwrap());
        let index = Index::load(&*backend).unwrap();
        Tree::new(Arc::new(Store::new(
            backend,
            index,
            KeyStore::new(),
            StoreConfig {
                blob_cache_dir: None,
                raw_cache_bytes: 8 << 20,
                block_cache_bytes: 8 << 20,
                verify: true,
                key_search: false,
            },
        )))
    }

    /// Every name a directory lists must be findable by that name, and land
    /// on the same key, all the way down a version's tree.
    #[test]
    fn listings_and_lookups_agree() {
        let Some(root) = sample() else { return };
        let tree = tree(&root);

        let mut stack = vec![Key::Root];
        let mut files = 0;
        let mut dirs = 0;
        while let Some(key) = stack.pop() {
            let Ok(entries) = tree.entries(key) else {
                continue;
            };
            dirs += 1;
            for e in entries {
                assert_eq!(
                    tree.lookup(key, &e.name).unwrap(),
                    Some(e.key),
                    "{:?} in {key:?} does not look up to itself",
                    String::from_utf8_lossy(&e.name)
                );
                let meta = tree.meta(e.key).unwrap();
                assert_eq!(meta.kind, e.kind);
                match e.kind {
                    Kind::Dir => stack.push(e.key),
                    Kind::File => files += 1,
                    Kind::Symlink => {
                        assert!(tree.link_target(e.key).is_some());
                    }
                }
                // Only `..` climbs out of a subtree, and we never list it.
                if !matches!(e.key, Key::Depot(_)) {
                    assert_ne!(tree.parent(e.key), e.key);
                }
            }
        }
        assert!(dirs > 1 && files > 0, "the sample dump listed nothing");
    }

    /// A file's bytes are the same read whole or in pieces.
    #[test]
    fn reads_are_stable_across_offsets() {
        let Some(root) = sample() else { return };
        let tree = tree(&root);

        // Depot 0 version 2 is the one `verify` is known to like.
        let blob = tree
            .store
            .index
            .depot(0)
            .and_then(|d| d.lookup_name("2"))
            .expect("sample depot 0 version 2");
        let mut stack = vec![Key::Version(blob)];
        let mut checked = 0;
        while let Some(key) = stack.pop() {
            for e in tree.entries(key).unwrap() {
                match e.kind {
                    Kind::Dir => stack.push(e.key),
                    Kind::File if checked < 4 => {
                        let Ok(loc) = tree.locate(e.key) else {
                            continue;
                        };
                        let size = loc.record.size.min(4096) as usize;
                        if size < 2 {
                            continue;
                        }
                        let whole = tree.read(&loc, 0, size).unwrap();
                        let head = tree.read(&loc, 0, size / 2).unwrap();
                        let tail = tree.read(&loc, size as u64 / 2, size - size / 2).unwrap();
                        assert_eq!(whole, [head, tail].concat());
                        checked += 1;
                    }
                    _ => {}
                }
            }
        }
        assert!(checked > 0, "no readable file in depot 0 version 2");
    }
}
