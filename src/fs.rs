//! The FUSE view.
//!
//! ```text
//! /<depot>/                      one directory per depot id
//! /<depot>/<version>/            the tree as of that version
//! /<depot>/<version>-<crc>/      when several blobs share a version number
//! /<depot>/latest -> <version>   symlink to the newest version
//! /<depot>/by-date/<timestamp>_<version> -> ../<version>
//! ```

// Sizes and offsets in this format are 32-bit on disk; the casts below are bounded by it.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyXattr, Request,
};
use parking_lot::{Mutex, RwLock};

use crate::format::manifest::{flags, Manifest, Node, NO_NODE};
use crate::index::{format_stamp, BlobId};
use crate::store::{FileLoc, ReadError, Store};

const TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
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

#[derive(Default)]
struct Inodes {
    by_key: HashMap<Key, u64>,
    keys: Vec<Key>,
}

impl Inodes {
    fn new() -> Self {
        let mut s = Self::default();
        s.intern(Key::Root); // inode 1
        s
    }
    fn intern(&mut self, key: Key) -> u64 {
        if let Some(&ino) = self.by_key.get(&key) {
            return ino;
        }
        let ino = self.keys.len() as u64 + 1;
        self.keys.push(key);
        self.by_key.insert(key, ino);
        ino
    }
    fn key(&self, ino: u64) -> Option<Key> {
        self.keys.get((ino as usize).checked_sub(1)?).copied()
    }
}

/// One directory's listing: (name, what it points at, kind).
type DirList = Arc<Vec<(OsString, Key, FileType)>>;

/// Listings built by `opendir`, so that paging through a big directory
/// does not rebuild it once per `readdir` call.
#[derive(Default)]
struct OpenDirs {
    next: u64,
    open: HashMap<u64, DirList>,
}

pub struct Steam2Fs {
    store: Arc<Store>,
    inodes: RwLock<Inodes>,
    dirs: Mutex<OpenDirs>,
    uid: u32,
    gid: u32,
}

fn errno(e: &ReadError) -> Errno {
    Errno::from_i32(e.errno())
}

impl Steam2Fs {
    pub fn new(store: Arc<Store>) -> Self {
        // SAFETY: getuid/getgid have no preconditions and cannot fail.
        #[allow(unsafe_code)]
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            store,
            inodes: RwLock::new(Inodes::new()),
            dirs: Mutex::new(OpenDirs::default()),
            uid,
            gid,
        }
    }

    fn ino(&self, key: Key) -> u64 {
        if let Some(&ino) = self.inodes.read().by_key.get(&key) {
            return ino;
        }
        self.inodes.write().intern(key)
    }

    fn key(&self, ino: INodeNo) -> Option<Key> {
        self.inodes.read().key(ino.0)
    }

    fn attr(&self, ino: u64, kind: FileType, size: u64, mtime: SystemTime) -> FileAttr {
        let perm = match kind {
            FileType::Directory => 0o555,
            FileType::Symlink => 0o777,
            _ => 0o444,
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 65536,
            flags: 0,
        }
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

    fn node_index(&self, key: Key, m: &Manifest) -> Option<u32> {
        match key {
            Key::Version(_) => Some(m.root()),
            Key::Node(_, idx) => Some(idx),
            _ => None,
        }
    }

    /// Attributes for a manifest node; file mtimes come from the version
    /// that last changed the file when its table is available.
    fn node_attr(&self, blob: BlobId, m: &Manifest, idx: u32) -> FileAttr {
        let ino = self.ino(self.node_key(blob, m, idx));
        let n = m.node(idx).copied().unwrap_or_default_node();
        if n.is_dir() {
            return self.attr(ino, FileType::Directory, 0, self.blob_date(blob));
        }
        let (size, mtime) = match self.store.locate(blob, n.file_id) {
            Ok(loc) => (loc.record.size, self.blob_date(loc.source)),
            Err(_) => (u64::from(n.count_or_size), self.blob_date(blob)),
        };
        self.attr(ino, FileType::RegularFile, size, mtime)
    }

    fn attr_for(&self, key: Key) -> Result<FileAttr, Errno> {
        let ino = self.ino(key);
        Ok(match key {
            Key::Root => self.attr(ino, FileType::Directory, 0, UNIX_EPOCH),
            Key::Depot(d) => {
                let latest = self.store.index.latest(d);
                let mtime = latest.map_or(UNIX_EPOCH, |b| self.blob_date(b));
                self.attr(ino, FileType::Directory, 0, mtime)
            }
            Key::ByDate(_) => self.attr(ino, FileType::Directory, 0, UNIX_EPOCH),
            Key::Latest(d) => {
                let target = self.store.index.latest(d).ok_or(Errno::ENOENT)?;
                let name = self
                    .store
                    .index
                    .depot(d)
                    .and_then(|x| x.name_of(target))
                    .unwrap_or("");
                self.attr(
                    ino,
                    FileType::Symlink,
                    name.len() as u64,
                    self.blob_date(target),
                )
            }
            Key::DateLink(b) => {
                let name = self
                    .store
                    .index
                    .depot(self.store.index.blob(b).depot)
                    .and_then(|x| x.name_of(b))
                    .unwrap_or("");
                // The target is `../<version>`.
                self.attr(
                    ino,
                    FileType::Symlink,
                    name.len() as u64 + 3,
                    self.blob_date(b),
                )
            }
            Key::Version(b) => self.attr(ino, FileType::Directory, 0, self.blob_date(b)),
            Key::Node(b, idx) => {
                let m = self.manifest(b).map_err(|e| errno(&e))?;
                self.node_attr(b, &m, idx)
            }
        })
    }

    fn locate(&self, key: Key) -> Result<(Arc<FileLoc>, Arc<Manifest>), ReadError> {
        let Key::Node(b, idx) = key else {
            return Err(ReadError::Other(anyhow::anyhow!("not a file")));
        };
        let m = self.manifest(b)?;
        let n = m.node(idx).ok_or(ReadError::MissingRecord(idx))?;
        Ok((self.store.locate(b, n.file_id)?, m))
    }

    /// The full listing of a directory, built once per `opendir`.
    fn dir_entries(&self, key: Key) -> Result<Vec<(OsString, Key, FileType)>, Errno> {
        let idx = &self.store.index;
        let mut entries: Vec<(OsString, Key, FileType)> = Vec::new();
        let parent_key = match key {
            Key::Root | Key::Depot(_) | Key::ByDate(_) | Key::Latest(_) | Key::DateLink(_) => {
                Key::Root
            }
            Key::Version(b) => Key::Depot(idx.blob(b).depot),
            Key::Node(b, i) => match self.manifest(b) {
                Ok(m) => m
                    .node(i)
                    .map_or(Key::Version(b), |n| self.node_key(b, &m, n.parent)),
                Err(_) => Key::Version(b),
            },
        };
        entries.push((".".into(), key, FileType::Directory));
        entries.push(("..".into(), parent_key, FileType::Directory));
        match key {
            Key::Root => {
                for (d, _) in idx.depots() {
                    entries.push((d.to_string().into(), Key::Depot(d), FileType::Directory));
                }
            }
            Key::Depot(d) => {
                if let Some(dep) = idx.depot(d) {
                    for (name, b) in dep.versions() {
                        entries.push((name.into(), Key::Version(b), FileType::Directory));
                    }
                    if idx.latest(d).is_some() {
                        entries.push(("latest".into(), Key::Latest(d), FileType::Symlink));
                    }
                    entries.push(("by-date".into(), Key::ByDate(d), FileType::Directory));
                }
            }
            Key::ByDate(d) => {
                if let Some(dep) = idx.depot(d) {
                    for (name, b) in dep.date_links() {
                        entries.push((name.into(), Key::DateLink(b), FileType::Symlink));
                    }
                }
            }
            Key::Version(b) | Key::Node(b, _) => {
                let m = self.manifest(b).map_err(|e| {
                    tracing::warn!("readdir: {e}");
                    errno(&e)
                })?;
                let dir = self.node_index(key, &m).ok_or(Errno::ENOTDIR)?;
                if !m.node(dir).is_some_and(Node::is_dir) {
                    return Err(Errno::ENOTDIR);
                }
                for c in m.children(dir) {
                    let kind = if m.node(c).is_some_and(Node::is_dir) {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    entries.push((
                        OsString::from_vec(m.name(c).to_vec()),
                        self.node_key(b, &m, c),
                        kind,
                    ));
                }
            }
            Key::Latest(_) | Key::DateLink(_) => return Err(Errno::ENOTDIR),
        }
        Ok(entries)
    }

    /// The listing for an open directory handle, rebuilt from the inode if
    /// the kernel reads a directory it did not open through us.
    fn dir_list(&self, ino: INodeNo, fh: FileHandle) -> Result<DirList, Errno> {
        if let Some(list) = self.dirs.lock().open.get(&fh.0) {
            return Ok(list.clone());
        }
        let key = self.key(ino).ok_or(Errno::ENOENT)?;
        Ok(Arc::new(self.dir_entries(key)?))
    }

    fn xattrs(&self, key: Key) -> Vec<(&'static str, String)> {
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
    fn unwrap_or_default_node(self) -> crate::format::manifest::Node;
}
impl NodeDefault for Option<crate::format::manifest::Node> {
    fn unwrap_or_default_node(self) -> crate::format::manifest::Node {
        self.unwrap_or(crate::format::manifest::Node {
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

impl Filesystem for Steam2Fs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(pkey) = self.key(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name_str = name.to_string_lossy();
        let idx = &self.store.index;
        let child = match pkey {
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
            Key::Version(_) | Key::Node(..) => {
                let blob = match pkey {
                    Key::Version(b) | Key::Node(b, _) => b,
                    _ => unreachable!(),
                };
                let m = match self.manifest(blob) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!("lookup: {e}");
                        reply.error(errno(&e));
                        return;
                    }
                };
                let Some(dir) = self.node_index(pkey, &m) else {
                    reply.error(Errno::ENOTDIR);
                    return;
                };
                m.child_by_name(dir, name.as_bytes())
                    .map(|c| self.node_key(blob, &m, c))
            }
            Key::Latest(_) | Key::DateLink(_) => None,
        };
        match child {
            Some(k) => match self.attr_for(k) {
                Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                Err(e) => reply.error(e),
            },
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self
            .key(ino)
            .ok_or(Errno::ENOENT)
            .and_then(|k| self.attr_for(k))
        {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let idx = &self.store.index;
        let target = match self.key(ino) {
            Some(Key::Latest(d)) => idx
                .latest(d)
                .and_then(|b| idx.depot(d).and_then(|x| x.name_of(b)))
                .map(str::to_string),
            Some(Key::DateLink(b)) => idx
                .depot(idx.blob(b).depot)
                .and_then(|x| x.name_of(b))
                .map(|n| format!("../{n}")),
            _ => None,
        };
        match target {
            Some(t) => reply.data(t.as_bytes()),
            None => reply.error(Errno::EINVAL),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let entries = match self.key(ino).ok_or(Errno::ENOENT).and_then(|k| self.dir_entries(k)) {
            Ok(e) => Arc::new(e),
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        let mut dirs = self.dirs.lock();
        dirs.next += 1;
        let fh = dirs.next;
        dirs.open.insert(fh, entries);
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let entries = match self.dir_list(ino, fh) {
            Ok(e) => e,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        for (i, (name, key, kind)) in entries.iter().enumerate().skip(offset as usize) {
            let ino = self.ino(*key);
            if reply.add(INodeNo(ino), i as u64 + 1, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectoryPlus,
    ) {
        let entries = match self.dir_list(ino, fh) {
            Ok(e) => e,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        for (i, (name, key, kind)) in entries.iter().enumerate().skip(offset as usize) {
            let ino = self.ino(*key);
            // An entry we listed should always have attributes; if it does
            // not, still show the name rather than dropping it from the
            // listing, and let a later stat report the error.
            let attr = self
                .attr_for(*key)
                .unwrap_or_else(|_| self.attr(ino, *kind, 0, UNIX_EPOCH));
            if reply.add(
                INodeNo(ino),
                i as u64 + 1,
                name,
                &TTL,
                &attr,
                Generation(0),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        self.dirs.lock().open.remove(&fh.0);
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.key(ino) {
            Some(Key::Node(..)) => reply.opened(FileHandle(0), FopenFlags::FOPEN_KEEP_CACHE),
            Some(_) => reply.error(Errno::EISDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let Some(key) = self.key(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let (loc, _m) = match self.locate(key) {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(ino = ino.0, "read: {e}");
                reply.error(errno(&e));
                return;
            }
        };
        match self.store.read(&loc, offset, size as usize) {
            Ok(data) => reply.data(&data),
            Err(e) => {
                tracing::warn!(file_id = loc.record.file_id, offset, "read: {e}");
                reply.error(errno(&e));
            }
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let Some(key) = self.key(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let wanted = name.to_string_lossy();
        // The kernel and tools ask for attributes in other namespaces
        // constantly (security.*, system.*); answering those without first
        // building every attribute we do serve saves parsing a blob and
        // building a file table per call.
        if !wanted.starts_with("user.steam2.") {
            reply.error(Errno::ENODATA);
            return;
        }
        match self.xattrs(key).into_iter().find(|(n, _)| *n == wanted) {
            Some((_, v)) => {
                if size == 0 {
                    reply.size(v.len() as u32);
                } else if v.len() as u32 <= size {
                    reply.data(v.as_bytes());
                } else {
                    reply.error(Errno::ERANGE);
                }
            }
            None => reply.error(Errno::ENODATA),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let Some(key) = self.key(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let mut buf = Vec::new();
        for (n, _) in self.xattrs(key) {
            buf.extend_from_slice(n.as_bytes());
            buf.push(0);
        }
        if size == 0 {
            reply.size(buf.len() as u32);
        } else if buf.len() as u32 <= size {
            reply.data(&buf);
        } else {
            reply.error(Errno::ERANGE);
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let files = self.store.index.blobs.len() as u64;
        reply.statfs(0, 0, 0, files, 0, 65536, 255, 65536);
    }
}
