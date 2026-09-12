//! The FUSE view of [`crate::tree`].

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

use crate::store::{ErrorClass, Store};
use crate::tree::{Key, Kind, Meta, Tree, TreeError};

const TTL: Duration = Duration::from_secs(3600);

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
    tree: Tree,
    inodes: RwLock<Inodes>,
    dirs: Mutex<OpenDirs>,
    uid: u32,
    gid: u32,
}

fn errno(e: &TreeError) -> Errno {
    Errno::from_i32(match e {
        TreeError::NotFound => libc::ENOENT,
        TreeError::NotADirectory => libc::ENOTDIR,
        TreeError::Read(r) => match r.class() {
            ErrorClass::Missing => libc::ENXIO,
            ErrorClass::NoKey => libc::ENOKEY,
            ErrorClass::Io => libc::EIO,
            ErrorClass::BadData => libc::EBADMSG,
        },
    })
}

fn file_type(kind: Kind) -> FileType {
    match kind {
        Kind::Dir => FileType::Directory,
        Kind::File => FileType::RegularFile,
        Kind::Symlink => FileType::Symlink,
    }
}

impl Steam2Fs {
    pub fn new(store: Arc<Store>) -> Self {
        // SAFETY: getuid/getgid have no preconditions and cannot fail.
        #[allow(unsafe_code)]
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            tree: Tree::new(store),
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

    fn attr_of(&self, key: Key, meta: &Meta) -> FileAttr {
        self.attr(self.ino(key), file_type(meta.kind), meta.size, meta.mtime)
    }

    fn attr_for(&self, key: Key) -> Result<FileAttr, Errno> {
        let meta = self.tree.meta(key).map_err(|e| errno(&e))?;
        Ok(self.attr_of(key, &meta))
    }

    /// The full listing of a directory, built once per `opendir`.
    fn dir_entries(&self, key: Key) -> Result<Vec<(OsString, Key, FileType)>, Errno> {
        let children = self.tree.entries(key).map_err(|e| errno(&e))?;
        let mut entries = Vec::with_capacity(children.len() + 2);
        entries.push((".".into(), key, FileType::Directory));
        entries.push(("..".into(), self.tree.parent(key), FileType::Directory));
        entries.extend(
            children
                .into_iter()
                .map(|e| (OsString::from_vec(e.name), e.key, file_type(e.kind))),
        );
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
}

impl Filesystem for Steam2Fs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(pkey) = self.key(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.tree.lookup(pkey, name.as_bytes()) {
            Ok(Some(k)) => match self.attr_for(k) {
                Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                Err(e) => reply.error(e),
            },
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => reply.error(errno(&e)),
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
        match self.key(ino).and_then(|k| self.tree.link_target(k)) {
            Some(t) => reply.data(t.as_bytes()),
            None => reply.error(Errno::EINVAL),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let entries = match self
            .key(ino)
            .ok_or(Errno::ENOENT)
            .and_then(|k| self.dir_entries(k))
        {
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
            if reply.add(INodeNo(ino), i as u64 + 1, name, &TTL, &attr, Generation(0)) {
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
        let loc = match self.tree.locate(key) {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(ino = ino.0, "read: {e}");
                reply.error(errno(&e));
                return;
            }
        };
        match self.tree.read(&loc, offset, size as usize) {
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
        match self
            .tree
            .xattrs(key)
            .into_iter()
            .find(|(n, _)| *n == wanted)
        {
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
        for (n, _) in self.tree.xattrs(key) {
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
        let files = self.tree.store.index.blobs.len() as u64;
        reply.statfs(0, 0, 0, files, 0, 65536, 255, 65536);
    }
}
