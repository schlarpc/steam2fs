use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::path::PathBuf;

use anyhow::Context;

use super::{Backend, DirEntry};

pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    pub fn new(root: PathBuf) -> anyhow::Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("resolving {}", root.display()))?;
        anyhow::ensure!(root.is_dir(), "{} is not a directory", root.display());
        Ok(Self { root })
    }

    fn path(&self, rel: &str) -> PathBuf {
        if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }
}

/// One positional read. Unix has `read_at`; Windows spells the same thing
/// `seek_read`, which moves the handle's own cursor as a side effect — we
/// open a fresh handle per read, so nothing else sees it.
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        file.seek_read(buf, offset)
    }
}

fn read_range(file: &File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = read_at(file, &mut buf[filled..], offset + filled as u64)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

impl Backend for LocalBackend {
    fn describe(&self) -> String {
        format!("local:{}", self.root.display())
    }

    fn list_dir(&self, rel: &str) -> anyhow::Result<Vec<DirEntry>> {
        let dir = self.path(rel);
        let mut out = Vec::new();
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))?
        {
            let entry = entry?;
            // Follow symlinks so a dump assembled from links reports real sizes.
            let meta = std::fs::metadata(entry.path())?;
            out.push(DirEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                size: meta.len(),
                is_dir: meta.is_dir(),
            });
        }
        Ok(out)
    }

    fn read_at(&self, rel: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let p = self.path(rel);
        let file = File::open(&p).with_context(|| format!("opening {}", p.display()))?;
        read_range(&file, offset, len).with_context(|| format!("reading {}", p.display()))
    }

    fn read_all(&self, rel: &str) -> anyhow::Result<Vec<u8>> {
        let p = self.path(rel);
        std::fs::read(&p).with_context(|| format!("reading {}", p.display()))
    }
}
