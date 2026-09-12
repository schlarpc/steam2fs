//! SFTP backend driven through the system `ssh` binary (so `~/.ssh/config`,
//! agents and control masters all work as usual).

// Sizes and offsets in this format are 32-bit on disk; the casts below are bounded by it.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Context;
use bytes::BytesMut;
use futures_util::StreamExt;
use openssh::{KnownHosts, Session, SessionBuilder};
use openssh_sftp_client::file::File;
use openssh_sftp_client::{Sftp, SftpOptions};
use parking_lot::Mutex;
use tokio::io::AsyncSeekExt;
use tokio::runtime::Runtime;

use super::{Backend, DirEntry};

const HANDLE_CACHE: usize = 64;

pub struct SftpBackend {
    rt: Runtime,
    session: Arc<Session>,
    sftp: Arc<Sftp>,
    destination: String,
    root: String,
    handles: Mutex<lru::LruCache<String, File>>,
}

impl SftpBackend {
    pub fn connect(destination: &str, root: &str) -> anyhow::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (session, sftp) = rt.block_on(async {
            let session = Arc::new(
                SessionBuilder::default()
                    .known_hosts_check(KnownHosts::Add)
                    .connect(destination)
                    .await
                    .with_context(|| format!("ssh connect to {destination}"))?,
            );
            let sftp = Sftp::from_clonable_session(session.clone(), SftpOptions::default())
                .await
                .context("starting sftp subsystem")?;
            anyhow::Ok((session, sftp))
        })?;
        let root = root.trim_end_matches('/').to_string();
        Ok(Self {
            rt,
            session,
            sftp: Arc::new(sftp),
            destination: destination.to_string(),
            root,
            handles: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(HANDLE_CACHE).unwrap_or(NonZeroUsize::MIN),
            )),
        })
    }

    fn path(&self, rel: &str) -> String {
        if rel.is_empty() {
            if self.root.is_empty() {
                ".".into()
            } else {
                self.root.clone()
            }
        } else if self.root.is_empty() {
            rel.to_string()
        } else {
            format!("{}/{rel}", self.root)
        }
    }

    /// A `File` positioned nowhere in particular; clones share the remote
    /// handle but keep independent offsets.
    async fn handle(&self, rel: &str) -> anyhow::Result<File> {
        if let Some(f) = self.handles.lock().get(rel) {
            return Ok(f.clone());
        }
        let p = self.path(rel);
        let f = self
            .sftp
            .open(&p)
            .await
            .with_context(|| format!("sftp open {p}"))?;
        self.handles.lock().put(rel.to_string(), f.clone());
        Ok(f)
    }

    /// One round trip instead of one per few hundred entries: the dump's
    /// `blobs/` and `dats/` hold ~60k files each.
    async fn list_dir_via_find(&self, path: &str) -> anyhow::Result<Vec<DirEntry>> {
        let output = self
            .session
            .command("find")
            .arg("-L")
            .arg(path)
            .arg("-mindepth")
            .arg("1")
            .arg("-maxdepth")
            .arg("1")
            .arg("-printf")
            .arg("%y\t%s\t%f\n")
            .output()
            .await?;
        anyhow::ensure!(
            output.status.success(),
            "find exited with {}",
            output.status
        );
        let text = String::from_utf8_lossy(&output.stdout);
        let mut out = Vec::new();
        for line in text.lines() {
            let mut it = line.splitn(3, '\t');
            let (Some(ty), Some(size), Some(name)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            out.push(DirEntry {
                name: name.to_string(),
                size: size.parse().unwrap_or(0),
                is_dir: ty == "d",
            });
        }
        Ok(out)
    }

    async fn read_range(&self, rel: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let mut f = self.handle(rel).await?;
        f.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut out = BytesMut::with_capacity(len);
        while out.len() < len {
            let want = (len - out.len()).min(u32::MAX as usize) as u32;
            match f.read(want, out.split_off(out.len())).await? {
                Some(chunk) => {
                    if chunk.is_empty() {
                        break;
                    }
                    out.unsplit(chunk);
                }
                None => break,
            }
        }
        Ok(out.to_vec())
    }
}

impl Backend for SftpBackend {
    fn describe(&self) -> String {
        format!("sftp:{}:{}", self.destination, self.root)
    }

    fn list_dir(&self, rel: &str) -> anyhow::Result<Vec<DirEntry>> {
        let p = self.path(rel);
        match self.rt.block_on(self.list_dir_via_find(&p)) {
            Ok(v) => return Ok(v),
            Err(e) => tracing::debug!("remote find failed ({e:#}); falling back to sftp readdir"),
        }
        self.rt.block_on(async {
            let mut fs = self.sftp.fs();
            let dir = fs
                .open_dir(&p)
                .await
                .with_context(|| format!("sftp opendir {p}"))?;
            let mut stream = std::pin::pin!(dir.read_dir());
            let mut out = Vec::new();
            while let Some(entry) = stream.next().await {
                let entry = entry.with_context(|| format!("sftp readdir {p}"))?;
                let name = entry.filename().to_string_lossy().into_owned();
                if name == "." || name == ".." {
                    continue;
                }
                let meta = entry.metadata();
                out.push(DirEntry {
                    name,
                    size: meta.len().unwrap_or(0),
                    is_dir: meta.file_type().is_some_and(|t| t.is_dir()),
                });
            }
            Ok(out)
        })
    }

    fn read_at(&self, rel: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        self.rt
            .block_on(self.read_range(rel, offset, len))
            .with_context(|| format!("sftp read {rel}@{offset}+{len}"))
    }

    fn read_all(&self, rel: &str) -> anyhow::Result<Vec<u8>> {
        let p = self.path(rel);
        self.rt.block_on(async {
            let mut fs = self.sftp.fs();
            let data = fs
                .read(&p)
                .await
                .with_context(|| format!("sftp read {p}"))?;
            Ok(data.to_vec())
        })
    }
}
