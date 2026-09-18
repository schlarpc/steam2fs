//! Where the dump's bytes come from. Everything above this layer only ever
//! lists directories and reads byte ranges, so a backend can be a local
//! directory, an SFTP host, or anything else with random access.

pub mod local;
pub mod sftp;

use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

pub trait Backend: Send + Sync {
    /// Human-readable description for logs.
    fn describe(&self) -> String;

    /// List one directory, relative to the dump root (`""` for the root).
    fn list_dir(&self, rel: &str) -> anyhow::Result<Vec<DirEntry>>;

    /// Read up to `len` bytes at `offset`. Short reads only happen at EOF.
    fn read_at(&self, rel: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>>;

    /// Read a whole (small) file.
    fn read_all(&self, rel: &str) -> anyhow::Result<Vec<u8>>;
}

/// How a source string was interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Local(PathBuf),
    /// `destination` is what `ssh` accepts: `host`, `user@host`, `ssh://user@host:port`.
    Sftp {
        destination: String,
        path: String,
    },
}

/// Accepts a local path, `sftp://[user@]host[:port]/abs/path`, or the scp
/// style `[user@]host:/path`. A string naming an existing local path is
/// always treated as local.
pub fn parse_source(s: &str) -> Source {
    if std::path::Path::new(s).exists() {
        return Source::Local(PathBuf::from(s));
    }
    if let Some(rest) = s.strip_prefix("sftp://") {
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        return Source::Sftp {
            destination: format!("ssh://{host}"),
            path: path.to_string(),
        };
    }
    if let Some((host, path)) = s.split_once(':') {
        if !host.is_empty() && !host.contains('/') {
            return Source::Sftp {
                destination: host.to_string(),
                path: if path.is_empty() {
                    ".".into()
                } else {
                    path.to_string()
                },
            };
        }
    }
    Source::Local(PathBuf::from(s))
}

pub fn open(source: &Source) -> anyhow::Result<Arc<dyn Backend>> {
    Ok(match source {
        Source::Local(p) => Arc::new(local::LocalBackend::new(p.clone())?),
        Source::Sftp { destination, path } => {
            Arc::new(sftp::SftpBackend::connect(destination, path)?)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sources() {
        assert_eq!(
            parse_source("example-host:/mnt/x"),
            Source::Sftp {
                destination: "example-host".into(),
                path: "/mnt/x".into()
            }
        );
        assert_eq!(
            parse_source("sftp://me@host:2222/data"),
            Source::Sftp {
                destination: "ssh://me@host:2222".into(),
                path: "/data".into()
            }
        );
        assert_eq!(
            parse_source("/definitely/not/here"),
            Source::Local("/definitely/not/here".into())
        );
        assert_eq!(parse_source("/"), Source::Local("/".into()));
    }
}
