//! SFTP backend, speaking SSH itself rather than driving the system `ssh`.
//!
//! `~/.ssh/config` is read for the host (including `ProxyCommand` and the
//! identity files), the agent is used when one is running, and host keys are
//! checked against `known_hosts`. This works the same way on Windows, where
//! there is no control-master socket to rely on.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context as _};
use parking_lot::Mutex;
use russh::client::{self, Handle};
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh_sftp::client::rawsession::RawSftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::runtime::Runtime;

use super::{Backend, DirEntry};

/// Open remote file handles to keep around. The dump is read in small
/// windows all over a handful of dats, so re-opening per read would cost a
/// round trip every time.
const HANDLE_CACHE: usize = 64;

/// The largest SFTP read we will ask for in one packet. Servers commonly cap
/// a single read at 256 KiB; anything bigger comes back short.
const MAX_READ: usize = 64 * 1024;

/// How long to let one request wait for its answer. This is queueing time,
/// not just service time, so it is generous.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// How many of those to keep in flight at once. The store's window is a
/// megabyte, so this covers a whole window in one round trip's worth of
/// waiting.
const MAX_IN_FLIGHT: usize = 16;

/// Accepts whatever host key the server presents if `known_hosts` has
/// nothing to say, and refuses one that disagrees with what is recorded.
struct ClientHandler {
    host: String,
    port: u16,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            // Certificates would need the CA to be configured; we do not
            // read that part of the config.
            tracing::warn!("server offered a certificate host key; refusing");
            return Ok(false);
        };
        match russh::keys::check_known_hosts(&self.host, self.port, key) {
            Ok(true) => Ok(true),
            Ok(false) => {
                tracing::error!(
                    host = self.host,
                    "server host key does not match known_hosts; refusing"
                );
                Ok(false)
            }
            Err(russh::keys::Error::KeyChanged { line }) => {
                tracing::error!(
                    host = self.host,
                    line,
                    "server host key changed since known_hosts was written; refusing"
                );
                Ok(false)
            }
            Err(e) => {
                // No known_hosts entry (or no file at all): accept, and say
                // so, rather than making the dump unreadable.
                tracing::warn!(host = self.host, "accepting unverified host key ({e})");
                Ok(true)
            }
        }
    }
}

/// `Signer` over a running agent, so keys that never leave it can still
/// authenticate us.
struct AgentSigner<S: AgentStream + Send + Unpin>(AgentClient<S>);

#[derive(Debug, thiserror::Error)]
enum AgentSignError {
    #[error(transparent)]
    Send(#[from] russh::SendError),
    #[error(transparent)]
    Agent(#[from] russh::keys::Error),
}

impl<S: AgentStream + Send + Unpin> russh::Signer for AgentSigner<S> {
    type Error = AgentSignError;

    async fn auth_sign(
        &mut self,
        key: &russh::keys::agent::AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.0.sign_request(key, hash_alg, to_sign).await?)
    }
}

pub struct SftpBackend {
    rt: Runtime,
    ssh: Handle<ClientHandler>,
    sftp: Arc<RawSftpSession>,
    destination: String,
    root: String,
    /// Remote path -> open file handle.
    handles: Mutex<lru::LruCache<String, Arc<str>>>,
}

/// `host`, `user@host`, or `ssh://[user@]host[:port]`.
fn split_destination(destination: &str) -> (Option<String>, String, Option<u16>) {
    let rest = destination
        .strip_prefix("ssh://")
        .unwrap_or(destination)
        .to_string();
    let (user, hostport) = match rest.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, rest),
    };
    match hostport.rsplit_once(':') {
        Some((h, p)) => match p.parse() {
            Ok(port) => (user, h.to_string(), Some(port)),
            Err(_) => (user, hostport, None),
        },
        None => (user, hostport, None),
    }
}

/// The identity files to try when the agent has nothing.
fn identity_files(cfg: &russh_config::Config) -> Vec<PathBuf> {
    if let Some(files) = &cfg.host_config.identity_file {
        if !files.is_empty() {
            return files.clone();
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let Some(home) = home else {
        return Vec::new();
    };
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|n| home.join(".ssh").join(n))
        .filter(|p| p.exists())
        .collect()
}

/// Every agent we know how to reach on this platform.
async fn agent_client() -> Option<AgentClient<Box<dyn AgentStream + Send + Unpin>>> {
    #[cfg(unix)]
    {
        match AgentClient::connect_env().await {
            Ok(a) => return Some(a.dynamic()),
            Err(e) => tracing::debug!("no ssh agent: {e}"),
        }
    }
    #[cfg(windows)]
    {
        match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            Ok(a) => return Some(a.dynamic()),
            Err(e) => tracing::debug!("no OpenSSH agent pipe: {e}"),
        }
        match AgentClient::connect_pageant().await {
            Ok(a) => return Some(a.dynamic()),
            Err(e) => tracing::debug!("no Pageant: {e}"),
        }
    }
    None
}

async fn authenticate(
    ssh: &mut Handle<ClientHandler>,
    user: &str,
    cfg: &russh_config::Config,
) -> anyhow::Result<()> {
    if let Some(agent) = agent_client().await {
        let mut signer = AgentSigner(agent);
        let identities = signer
            .0
            .request_identities()
            .await
            .context("listing agent identities")?;
        tracing::debug!("agent offers {} identities", identities.len());
        for id in identities {
            let russh::keys::agent::AgentIdentity::PublicKey { key, comment } = &id else {
                continue;
            };
            let key = key.clone();
            match ssh
                .authenticate_publickey_with(user, key, None, &mut signer)
                .await
            {
                Ok(r) if r.success() => {
                    tracing::debug!("authenticated with agent key {comment:?}");
                    return Ok(());
                }
                Ok(_) => tracing::debug!("agent key {comment:?} rejected"),
                Err(e) => tracing::debug!("agent key {comment:?} failed: {e}"),
            }
        }
    }

    for path in identity_files(cfg) {
        let key = match russh::keys::load_secret_key(&path, None) {
            Ok(k) => k,
            Err(e) => {
                tracing::debug!("cannot use {}: {e}", path.display());
                continue;
            }
        };
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha512));
        match ssh.authenticate_publickey(user, key).await {
            Ok(r) if r.success() => {
                tracing::debug!("authenticated with {}", path.display());
                return Ok(());
            }
            Ok(_) => tracing::debug!("{} rejected", path.display()),
            Err(e) => tracing::debug!("{} failed: {e}", path.display()),
        }
    }

    Err(anyhow!(
        "no ssh key was accepted (tried the agent and {:?}); \
         steam2fs does not prompt for passwords",
        identity_files(cfg)
    ))
}

impl SftpBackend {
    pub fn connect(destination: &str, root: &str) -> anyhow::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (user, host, port) = split_destination(destination);
        let (ssh, sftp) = rt.block_on(async {
            let mut cfg = russh_config::parse_home(&host)
                .unwrap_or_else(|_| russh_config::Config::default(&host));
            if user.is_some() {
                cfg.user = user;
            }
            if port.is_some() {
                cfg.port = port;
            }
            let user = cfg.user();
            let stream = cfg
                .stream()
                .await
                .with_context(|| format!("connecting to {}:{}", cfg.host(), cfg.port()))?;

            // A mount can sit idle for hours between reads, so keep the
            // connection alive, and do not wait on Nagle for the small
            // random reads the store makes.
            let config = Arc::new(client::Config {
                keepalive_interval: Some(std::time::Duration::from_secs(60)),
                keepalive_max: 3,
                nodelay: true,
                ..client::Config::default()
            });
            let handler = ClientHandler {
                host: cfg.host().to_string(),
                port: cfg.port(),
            };
            let mut ssh = client::connect_stream(config, stream, handler)
                .await
                .with_context(|| format!("ssh handshake with {}", cfg.host()))?;
            authenticate(&mut ssh, &user, &cfg)
                .await
                .with_context(|| format!("authenticating to {}@{}", user, cfg.host()))?;

            let channel = ssh
                .channel_open_session()
                .await
                .context("opening a session channel")?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .context("requesting the sftp subsystem")?;
            let sftp = RawSftpSession::new(channel.into_stream());
            sftp.init().await.context("sftp handshake")?;
            // Several mount threads read at once and each read is pipelined,
            // so a request can sit in the queue for a while before the server
            // gets to it. The default ten seconds turns that queueing delay
            // into spurious read errors.
            sftp.set_timeout(REQUEST_TIMEOUT.as_secs());
            anyhow::Ok((ssh, Arc::new(sftp)))
        })?;

        Ok(Self {
            rt,
            ssh,
            sftp,
            destination: destination.to_string(),
            root: root.trim_end_matches('/').to_string(),
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

    /// An open handle for `rel`, opening one if the cache has none. Evicting
    /// a handle closes it, so a long mount over many dats does not leave the
    /// server holding thousands of open files.
    async fn handle(&self, rel: &str) -> anyhow::Result<Arc<str>> {
        if let Some(h) = self.handles.lock().get(rel) {
            return Ok(h.clone());
        }
        let p = self.path(rel);
        let opened = self
            .sftp
            .open(p.clone(), OpenFlags::READ, FileAttributes::default())
            .await
            .with_context(|| format!("sftp open {p}"))?;
        let handle: Arc<str> = Arc::from(opened.handle.as_str());
        let evicted = self
            .handles
            .lock()
            .push(rel.to_string(), handle.clone())
            .filter(|(key, _)| key != rel)
            .map(|(_, old)| old);
        if let Some(old) = evicted {
            if let Err(e) = self.sftp.close(old.to_string()).await {
                tracing::debug!("closing an evicted sftp handle: {e}");
            }
        }
        Ok(handle)
    }

    /// One round trip instead of one per few hundred entries: the dump's
    /// `blobs/` and `dats/` hold ~60k files each.
    async fn list_dir_via_find(&self, path: &str) -> anyhow::Result<Vec<DirEntry>> {
        let mut channel = self.ssh.channel_open_session().await?;
        let quoted = format!("'{}'", path.replace('\'', r"'\''"));
        channel
            .exec(
                true,
                format!("find -L {quoted} -mindepth 1 -maxdepth 1 -printf '%y\\t%s\\t%f\\n'"),
            )
            .await?;
        let mut stdout = Vec::new();
        let mut status = None;
        // Read until the channel closes rather than stopping at EOF: the
        // exit status can arrive on either side of it.
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        anyhow::ensure!(status == Some(0), "remote find exited with {status:?}");
        let text = String::from_utf8_lossy(&stdout);
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

    async fn list_dir_via_sftp(&self, path: &str) -> anyhow::Result<Vec<DirEntry>> {
        let dir = self
            .sftp
            .opendir(path.to_string())
            .await
            .with_context(|| format!("sftp opendir {path}"))?
            .handle;
        let mut out = Vec::new();
        loop {
            match self.sftp.readdir(dir.as_str()).await {
                Ok(name) => {
                    for f in name.files {
                        if f.filename == "." || f.filename == ".." {
                            continue;
                        }
                        out.push(DirEntry {
                            name: f.filename,
                            size: f.attrs.size.unwrap_or(0),
                            is_dir: f.attrs.is_dir(),
                        });
                    }
                }
                Err(russh_sftp::client::error::Error::Status(s))
                    if s.status_code == StatusCode::Eof =>
                {
                    break
                }
                Err(e) => {
                    let _ = self.sftp.close(dir).await;
                    return Err(anyhow!("sftp readdir {path}: {e}"));
                }
            }
        }
        let _ = self.sftp.close(dir).await;
        Ok(out)
    }

    /// Read `len` bytes at `offset`, in flight together.
    ///
    /// The store asks for a megabyte at a time, which is 16 packets: sending
    /// them one after another costs 16 round trips, and on a link with any
    /// latency at all that, not the bandwidth, is what you wait for. The
    /// protocol tags every request with an id, so they can all be outstanding
    /// at once and sorted out on arrival.
    async fn read_range(&self, rel: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let handle = self.handle(rel).await?;
        let mut out: Vec<u8> = Vec::with_capacity(len);
        'batches: while out.len() < len {
            let base = offset + out.len() as u64;
            let remaining = len - out.len();
            let wants: Vec<(u64, usize)> = (0..MAX_IN_FLIGHT)
                .map(|i| i * MAX_READ)
                .take_while(|start| *start < remaining)
                .map(|start| (base + start as u64, MAX_READ.min(remaining - start)))
                .collect();

            let replies = futures_util::future::join_all(
                wants
                    .iter()
                    .map(|(at, want)| self.sftp.read(handle.to_string(), *at, *want as u32)),
            )
            .await;

            // Strictly in order: a server may answer any read with fewer
            // bytes than asked for, and the replies after a short one cover
            // a range we have not filled yet, so they are dropped and the
            // outer loop asks again from where we got to. Only an empty
            // answer or an EOF status means the file has ended.
            for (reply, (at, want)) in replies.into_iter().zip(&wants) {
                match reply {
                    Ok(data) if data.data.is_empty() => break 'batches,
                    Ok(data) => {
                        let short = data.data.len() < *want;
                        out.extend_from_slice(&data.data);
                        if short {
                            tracing::debug!(
                                at,
                                want,
                                got = data.data.len(),
                                "short sftp read; asking again from there"
                            );
                            break;
                        }
                    }
                    // Reading at or past the end is an EOF status, not an
                    // empty data packet.
                    Err(russh_sftp::client::error::Error::Status(s))
                        if s.status_code == StatusCode::Eof =>
                    {
                        break 'batches
                    }
                    Err(e) => return Err(anyhow!("sftp read: {e}")),
                }
            }
        }
        Ok(out)
    }
}

impl Backend for SftpBackend {
    fn describe(&self) -> String {
        format!("sftp:{}:{}", self.destination, self.root)
    }

    fn list_dir(&self, rel: &str) -> anyhow::Result<Vec<DirEntry>> {
        let p = self.path(rel);
        self.rt.block_on(async {
            match self.list_dir_via_find(&p).await {
                Ok(v) => Ok(v),
                Err(e) => {
                    tracing::debug!("remote find failed ({e:#}); falling back to sftp readdir");
                    self.list_dir_via_sftp(&p).await
                }
            }
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
            let attrs = self
                .sftp
                .stat(p.clone())
                .await
                .with_context(|| format!("sftp stat {p}"))?;
            let size = attrs.attrs.size.unwrap_or(0);
            self.read_range(rel, 0, size as usize).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_split_into_user_host_port() {
        assert_eq!(split_destination("example"), (None, "example".into(), None));
        assert_eq!(
            split_destination("me@example"),
            (Some("me".into()), "example".into(), None)
        );
        assert_eq!(
            split_destination("ssh://me@example:2222"),
            (Some("me".into()), "example".into(), Some(2222))
        );
        // A trailing colon that is not a port stays part of the host.
        assert_eq!(
            split_destination("example:notaport"),
            (None, "example:notaport".into(), None)
        );
    }
}
