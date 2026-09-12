//! steam2fs: a read-only, time-travelling FUSE view over a Steam2 content
//! server dump (blob + dat files), served straight from the archive without
//! extracting anything.

// Manifest node indices are u32 on disk.
#![allow(clippy::cast_possible_truncation)]

mod backend;
mod cache;
mod format;
mod fs;
mod index;
mod keys;
mod store;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};

use crate::index::Index;
use crate::keys::KeyStore;
use crate::store::{Store, StoreConfig};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct SourceArgs {
    /// Dump root: a local directory, `host:/path`, or `sftp://[user@]host[:port]/path`.
    /// It must contain `blobs/` and `dats/` (and ideally `blobs_dates.txt`).
    source: String,

    /// Directory for cached blob files (content-addressed, safe to share).
    /// Defaults to `$XDG_CACHE_HOME/steam2fs/blobs`; `--no-blob-cache` disables it.
    #[arg(long, env = "STEAM2FS_CACHE_DIR")]
    cache_dir: Option<PathBuf>,

    #[arg(long)]
    no_blob_cache: bool,

    /// Extra depot key as `DEPOT=32-hex-digits`; repeatable.
    #[arg(long = "key", value_name = "DEPOT=HEX")]
    keys: Vec<String>,

    /// File of `DEPOT=HEX` lines.
    #[arg(long, value_name = "FILE")]
    keys_file: Option<PathBuf>,

    /// Skip per-block checksum verification (faster, but incomplete
    /// downloads then read as garbage instead of failing).
    #[arg(long)]
    no_verify: bool,

    /// When a depot's key fails to decrypt a blob, don't try every other
    /// known key against it.
    #[arg(long)]
    no_key_search: bool,

    /// Cache of raw dat bytes, in MiB.
    #[arg(long, default_value_t = 256)]
    raw_cache_mb: usize,

    /// Cache of decoded blocks, in MiB.
    #[arg(long, default_value_t = 256)]
    block_cache_mb: usize,
}

#[derive(Subcommand)]
enum Command {
    /// Mount the dump.
    Mount {
        #[command(flatten)]
        source: SourceArgs,
        mountpoint: PathBuf,
        /// Let other users access the mount (needs `user_allow_other` in /etc/fuse.conf).
        #[arg(long)]
        allow_other: bool,
        /// FUSE worker threads.
        #[arg(long, default_value_t = 4)]
        threads: usize,
    },
    /// Print what is known about a depot, or one version of it.
    Inspect {
        #[command(flatten)]
        source: SourceArgs,
        depot: u32,
        /// Version directory name, e.g. `12` or `18-ef45a233`.
        version: Option<String>,
        /// Also list every file with its location.
        #[arg(long)]
        files: bool,
    },
    /// Read every block of one version and report checksum failures.
    Verify {
        #[command(flatten)]
        source: SourceArgs,
        depot: u32,
        version: String,
    },
    /// Check which encrypted blobs the known keys actually decrypt, trying
    /// every key where the depot's own fails. Writes discovered keys as
    /// `DEPOT@CRC=HEX` lines usable with `--keys-file`.
    KeyAudit {
        #[command(flatten)]
        source: SourceArgs,
        /// Only this depot.
        #[arg(long)]
        depot: Option<u32>,
        /// Where to write discovered keys (appended).
        #[arg(long, default_value = "discovered-keys.txt")]
        out: PathBuf,
        /// Parallel workers.
        #[arg(long, default_value_t = 8)]
        jobs: usize,
    },
}

fn open_store(args: &SourceArgs) -> anyhow::Result<Arc<Store>> {
    let source = backend::parse_source(&args.source);
    tracing::info!(?source, "opening backend");
    let backend = backend::open(&source)?;
    let index = Index::load(&*backend).context("indexing the dump")?;

    let mut keys = KeyStore::new();
    if let Some(f) = &args.keys_file {
        keys.load_file(f)
            .with_context(|| format!("loading {}", f.display()))?;
    }
    for spec in &args.keys {
        keys.insert_spec(spec)?;
    }

    let blob_cache_dir = if args.no_blob_cache {
        None
    } else {
        Some(match &args.cache_dir {
            Some(d) => d.clone(),
            None => {
                let base = std::env::var_os("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
                    .context("no XDG_CACHE_HOME or HOME; pass --cache-dir")?;
                base.join("steam2fs").join("blobs")
            }
        })
    };
    if let Some(d) = &blob_cache_dir {
        std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
    }

    Ok(Arc::new(Store::new(
        backend,
        index,
        keys,
        StoreConfig {
            blob_cache_dir,
            raw_cache_bytes: args.raw_cache_mb << 20,
            block_cache_bytes: args.block_cache_mb << 20,
            verify: !args.no_verify,
            key_search: !args.no_key_search,
        },
    )))
}

fn resolve_version(store: &Store, depot: u32, version: &str) -> anyhow::Result<index::BlobId> {
    let dep = store
        .index
        .depot(depot)
        .with_context(|| format!("depot {depot} is not in the dump"))?;
    dep.lookup_name(version)
        .with_context(|| format!("depot {depot} has no version {version:?}"))
}

fn inspect(store: &Store, depot: u32, version: Option<String>, files: bool) -> anyhow::Result<()> {
    let idx = &store.index;
    let dep = idx
        .depot(depot)
        .with_context(|| format!("depot {depot} is not in the dump"))?;
    println!(
        "depot {depot}: {} blobs, key {}",
        dep.blobs.len(),
        if store.key_for(depot).is_some() {
            "known"
        } else {
            "UNKNOWN"
        }
    );
    let Some(version) = version else {
        for (name, b) in dep.versions() {
            let e = idx.blob(b);
            let date = e
                .date
                .and_then(|d| d.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or("-".into(), |d| index::format_stamp(d.as_secs()));
            let dat = store.parsed(b).ok().map(|p| {
                match idx.find_dat(depot, e.version, p.meta.dat_crc) {
                    Some(d) => {
                        let de = idx.dat(d);
                        format!(
                            "dat {} bytes{}",
                            de.size,
                            if de.incomplete { " (incomplete)" } else { "" }
                        )
                    }
                    None => format!("dat {:08x} MISSING", p.meta.dat_crc),
                }
            });
            println!(
                "  {name:<14} {date}  {}",
                dat.unwrap_or_else(|| "(blob unreadable)".into())
            );
        }
        return Ok(());
    };
    let id = resolve_version(store, depot, &version)?;
    let chain = store.chain(id)?;
    println!("chain ({} versions, root first):", chain.len());
    for b in &chain {
        let e = idx.blob(*b);
        let p = store.parsed(*b)?;
        let dat = idx.find_dat(depot, e.version, p.meta.dat_crc);
        println!(
            "  v{:<5} blob {:08x} prev {:<16} dat {:08x} {:<10} manifest app {} ver {} nodes {} records {}",
            e.version,
            e.crc,
            p.meta.prev.map_or("-".into(), |(v, c)| format!("{v}-{c:08x}")),
            p.meta.dat_crc,
            match dat {
                Some(d) if idx.dat(d).incomplete => "incomplete",
                Some(_) => "ok",
                None => "MISSING",
            },
            p.manifest.app_id,
            p.manifest.version_id,
            p.manifest.nodes().len(),
            p.records.len(),
        );
    }
    let table = store.table(id)?;
    let parsed = store.parsed(id)?;
    let m = &parsed.manifest;
    let file_nodes = m.nodes().iter().filter(|n| !n.is_dir()).count();
    let located = m
        .nodes()
        .iter()
        .filter(|n| !n.is_dir() && table.contains(n.file_id))
        .count();
    let readable = m
        .nodes()
        .iter()
        .filter(|n| !n.is_dir())
        .filter(|n| table.get(n.file_id).is_some_and(|l| l.dat.is_some()))
        .count();
    println!("version {version}: {file_nodes} files, {located} with records, {readable} with a dat present");
    if files {
        for (i, n) in m.nodes().iter().enumerate() {
            if n.is_dir() {
                continue;
            }
            let path = String::from_utf8_lossy(&m.path(i as u32)).into_owned();
            match table.get(n.file_id) {
                Some(loc) => println!(
                    "  {path}  id {} {:?} {} bytes, {} blocks, from v{} {}",
                    n.file_id,
                    loc.record.mode,
                    loc.record.size,
                    loc.record.num_blocks(),
                    idx.blob(loc.source).version,
                    if loc.dat.is_some() {
                        ""
                    } else {
                        "(dat missing)"
                    }
                ),
                None => println!("  {path}  id {} NO RECORD", n.file_id),
            }
        }
    }
    Ok(())
}

fn verify(store: &Store, depot: u32, version: &str) -> anyhow::Result<()> {
    let id = resolve_version(store, depot, version)?;
    let table = store.table(id)?;
    let m = store.parsed(id)?.manifest.clone();
    let (mut files, mut blocks, mut failed) = (0usize, 0usize, 0usize);
    for (i, n) in m.nodes().iter().enumerate() {
        if n.is_dir() {
            continue;
        }
        files += 1;
        let path = String::from_utf8_lossy(&m.path(i as u32)).into_owned();
        let Some(loc) = table.get(n.file_id) else {
            println!("NO RECORD  {path}");
            failed += 1;
            continue;
        };
        for b in 0..loc.record.num_blocks() {
            blocks += 1;
            if let Err(e) = store.block(loc, b) {
                println!("FAIL  {path}: {e}");
                failed += 1;
                break;
            }
        }
    }
    println!("{files} files, {blocks} blocks read, {failed} failures");
    anyhow::ensure!(failed == 0, "{failed} files failed verification");
    Ok(())
}

fn key_audit(
    store: &Arc<Store>,
    depot: Option<u32>,
    out: &PathBuf,
    jobs: usize,
) -> anyhow::Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use store::KeyResolution;

    let blobs: Vec<index::BlobId> = store
        .index
        .depots()
        .filter(|(d, _)| depot.is_none_or(|w| w == *d))
        .flat_map(|(_, dep)| dep.blobs.iter().copied())
        .collect();
    tracing::info!(
        blobs = blobs.len(),
        "key audit: scanning blobs for encrypted files"
    );

    #[derive(Default)]
    struct Counts {
        encrypted_blobs: AtomicUsize,
        ok: AtomicUsize,
        discovered: AtomicUsize,
        unreadable: AtomicUsize,
        no_key: AtomicUsize,
    }
    let counts = Counts::default();
    let next = AtomicUsize::new(0);
    let report = parking_lot::Mutex::new(Vec::<String>::new());
    let discovered = parking_lot::Mutex::new(Vec::<String>::new());

    std::thread::scope(|s| {
        for _ in 0..jobs.max(1) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(&id) = blobs.get(i) else { break };
                let entry = store.index.blob(id);
                let parsed = match store.parsed(id) {
                    Ok(p) => p,
                    Err(e) => {
                        report
                            .lock()
                            .push(format!("UNREADABLE {}: {e:#}", entry.file_name));
                        counts.unreadable.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let Some(rec) = parsed
                    .records
                    .iter()
                    .find(|r| r.mode.is_encrypted() && !r.blocks.is_empty())
                else {
                    continue;
                };
                counts.encrypted_blobs.fetch_add(1, Ordering::Relaxed);
                let loc = match store.locate(id, rec.file_id) {
                    Ok(l) => l,
                    Err(e) => {
                        report
                            .lock()
                            .push(format!("UNREADABLE {}: {e}", entry.file_name));
                        counts.unreadable.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                match store.probe_key(&loc) {
                    Ok(KeyResolution::Configured(_)) => {
                        counts.ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(KeyResolution::Discovered(k, from)) => {
                        counts.discovered.fetch_add(1, Ordering::Relaxed);
                        let line = format!("{}@{:08x}={}", entry.depot, entry.crc, hex::encode(k));
                        report.lock().push(format!(
                            "DISCOVERED {} <- depot {from}'s key",
                            entry.file_name
                        ));
                        discovered.lock().push(format!(
                            "# {} (key of depot {from})\n{line}",
                            entry.file_name
                        ));
                    }
                    Ok(KeyResolution::None { tried }) => {
                        counts.no_key.fetch_add(1, Ordering::Relaxed);
                        report
                            .lock()
                            .push(format!("NO KEY {} (tried {tried})", entry.file_name));
                    }
                    Err(e) => {
                        counts.unreadable.fetch_add(1, Ordering::Relaxed);
                        report
                            .lock()
                            .push(format!("UNREADABLE {}: {e}", entry.file_name));
                    }
                }
                let done = i + 1;
                if done.is_multiple_of(500) {
                    tracing::info!("key audit: {done}/{} blobs", blobs.len());
                }
            });
        }
    });

    let mut lines = report.into_inner();
    lines.sort();
    for l in &lines {
        println!("{l}");
    }
    let found = discovered.into_inner();
    if !found.is_empty() {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)?;
        for l in &found {
            writeln!(f, "{l}")?;
        }
        println!("wrote {} discovered keys to {}", found.len(), out.display());
    }
    println!(
        "{} blobs with encrypted files: {} decrypt with the configured key, {} with another depot's key, {} with no known key, {} unreadable",
        counts.encrypted_blobs.load(Ordering::Relaxed),
        counts.ok.load(Ordering::Relaxed),
        counts.discovered.load(Ordering::Relaxed),
        counts.no_key.load(Ordering::Relaxed),
        counts.unreadable.load(Ordering::Relaxed),
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Mount {
            source,
            mountpoint,
            allow_other,
            threads,
        } => {
            let store = open_store(&source)?;
            let options = vec![
                fuser::MountOption::RO,
                fuser::MountOption::FSName("steam2fs".into()),
                fuser::MountOption::Subtype("steam2fs".into()),
                fuser::MountOption::DefaultPermissions,
            ];
            let mut config = fuser::Config::default();
            if allow_other {
                config.acl = fuser::SessionACL::All;
            }
            config.mount_options = options;
            config.n_threads = Some(threads.max(1));
            tracing::info!(mountpoint = %mountpoint.display(), "mounting");
            fuser::mount(fs::Steam2Fs::new(store), &mountpoint, &config).context("mount")?;
            Ok(())
        }
        Command::Inspect {
            source,
            depot,
            version,
            files,
        } => {
            let store = open_store(&source)?;
            inspect(&store, depot, version, files)
        }
        Command::Verify {
            source,
            depot,
            version,
        } => {
            let store = open_store(&source)?;
            verify(&store, depot, &version)
        }
        Command::KeyAudit {
            source,
            depot,
            out,
            jobs,
        } => {
            let store = open_store(&source)?;
            key_audit(&store, depot, &out, jobs)
        }
    }
}
