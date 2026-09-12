# steam2fs

A read-only FUSE filesystem that shows every version of every depot in a
Steam2 content-server dump, straight from the archive's `blob` and `dat`
files. Nothing is extracted; file bytes are decoded on demand from the
32 KiB blocks the format is stored in.

```text
/                              one directory per depot id
/<depot>/<version>/            the depot's tree as of that version
/<depot>/<version>-<crc>/      when several blobs share a version number (resets, forks)
/<depot>/latest                symlink to the newest version
/<depot>/by-date/<stamp>_v<N>  symlinks ordered by the blob's original date
```

Each file's mtime is the date of the version that last changed it, so
`ls -lt` in any version shows what was updated when. Extended attributes
(`getfattr -d file`) expose depot, version, file id, storage mode, source
dat and offset.

## Usage

```shell
# local copy of the dump
steam2fs mount /path/to/steam2 /mnt/steam2

# over ssh, using your ~/.ssh/config and agent
steam2fs mount example-host:/srv/dumps/steam2 /mnt/steam2

# what is known about a depot, one version, or every file's location
steam2fs inspect SOURCE 0
steam2fs inspect SOURCE 102021 18-ef45a233 --files

# read every block of a version and check the stored checksums
steam2fs verify SOURCE 0 56
```

The source must contain `blobs/` and `dats/`; `blobs_dates.txt` is used for
dates when present. Sources are a local directory, `host:/path`, or
`sftp://[user@]host[:port]/path`.

Unmount with `fusermount3 -u /mnt/steam2`.

### Options

- `--key DEPOT=HEX` or `--key DEPOT@BLOBCRC=HEX`, `--keys-file FILE`: extra
  AES keys. About 4,700 depot keys are built in. A republished blob can use
  a different key than the rest of its depot, which the `@BLOBCRC` form
  targets (the crc is the third component of the blob's file name).
- Key search is automatic: when a depot's key fails on a blob, every known
  key is tried against one block (validated by the stored checksum) and the
  match is remembered for the mount. `--no-key-search` disables it. A blob
  nothing decrypts reads as `ENOKEY`.
- `--cache-dir DIR`: where blob files are cached locally. Names embed a
  sha256, which is verified on fetch, so the cache is content-addressed
  and never stale.
- `--raw-cache-mb`, `--block-cache-mb`: in-memory caches of fetched dat
  bytes and decoded blocks (256 MiB each by default).
- `--no-verify`: skip per-block checksum checks. With verification on, a
  block from an unfinished download (`.dat.!qB`) fails with `EIO` instead
  of reading as zeros.
- `--allow-other`: needs `user_allow_other` in `/etc/fuse.conf`.

Set `RUST_LOG=debug` for details on what the filesystem is doing.

### Key audit

```shell
steam2fs key-audit SOURCE --jobs 8 --out discovered-keys.txt
```

Reads one encrypted block from every blob that has encrypted files and
reports which decrypt with the configured key, which only decrypt with some
other depot's key (written to the output file in `DEPOT@CRC=HEX` form for
`--keys-file`), and which no known key opens.

Run against the full terarelease dump: of 15,557 encrypted blobs, 14,990
open with the built-in keys, none open with any other depot's key, and 472
(across 256 depots, mostly pre-release republishes) open with nothing in
the table. Those read as `ENOKEY` unless a key turns up elsewhere.

## How the dump is structured

- Every version of a depot has one blob (metadata) and one dat (data).
  Blob key 7 holds the dat's crc, key 12 the parent blob's crc, so versions
  form a chain that is followed exactly, including resets and forks.
- A changed file gets a new file id. A dat holds complete copies of the
  files new in that version; a version's file table is the union of its
  ancestors' records, and each file is whole and contiguous in one dat.
  Blob keys 5 and 6 list, per earlier version N, the ids to fetch and to
  delete when updating from N; they are redundant with the manifests.
- Files are stored as independent blocks: zlib, AES-128-CFB (zero IV) plus
  zlib, or AES only. Block checksums are `adler32(seed 0) ^ crc32`.
- Blob integrity is checked three ways on load: the sha256 in the file
  name, key 10 (crc32 of the blob with that field zeroed), and the manifest
  fingerprint, which must equal blob key 2. Manifest checksums, block
  sizes, version ids and dat sizes are checked as well.

Depots with a missing parent blob still mount; files whose data cannot be
located return `ENXIO`. Encrypted depots without a key return `ENOKEY`.

Not interpreted: the 128-byte signature in blob key 9, the manifest's hash
buckets and minimum-footprint/user-config lists, and the `depot_info`
header word.

## Development

Nix flake with a pinned toolchain; `direnv allow` or `nix develop`, then the
usual `cargo build`, `cargo test`, `cargo clippy --all-targets`.
Mounting only needs `fusermount3` on the host (no libfuse link).
