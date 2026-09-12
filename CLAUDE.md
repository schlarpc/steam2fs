# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

This is a Rust project using Nix flakes with a pinned toolchain. First load the environment:

- `direnv allow` — load the development environment (or `nix develop`)

### Build & run

- `cargo run` — build (debug) and run
- `cargo build --release` — optimized build
- `nix run` — build and run via Nix
- `./result/bin/steam2fs` — the nix-built binary

### Test, lint, format

- `cargo nextest run` — fast parallel test runner
- `cargo llvm-cov nextest` — tests with coverage
- `cargo clippy --all-targets` — lint
- `cargo fmt` — format

### Nix

- `nix build` — build the package
- `nix build .#windows` — cross-compile for Windows (x86_64-pc-windows-msvc)
- `nix flake check` — run all checks (build, clippy, fmt, test, coverage)
- `nix flake update` — update flake inputs

### Windows cross-compilation

- `cargo xwin build --release --target x86_64-pc-windows-msvc` — cross-compile from the dev shell
- The pure Nix build gets the MSVC CRT/SDK from a pinned `xwin` fixed-output derivation in
  `flake.nix`; to bump the pinned versions, update them there, set `outputHash = pkgs.lib.fakeHash`,
  build, and copy the real hash from the mismatch error.

## Architecture

Read-only FUSE filesystem over a Steam2 content-server dump (`blobs/` + `dats/`), see README.md.

- **src/main.rs** — clap CLI: `mount`, `inspect`, `verify`, `key-audit`; builds the `Store`
- **src/backend/** — `Backend` trait (list dir, read range); `local.rs`, `sftp.rs` (system `ssh`
  via the `openssh` crate; listing uses a remote `find`, reads use sftp)
- **src/index.rs** — inventory from file names only; version-directory naming; `blobs_dates.txt`
- **src/format/** — parsers: `blob.rs` (key/value container), `manifest.rs` (directory tree),
  `checksums.rs` (per-file block table), `chunk.rs` (block decode + checksum)
- **src/store.rs** — blob fetch + on-disk cache, parent chain, per-version file tables, dat reads
  through raw-window and decoded-block LRU caches
- **src/fs.rs** — `fuser::Filesystem` impl; inode interning; symlinks; xattrs
- **src/keys/table.rs** — generated depot key table (from the original extractor's `keys.cpp`)

Format facts worth knowing: manifest child/sibling links end at 0, not 0xffffffff; a compressed
blob's `packed_size` includes its 20-byte header; block checksum is adler32 seeded with 0 XOR crc32;
blob key 10 is crc32 of the blob with that field zeroed; blob key 2 equals the manifest fingerprint;
a changed file gets a new file id (blob keys 5/6 are per-version add/remove id lists).

Test data: `../samples/dump` holds a few real blobs/dats (symlinks) for `inspect`/`verify`/mount
tests; `verify` on depot 0 version 2 must report 0 failures.

## Keeping in sync with the base template

Pull upstream template updates with [cruft](https://cruft.github.io/cruft/):

- `cruft update --checkout template`
