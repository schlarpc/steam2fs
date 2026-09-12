//! End-to-end tests over the sample dump in `../samples/dump`.
//!
//! The samples are a handful of real blobs and dats symlinked into place, so
//! they are not present in every checkout (or inside the Nix build sandbox).
//! Every test here skips, loudly, when they are missing.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn dump() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../samples/dump");
    if p.join("blobs").is_dir() && p.join("dats").is_dir() {
        return Some(p);
    }
    eprintln!("skipping: no sample dump at {}", p.display());
    None
}

/// `<subcommand> [flags] <source> [operands]`.
fn cli(sub: &[&str], operands: &[&str]) -> Option<(String, Output)> {
    let dump = dump()?;
    let out = Command::new(env!("CARGO_BIN_EXE_steam2fs"))
        .args(sub)
        .arg(&dump)
        .args(operands)
        .output()
        .unwrap();
    Some((String::from_utf8_lossy(&out.stdout).into_owned(), out))
}

#[test]
fn verifies_a_complete_version() {
    let Some((stdout, out)) = cli(&["verify"], &["0", "2"]) else {
        return;
    };
    assert!(out.status.success(), "verify failed: {stdout}");
    assert!(
        stdout.contains("0 failures"),
        "expected a clean verify, got: {stdout}"
    );
    // Depot 0 version 2 is 24 files, and every block of them decodes and
    // checksums; that is the invariant the sample dump exists to pin down.
    assert!(stdout.contains("24 files"), "{stdout}");
}

#[test]
fn verify_reports_a_missing_dat() {
    // Depot 7's dat is not in the sample dump, so every file is unreadable
    // and the command has to fail rather than report success.
    let Some((stdout, out)) = cli(&["verify"], &["7", "0"]) else {
        return;
    };
    assert!(!out.status.success());
    assert!(stdout.contains("is not in the dump"), "{stdout}");
}

#[test]
fn verify_rejects_an_unknown_version() {
    let Some((_, out)) = cli(&["verify"], &["0", "999"]) else {
        return;
    };
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("no version"), "{err}");
}

#[test]
fn inspect_lists_versions_and_chains() {
    let Some((stdout, out)) = cli(&["inspect"], &["0"]) else {
        return;
    };
    assert!(out.status.success());
    assert!(stdout.contains("depot 0: 3 blobs, key known"), "{stdout}");

    // A version with a parent shows the chain root-first.
    let (stdout, out) = cli(&["inspect"], &["102021", "18-ef45a233"]).unwrap();
    assert!(out.status.success());
    let chain = stdout
        .lines()
        .position(|l| l.starts_with("chain "))
        .unwrap();
    let v17 = stdout.lines().position(|l| l.contains("v17 ")).unwrap();
    let v18 = stdout.lines().position(|l| l.contains("v18 ")).unwrap();
    assert!(
        chain < v17 && v17 < v18,
        "chain is not root-first: {stdout}"
    );
}

#[test]
fn inspect_files_locates_every_file() {
    let Some((stdout, out)) = cli(&["inspect", "--files"], &["0", "2"]) else {
        return;
    };
    assert!(out.status.success());
    assert!(stdout.contains("24 files, 24 with records"), "{stdout}");
    assert!(stdout.contains("HLTV-Readme.txt"), "{stdout}");
    assert!(!stdout.contains("NO RECORD"), "{stdout}");
    // Files inherited from an older version report where they came from.
    assert!(stdout.contains("from v"), "{stdout}");
}

#[test]
fn blob_cache_round_trips_and_rejects_corruption() {
    let Some(dump) = dump() else { return };
    let cache = std::env::temp_dir().join(format!("steam2fs-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache);

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_steam2fs"))
            .args(["verify", "--cache-dir"])
            .arg(&cache)
            .arg(&dump)
            .args(["0", "2"])
            .output()
            .unwrap()
    };

    assert!(run().status.success());
    let cached: Vec<_> = std::fs::read_dir(&cache)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(!cached.is_empty(), "nothing was cached");

    // A cached blob that has rotted fails its own crc32 when parsed. That
    // has to heal itself by refetching, not fail the same way forever.
    let victim = cached
        .iter()
        .find(|p| p.extension().is_some_and(|e| e == "blob"))
        .unwrap();
    let good = std::fs::read(victim).unwrap();
    let mut bytes = good.clone();
    let len = bytes.len();
    bytes[len / 2] ^= 0xff;
    std::fs::write(victim, &bytes).unwrap();

    let out = run();
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("did not parse"), "{err}");
    assert_eq!(
        std::fs::read(victim).unwrap(),
        good,
        "the rotted cache entry should have been replaced"
    );

    // A truncated one is caught by the size check before it is even parsed.
    std::fs::write(victim, &good[..good.len() / 2]).unwrap();
    let out = run();
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("expected"), "{err}");

    let _ = std::fs::remove_dir_all(&cache);
}

#[test]
fn key_audit_reports_every_encrypted_blob() {
    let Some(dump) = dump() else { return };
    let out = Command::new(env!("CARGO_BIN_EXE_steam2fs"))
        .args(["key-audit", "--out"])
        .arg(std::env::temp_dir().join(format!("steam2fs-keys-{}.txt", std::process::id())))
        .arg(&dump)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("blobs with encrypted files"), "{stdout}");
    assert!(stdout.contains("0 unreadable"), "{stdout}");
}
