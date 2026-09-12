//! Windows links WinFsp's DLL lazily, so the binary still runs (for
//! `inspect`, `verify` and `key-audit`) on a machine with no WinFsp
//! installed. These are the same link arguments `winfsp::build::
//! winfsp_link_delayload` emits; we emit them directly because that helper
//! lives in a crate that only builds for Windows *hosts*, which a
//! cross-compile does not have.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let var = |k: &str| std::env::var(k).unwrap_or_default();
    if var("CARGO_CFG_TARGET_OS") != "windows" {
        return;
    }
    let dll = match var("CARGO_CFG_TARGET_ARCH").as_str() {
        "x86_64" => "winfsp-x64.dll",
        "aarch64" => "winfsp-a64.dll",
        "x86" => "winfsp-x86.dll",
        other => panic!("no WinFsp DLL for target architecture {other}"),
    };
    if var("CARGO_CFG_TARGET_ENV") == "msvc" {
        // delayimp.lib provides __delayLoadHelper2.
        println!("cargo::rustc-link-lib=dylib=delayimp");
        println!("cargo::rustc-link-arg=/DELAYLOAD:{dll}");
    } else {
        println!("cargo::rustc-link-arg=-Wl,--delayload={dll}");
    }
}
