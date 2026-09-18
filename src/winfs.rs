//! The WinFsp view of [`crate::tree`].
//!
//! Windows has no symlinks worth serving here, so the two link entries are
//! shown as the directories they point at: `\<depot>\latest\...` and
//! `\<depot>\by-date\<stamp>_v<N>\...` are the version trees themselves.
//! Extended attributes are not served at all; `steam2fs inspect` prints the
//! same facts.

use std::ffi::c_void;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context as _};
use widestring::{U16CStr, U16CString};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    LocalFree, HLOCAL, STATUS_ACCESS_DENIED, STATUS_END_OF_FILE, STATUS_FILE_CORRUPT_ERROR,
    STATUS_FILE_INVALID, STATUS_IO_DEVICE_ERROR, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::FspError;

use crate::store::{ErrorClass, Store};
use crate::tree::{Key, Kind, Meta, Tree, TreeError};

/// Everyone may read and traverse; nobody may write.
const SDDL: &str = "O:BAG:BAD:P(A;;FRFX;;;WD)";

const SECTOR_SIZE: u16 = 512;
const SECTORS_PER_ALLOCATION_UNIT: u16 = 1;
const ALLOCATION_UNIT: u64 = SECTOR_SIZE as u64 * SECTORS_PER_ALLOCATION_UNIT as u64;

fn status(e: &TreeError) -> FspError {
    let nt = match e {
        TreeError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        TreeError::NotADirectory => STATUS_NOT_A_DIRECTORY,
        TreeError::Read(r) => match r.class() {
            // The record is fine but its bytes are not in this dump.
            ErrorClass::Missing => STATUS_FILE_INVALID,
            // Nothing we hold decrypts it; "denied" is the closest thing
            // Windows says out loud.
            ErrorClass::NoKey => STATUS_ACCESS_DENIED,
            ErrorClass::Io => STATUS_IO_DEVICE_ERROR,
            ErrorClass::BadData => STATUS_FILE_CORRUPT_ERROR,
        },
    };
    FspError::NTSTATUS(nt.0)
}

/// Windows counts 100ns ticks from 1601; the tree speaks `SystemTime`.
fn filetime(t: SystemTime) -> u64 {
    const UNIX_EPOCH_IN_TICKS: u64 = 116_444_736_000_000_000;
    let ticks = t
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() / 100);
    UNIX_EPOCH_IN_TICKS.saturating_add(u64::try_from(ticks).unwrap_or(u64::MAX))
}

fn read_sddl(sddl: &str) -> anyhow::Result<Vec<u8>> {
    let wide = U16CString::from_str(sddl)?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is a NUL-terminated wide string and outlives the call;
    // the descriptor it allocates is freed below.
    #[allow(unsafe_code)]
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )?;
    }
    if descriptor.0.is_null() {
        anyhow::bail!("the built-in security descriptor did not parse");
    }
    // SAFETY: `descriptor` is a valid self-relative descriptor.
    #[allow(unsafe_code)]
    let bytes = unsafe {
        let len = GetSecurityDescriptorLength(descriptor) as usize;
        let bytes = std::slice::from_raw_parts(descriptor.0.cast::<u8>(), len).to_vec();
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        bytes
    };
    Ok(bytes)
}

/// One open file or directory.
pub struct Context {
    key: Key,
    kind: Kind,
    dir: DirBuffer,
}

pub struct Steam2WinFs {
    tree: Tree,
    security: Vec<u8>,
}

impl Steam2WinFs {
    fn new(store: Arc<Store>) -> anyhow::Result<Self> {
        Ok(Self {
            tree: Tree::new(store),
            security: read_sddl(SDDL)?,
        })
    }

    /// Symlinks become the thing they point at, since we do not serve
    /// reparse points.
    fn resolve(&self, key: Key) -> Key {
        match key {
            Key::Latest(d) => self.tree.store.index.latest(d).map_or(key, Key::Version),
            Key::DateLink(b) => Key::Version(b),
            _ => key,
        }
    }

    /// Walk a `\`-separated path from the root. Lookups are exact first and
    /// case-insensitive second, because Windows callers expect to be able to
    /// spell a name any way they like.
    fn resolve_path(&self, file_name: &U16CStr) -> Result<Key, TreeError> {
        let path = file_name.to_string_lossy();
        let mut key = Key::Root;
        for component in path.split('\\').filter(|c| !c.is_empty()) {
            if component == "." {
                continue;
            }
            if component == ".." {
                key = self.tree.parent(key);
                continue;
            }
            key = self.resolve(key);
            let found = match self.tree.lookup(key, component.as_bytes())? {
                Some(k) => k,
                None => self.lookup_insensitive(key, component)?,
            };
            key = found;
        }
        Ok(self.resolve(key))
    }

    fn lookup_insensitive(&self, parent: Key, name: &str) -> Result<Key, TreeError> {
        self.tree
            .entries(parent)?
            .into_iter()
            .find(|e| String::from_utf8_lossy(&e.name).eq_ignore_ascii_case(name))
            .map(|e| e.key)
            .ok_or(TreeError::NotFound)
    }

    fn attributes(&self, meta: &Meta) -> u32 {
        let dir = matches!(meta.kind, Kind::Dir | Kind::Symlink);
        if dir {
            FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0
        } else {
            FILE_ATTRIBUTE_READONLY.0
        }
    }

    fn fill_info(&self, meta: &Meta, info: &mut FileInfo) {
        let time = filetime(meta.mtime);
        info.file_attributes = self.attributes(meta);
        info.reparse_tag = 0;
        info.file_size = meta.size;
        info.allocation_size = meta.size.div_ceil(ALLOCATION_UNIT) * ALLOCATION_UNIT;
        info.creation_time = time;
        info.last_access_time = time;
        info.last_write_time = time;
        info.change_time = time;
        info.index_number = 0;
        info.hard_links = 0;
        info.ea_size = 0;
    }

    fn meta(&self, key: Key) -> Result<Meta, FspError> {
        self.tree.meta(key).map_err(|e| status(&e))
    }
}

impl FileSystemContext for Steam2WinFs {
    type FileContext = Context;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let key = self.resolve_path(file_name).map_err(|e| status(&e))?;
        let meta = self.meta(key)?;
        let size = self.security.len() as u64;
        if let Some(buffer) = security_descriptor {
            if buffer.len() as u64 >= size {
                // SAFETY: the buffer is at least `size` bytes and does not
                // overlap our own copy.
                #[allow(unsafe_code)]
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.security.as_ptr(),
                        buffer.as_mut_ptr().cast::<u8>(),
                        self.security.len(),
                    );
                }
            }
        }
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: size,
            attributes: self.attributes(&meta),
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let key = self.resolve_path(file_name).map_err(|e| status(&e))?;
        let meta = self.meta(key)?;
        self.fill_info(&meta, file_info.as_mut());
        Ok(Context {
            key,
            kind: meta.kind,
            dir: DirBuffer::new(),
        })
    }

    fn close(&self, _context: Self::FileContext) {}

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let meta = self.meta(context.key)?;
        self.fill_info(&meta, file_info);
        Ok(())
    }

    fn get_security(
        &self,
        _context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        let size = self.security.len() as u64;
        if let Some(buffer) = security_descriptor {
            if buffer.len() as u64 >= size {
                // SAFETY: as in `get_security_by_name`.
                #[allow(unsafe_code)]
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.security.as_ptr(),
                        buffer.as_mut_ptr().cast::<u8>(),
                        self.security.len(),
                    );
                }
            }
        }
        Ok(size)
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let loc = self.tree.locate(context.key).map_err(|e| {
            tracing::warn!("read: {e}");
            status(&e)
        })?;
        if offset >= loc.record.size {
            return Err(FspError::NTSTATUS(STATUS_END_OF_FILE.0));
        }
        let want = buffer
            .len()
            .min(usize::try_from(loc.record.size - offset).unwrap_or(usize::MAX));
        let data = self.tree.read(&loc, offset, want).map_err(|e| {
            tracing::warn!(file_id = loc.record.file_id, offset, "read: {e}");
            status(&e)
        })?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len() as u32)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if !matches!(context.kind, Kind::Dir) {
            return Err(FspError::NTSTATUS(STATUS_NOT_A_DIRECTORY.0));
        }
        // The first read of a handle fills the buffer; WinFsp serves every
        // later page, and every marker, out of it.
        if let Ok(lock) = context.dir.acquire(false, None) {
            let entries = self.tree.entries(context.key).map_err(|e| status(&e))?;
            let mut info: DirInfo<255> = DirInfo::new();

            let mut write = |name: &str, meta: &Meta| -> winfsp::Result<()> {
                info.reset();
                self.fill_info(meta, info.file_info_mut());
                info.set_name(name)?;
                lock.write(&mut info)
            };

            if !matches!(context.key, Key::Root) {
                let this = self.meta(context.key)?;
                write(".", &this)?;
                let parent = self.resolve(self.tree.parent(context.key));
                let parent_meta = self.meta(parent).unwrap_or(this);
                write("..", &parent_meta)?;
            }

            for entry in entries {
                let key = self.resolve(entry.key);
                let name = String::from_utf8_lossy(&entry.name).into_owned();
                // An entry we listed should still appear even if its own
                // metadata will not load; a later open reports the error.
                let meta = self.tree.meta(key).unwrap_or(Meta {
                    kind: entry.kind,
                    size: 0,
                    mtime: UNIX_EPOCH,
                });
                write(&name, &meta)?;
            }
        }
        Ok(context.dir.read(marker, buffer))
    }

    fn get_volume_info(&self, out: &mut VolumeInfo) -> winfsp::Result<()> {
        out.total_size = 0;
        out.free_size = 0;
        out.set_volume_label("steam2");
        Ok(())
    }
}

/// The WinFsp DLL for this architecture, as the installer names it.
const WINFSP_DLL: &str = if cfg!(target_arch = "x86_64") {
    "winfsp-x64.dll"
} else if cfg!(target_arch = "aarch64") {
    "winfsp-a64.dll"
} else {
    "winfsp-x86.dll"
};

/// Read WinFsp's `InstallDir` registry value from `subkey` under HKLM.
fn registry_install_dir(subkey: &str) -> Option<std::path::PathBuf> {
    let subkey = U16CString::from_str(subkey).ok()?;
    let mut buf = [0u16; 1024];
    let mut size = u32::try_from(std::mem::size_of_val(&buf)).ok()?;
    #[allow(unsafe_code)]
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            windows::core::w!("InstallDir"),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status.is_err() {
        return None;
    }
    let len = usize::try_from(size).ok()? / std::mem::size_of::<u16>();
    let dir = U16CStr::from_slice_truncate(&buf[..len]).ok()?;
    Some(dir.to_os_string().into())
}

/// Load the WinFsp DLL from wherever the installer put it.
///
/// The `winfsp` crate's `winfsp_init` only tries a bare `LoadLibraryW`,
/// which searches the exe directory and `PATH`; the installer adds its
/// `bin` directory to neither. Its registry fallback sits behind a
/// `system` feature whose build script cannot run on a non-Windows host,
/// so we do the lookup here. Once the module is in the process, both the
/// crate's bare-name load and the delay-load helper resolve to it.
fn preload_winfsp() -> Option<std::path::PathBuf> {
    // The x64/x86 installer is a 32-bit MSI and lands in WOW6432Node; the
    // native ARM64 installer writes directly under SOFTWARE.
    let dir = registry_install_dir("SOFTWARE\\WOW6432Node\\WinFsp")
        .or_else(|| registry_install_dir("SOFTWARE\\WinFsp"))?;
    let dll = dir.join("bin").join(WINFSP_DLL);
    let wide = U16CString::from_os_str(dll.as_os_str()).ok()?;
    #[allow(unsafe_code)]
    let loaded = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) };
    match loaded {
        Ok(_) => Some(dll),
        Err(e) => {
            tracing::debug!("LoadLibraryW({}): {e:?}", dll.display());
            None
        }
    }
}

/// Mount the store at `mountpoint` (a drive letter such as `R:`, or a
/// directory) until the process is interrupted.
pub fn mount(
    store: Arc<Store>,
    mountpoint: &std::path::Path,
    threads: usize,
) -> anyhow::Result<()> {
    match preload_winfsp() {
        Some(dll) => tracing::debug!("loaded {}", dll.display()),
        None => tracing::debug!("no WinFsp install found in the registry"),
    }
    // Holding the token keeps the delay-loaded DLL resolved for the mount.
    let _init = winfsp::winfsp_init().map_err(|e| {
        tracing::debug!("winfsp_init: {e:?}");
        anyhow!(
            "WinFsp is not available; install WinFsp 2.1 or newer from \
             https://github.com/winfsp/winfsp/releases"
        )
    })?;

    let mut params = VolumeParams::new();
    params
        .sector_size(SECTOR_SIZE)
        .sectors_per_allocation_unit(SECTORS_PER_ALLOCATION_UNIT)
        .max_component_length(255)
        .volume_creation_time(filetime(SystemTime::now()))
        .volume_serial_number(0x5354_4d32)
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .read_only_volume(true)
        .persistent_acls(true)
        .post_cleanup_when_modified_only(true)
        // The tree never changes while we are mounted, so let the cache
        // manager keep what it has learned.
        .file_info_timeout(u32::MAX)
        .filesystem_name("steam2fs");

    let context = Steam2WinFs::new(store)?;
    // The default (fine-grained) guard: WinFsp calls us from several
    // dispatcher threads at once, which is what the store is built for.
    let mut host: FileSystemHost<Steam2WinFs> = FileSystemHost::new(params, context)
        .map_err(|e| anyhow!("creating the WinFsp filesystem: {e}"))?;
    host.mount(mountpoint.to_path_buf())
        .map_err(|e| anyhow!("mounting at {}: {e}", mountpoint.display()))?;
    host.start_with_threads(threads as u32)
        .map_err(|e| anyhow!("starting the WinFsp dispatcher: {e}"))?;

    // Required by WinFsp's FLOSS exception, which is what lets a
    // non-GPL-licensed program link its DLL at all.
    tracing::info!("WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos");
    tracing::info!("mounted; press Ctrl-C to unmount");
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc_channel(tx)?;
    let _ = rx.recv();

    host.stop();
    host.unmount();
    Ok(())
}

/// Ctrl-C, without pulling in a crate for it.
fn ctrlc_channel(tx: std::sync::mpsc::Sender<()>) -> anyhow::Result<()> {
    use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_C_EVENT};

    static SENDER: std::sync::OnceLock<std::sync::mpsc::Sender<()>> = std::sync::OnceLock::new();
    SENDER
        .set(tx)
        .map_err(|_| anyhow!("a console handler is already installed"))?;

    // SAFETY: called by the console host on its own thread; it only sends
    // on a channel.
    #[allow(unsafe_code)]
    unsafe extern "system" fn handler(event: u32) -> windows::core::BOOL {
        if event == CTRL_C_EVENT {
            if let Some(tx) = SENDER.get() {
                let _ = tx.send(());
            }
            return true.into();
        }
        false.into()
    }

    // SAFETY: `handler` is a valid console handler and stays valid for the
    // life of the process.
    #[allow(unsafe_code)]
    unsafe {
        SetConsoleCtrlHandler(Some(handler), true).context("installing a Ctrl-C handler")?;
    }
    Ok(())
}
