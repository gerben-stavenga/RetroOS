//! Hosted native filesystem backend.

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};
use alloc::vec::Vec;

/// The installed native host-fs hook table. Primitive signatures only: the
/// entry crate wires these to `arch-interp`'s `std::fs` server (which has no
/// `kernel` dependency, so no `Vnode`/`DirEntry` may appear here).
///   `open`  → (status, handle, size); status < 0 = miss.
///   `read`  → bytes read, or negative errno.
///   `readdir` → (status, name, name_len, size, is_dir, mtime); status < 0 = end.
///   `create`→ (status, handle); status < 0 = fail.
///   `write` → bytes written, or negative errno.
///   `mkdir` → 0 on success, negative errno.
#[derive(Clone, Copy)]
#[allow(clippy::type_complexity)] // the readdir hook's tuple reply is documented above
pub struct HostBackendHooks {
    pub open: fn(&[u8]) -> (i32, u64, u32),
    pub read: fn(u64, u32, &mut [u8], u32) -> i32,
    pub readdir: fn(&[u8], usize) -> (i32, [u8; 100], usize, u32, bool, u32),
    pub dir_exists: fn(&[u8]) -> bool,
    pub create: fn(&[u8]) -> (i32, u64),
    pub write: fn(u64, u32, &[u8]) -> i32,
    pub clunk: fn(u64),
    pub remove: fn(&[u8]) -> i32,
    pub mkdir: fn(&[u8]) -> i32,
}

static mut HOST_BACKEND: Option<HostBackendHooks> = None;

/// Install the native host-fs hooks. Single-threaded boot context (the entry
/// calls this before `startup`), safe by the same argument as the rest of the
/// boot statics.
pub fn install_host_backend(hooks: HostBackendHooks) {
    unsafe {
        HOST_BACKEND = Some(hooks);
    }
}

/// Whether a native host backend is installed — the hosted signal that `/host`
/// is available without probing a serial port.
pub fn host_backend_installed() -> bool {
    unsafe { HOST_BACKEND }.is_some()
}

#[inline]
fn backend() -> HostBackendHooks {
    unsafe { HOST_BACKEND }.expect("host backend not installed")
}

/// The `Filesystem` mounted at `/host` (or root, under `Media::HostRoot`) on
/// hosted: every call dispatches to the injected native `std::fs` hooks.
pub struct InjectedHostFs;
pub static INJECTED_HOSTFS: InjectedHostFs = InjectedHostFs;

impl Filesystem for InjectedHostFs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let (status, handle, size) = (backend().open)(path);
        if status < 0 {
            return None;
        }
        Some(Vnode {
            handle,
            size,
            mode: 0o644,
        })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32 {
        (backend().read)(handle, offset, buf, size)
    }

    /// Cookie = entry index: the hook is per-entry, so batching happens here.
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        let mut index = cookie;
        while out.len() < max {
            let (status, name, name_len, size, is_dir, mtime) =
                (backend().readdir)(dir, index as usize);
            if status < 0 {
                return None;
            }
            out.push(DirEntry {
                name,
                name_len,
                size,
                is_dir,
                is_symlink: false,
                mode: if is_dir { 0o755 } else { 0o644 },
                mtime,
                node: 0,
                mount_idx: 0,
            });
            index += 1;
        }
        Some(index)
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        (backend().dir_exists)(path)
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        let (status, handle) = (backend().create)(path);
        if status < 0 {
            return None;
        }
        Some(Vnode {
            handle,
            size: 0,
            mode: 0o644,
        })
    }

    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        (backend().write)(handle, offset, data)
    }

    fn clunk(&self, handle: u64) {
        (backend().clunk)(handle)
    }

    fn remove(&self, path: &[u8]) -> i32 {
        (backend().remove)(path)
    }

    /// Real directories on the real host fs. Without this, MKDIR falls into
    /// the VFS RAM-ghost path and every file later created inside the "new"
    /// directory silently lands in RAM and vanishes on shutdown.
    fn mkdir(&self, path: &[u8]) -> i32 {
        (backend().mkdir)(path)
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    fn supports_create(&self) -> bool {
        true
    }
}
