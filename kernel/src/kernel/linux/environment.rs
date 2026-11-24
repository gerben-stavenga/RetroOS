//! Default Linux entry settings, independent of the legacy DOS environment.
//! Direct ELF launches need the same defaults as shell.elf; execve preserves
//! the caller's exact environment and explicit INI settings take precedence.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

static SETTINGS: spin::Mutex<Vec<u8>> = spin::Mutex::new(Vec::new());
static HOME: spin::Mutex<Option<Vec<u8>>> = spin::Mutex::new(None);
static IDENTITY: spin::Mutex<Option<(u32, u32)>> = spin::Mutex::new(None);
static HOST_PATHS: AtomicBool = AtomicBool::new(false);

/// Device metadata may be queried under the VFS lock. Exec initializes the
/// session identity before entering user code; do not recursively resolve home.
pub(crate) fn cached_identity() -> (u32, u32) { IDENTITY.lock().unwrap_or((0, 0)) }

pub(crate) fn configure_session(home: Option<&[u8]>, identity: Option<(u32, u32)>, host_paths: bool) {
    *HOME.lock() = home.map(<[u8]>::to_vec);
    *IDENTITY.lock() = identity;
    HOST_PATHS.store(host_paths, Ordering::Relaxed);
}

pub(crate) fn uses_host_paths() -> bool {
    HOST_PATHS.load(Ordering::Relaxed)
}

/// Use the platform's supplied identity or derive it from the mounted home.
/// Environment supplied to exec cannot change this identity.
pub(super) fn identity() -> (u32, u32) {
    if let Some(identity) = *IDENTITY.lock() { return identity; }
    let home = HOME.lock().clone();
    let root = crate::kernel::dos::c_root();
    let root = root.as_bytes();
    let path = home.as_deref().unwrap_or(root);
    let path = path.strip_prefix(b"/").unwrap_or(path);
    let path = path.strip_suffix(b"/").unwrap_or(path);
    let identity = crate::kernel::vfs::ownership(path, true).unwrap_or((0, 0));
    *IDENTITY.lock() = Some(identity);
    identity
}

pub(crate) fn configure(settings: Vec<u8>) {
    *SETTINGS.lock() = settings;
}

pub(super) fn initial(root: &[u8], locale: &str) -> Vec<u8> {
    // Older BOOT.INI files retain their defaults until a session home is set.
    let home = HOME.lock();
    build(home.as_deref().unwrap_or(root), locale, &SETTINGS.lock(), uses_host_paths())
}

fn build(root: &[u8], locale: &str, settings: &[u8], host_paths: bool) -> Vec<u8> {
    let root = root.strip_suffix(b"/").unwrap_or(root);
    let home = [b"HOME=/".as_slice(), root.strip_prefix(b"/").unwrap_or(root)].concat();
    let lang = [b"LANG=".as_slice(), locale.as_bytes()].concat();
    let entries: Vec<&[u8]> = settings.split(|&b| b == 0).filter(|e| !e.is_empty()).collect();
    let mut result = Vec::new();
    for entry in [home.as_slice(), lang.as_slice()].into_iter().chain(entries.iter().copied()) {
        let key = entry.split(|&b| b == b'=').next().unwrap();
        if entries.iter().rev().find(|e| e.split(|&b| b == b'=').next() == Some(key)).is_some_and(|last| *last != entry) {
            continue;
        }
        if result.split(|&b| b == 0).any(|e| e.split(|&b| b == b'=').next() == Some(key)) {
            continue;
        }
        result.extend_from_slice(entry);
        result.push(0);
    }
    let home = result.split(|&b| b == 0).find_map(|entry| entry.strip_prefix(b"HOME=")).unwrap_or(b"/home/retroos").to_vec();
    let home = home.strip_suffix(b"/").unwrap_or(&home);
    let path = [home, b"/bin:", home, b"/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"].concat();
    let temporary = [home, b"/TEMP"].concat();
    let temporary = if host_paths { b"/tmp" } else { temporary.as_slice() };
    for (name, value) in [(b"PATH=".as_slice(), path.as_slice()), (b"TMPDIR=", temporary),
        (b"SHELL=", b"/bin/sh"), (b"TERM=", b"linux")]
    {
        if result.split(|&b| b == 0).any(|entry| entry.starts_with(name)) { continue; }
        result.extend_from_slice(name);
        result.extend_from_slice(value);
        result.push(0);
    }
    result.push(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_settings_override_boot_defaults_without_legacy_values() {
        let defaults = build(b"home/retroos/", "en_US.UTF-8", b"", false);
        let entries: Vec<_> = defaults.split(|&b| b == 0).collect();
        assert!(entries.contains(&b"HOME=/home/retroos".as_slice()));
        assert!(entries.contains(&b"PATH=/home/retroos/bin:/home/retroos/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin".as_slice()));
        assert!(entries.contains(&b"TMPDIR=/home/retroos/TEMP".as_slice()));
        assert!(entries.contains(&b"SHELL=/bin/sh".as_slice()));
        assert!(entries.contains(&b"TERM=linux".as_slice()));
        let root = build(b"", "en_US.UTF-8", b"", false);
        assert!(root.split(|&b| b == 0).any(|e| e == b"PATH=/bin:/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"));
        let overrides = build(b"home/retroos/", "en_US.UTF-8", b"HOME=/first\0HOME=/custom/\0PATH=\0LANG=it_IT.UTF-8\0TMPDIR=/tmp\0SHELL=/bin/bash\0TERM=vt100\0\0", false);
        for expected in [b"HOME=/custom/".as_slice(), b"PATH=", b"LANG=it_IT.UTF-8", b"TMPDIR=/tmp", b"SHELL=/bin/bash", b"TERM=vt100"] {
            assert!(overrides.split(|&b| b == 0).any(|e| e == expected));
        }
        assert!(!overrides.split(|&b| b == 0).any(|e| e == b"HOME=/first"));
    }
}
