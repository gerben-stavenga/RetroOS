//! Default Linux entry settings, independent of the legacy DOS environment.
//! Direct ELF launches need the same defaults as shell.elf; execve preserves
//! the caller's exact environment and explicit INI settings take precedence.
use alloc::vec::Vec;

static SETTINGS: spin::Mutex<Vec<u8>> = spin::Mutex::new(Vec::new());
static HOME: spin::Mutex<Option<Vec<u8>>> = spin::Mutex::new(None);

pub(crate) fn configure_home(home: Option<&str>) {
    *HOME.lock() = home.map(|home| home.as_bytes().to_vec());
}

pub(crate) fn configure(settings: Vec<u8>) {
    *SETTINGS.lock() = settings;
}

pub(super) fn initial(root: &[u8], locale: &str) -> Vec<u8> {
    // Older BOOT.INI files retain their defaults until a session home is set.
    let home = HOME.lock();
    build(home.as_deref().unwrap_or(root), locale, &SETTINGS.lock())
}

fn build(root: &[u8], locale: &str, settings: &[u8]) -> Vec<u8> {
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
    let path = [home, b"/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"].concat();
    let temporary = [home, b"/TEMP"].concat();
    for (name, value) in [(b"PATH=".as_slice(), path.as_slice()), (b"TMPDIR=", temporary.as_slice()),
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
        let defaults = build(b"home/retroos/", "en_US.UTF-8", b"");
        let entries: Vec<_> = defaults.split(|&b| b == 0).collect();
        assert!(entries.contains(&b"HOME=/home/retroos".as_slice()));
        assert!(entries.contains(&b"PATH=/home/retroos/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin".as_slice()));
        assert!(entries.contains(&b"TMPDIR=/home/retroos/TEMP".as_slice()));
        assert!(entries.contains(&b"SHELL=/bin/sh".as_slice()));
        assert!(entries.contains(&b"TERM=linux".as_slice()));
        let root = build(b"", "en_US.UTF-8", b"");
        assert!(root.split(|&b| b == 0).any(|e| e == b"PATH=/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"));
        let overrides = build(b"home/retroos/", "en_US.UTF-8", b"HOME=/first\0HOME=/custom/\0PATH=\0LANG=it_IT.UTF-8\0TMPDIR=/tmp\0SHELL=/bin/bash\0TERM=vt100\0\0");
        for expected in [b"HOME=/custom/".as_slice(), b"PATH=", b"LANG=it_IT.UTF-8", b"TMPDIR=/tmp", b"SHELL=/bin/bash", b"TERM=vt100"] {
            assert!(overrides.split(|&b| b == 0).any(|e| e == expected));
        }
        assert!(!overrides.split(|&b| b == 0).any(|e| e == b"HOME=/first"));
    }
}
