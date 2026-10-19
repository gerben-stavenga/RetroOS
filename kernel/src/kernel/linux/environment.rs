//! Linux entry settings are independent of the legacy process environment.
//! Session policy (PATH, temporary directory, shell) belongs to shell.elf.
use alloc::vec::Vec;

static SETTINGS: spin::Mutex<Vec<u8>> = spin::Mutex::new(Vec::new());

pub(crate) fn configure(settings: Vec<u8>) {
    *SETTINGS.lock() = settings;
}

pub(super) fn initial(root: &[u8], locale: &str) -> Vec<u8> {
    build(root, locale, &SETTINGS.lock())
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
    result.push(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_settings_override_boot_defaults_without_legacy_values() {
        assert_eq!(build(b"home/retroos/", "en_US.UTF-8", b""), b"HOME=/home/retroos\0LANG=en_US.UTF-8\0\0");
        assert_eq!(build(b"", "en_US.UTF-8", b""), b"HOME=/\0LANG=en_US.UTF-8\0\0");
        assert_eq!(build(b"home/retroos/", "en_US.UTF-8", b"HOME=/first\0HOME=/custom\0PATH=\0LANG=it_IT.UTF-8\0\0"),
                   b"HOME=/custom\0PATH=\0LANG=it_IT.UTF-8\0\0");
    }
}
