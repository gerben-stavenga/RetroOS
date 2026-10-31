//! Registry storage shared by Windows processes. NT structure marshalling is in RETROOS.DLL.
use super::*;
struct Key {
    path: Vec<u16>,
    spelling: Vec<u16>,
    deleted: bool,
    link: bool,
    modified: u64,
    values: Vec<(Vec<u16>, u32, Vec<u8>, Vec<u16>)>,
}
static KEYS: spin::Mutex<Vec<Key>> = spin::Mutex::new(Vec::new());
#[derive(Default)]
pub(super) struct Handles {
    keys: Vec<Option<usize>>,
}
const BASE: u32 = 0x7100_0000;
fn canonical(name: &[u16]) -> Vec<u16> {
    alloc::string::String::from_utf16_lossy(name)
        .to_lowercase()
        .encode_utf16()
        .collect()
}
fn normalize_path(path: &[u16]) -> Vec<u16> {
    let mut result = Vec::with_capacity(path.len());
    for &c in path {
        if c != 92 || result.last() != Some(&92) { result.push(c); }
    }
    while result.len() > 1 && result.last() == Some(&92) { result.pop(); }
    result
}
// Monotonic FILETIME values let Wine invalidate registry-backed display caches.
static LAST_WRITE: spin::Mutex<u64> = spin::Mutex::new(0);
fn stamp() -> u64 {
    let wall = (u64::from(crate::kernel::clock::rtc_unix_timestamp().unwrap_or(0)) + 11_644_473_600) * 10_000_000;
    let mut last = LAST_WRITE.lock();
    *last = wall.max(*last + 1);
    *last
}
fn resolve_links(keys: &[Key], input: &[u16], open_link: bool) -> Result<Vec<u16>, u32> {
    let mut path = normalize_path(input);
    for _ in 0..32 {
        let link = keys.iter().filter(|k| !k.deleted && k.link)
            .filter(|k| (path == k.path && !open_link) ||
                (path.starts_with(&k.path) && path.get(k.path.len()) == Some(&92)))
            .min_by_key(|k| k.path.len());
        let Some(link) = link else { return Ok(path); };
        let value = link.values.iter().find(|v| v.1 == 6).ok_or(0xc0000034u32)?;
        let target: Vec<u16> = value.2.chunks_exact(2).map(|b| u16::from_le_bytes([b[0],b[1]])).collect();
        if target.first() != Some(&92) { return Err(0xc0000033); }
        let mut target = normalize_path(&canonical(&target));
        target.extend_from_slice(&path[link.path.len()..]);
        path = target;
        if path.len() > 16383 { return Err(0xc0000033); }
    }
    Err(0xc0000280)
}
pub(super) fn call<A: crate::Arch>(machine: &mut A, handles: &mut Handles, args: [u32; 7]) -> u32 {
    let [op, handle, name, length, data, size, info] = args;
    if length > 32766 || length & 1 != 0 || size > 16 * 1024 * 1024 {
        return 0xc000000d;
    }
    let name: Vec<u16> = (0..length / 2)
        .map(|i| machine.read::<u16>((name + i * 2) as usize))
        .collect();
    let spelling = name.clone();
    let name = canonical(&name);
    let mut keys = KEYS.lock();
    if keys.is_empty() {
        for path in [
            "\\registry",
            "\\registry\\machine",
            "\\registry\\user",
            "\\registry\\user\\s-1-5-21-0-0-0-1000",
        ] {
            keys.push(Key {
                path: path.encode_utf16().collect(),
                spelling: path.encode_utf16().collect(),
                deleted: false,
                link: false,
                modified: stamp(),
                values: Vec::new(),
            });
        }
    }
    let index = handle
        .checked_sub(BASE)
        .filter(|h| h % 4 == 0)
        .and_then(|h| handles.keys.get((h / 4) as usize))
        .and_then(|h| *h);
    if op <= 1 {
        if index.is_some_and(|i| keys[i].deleted) {
            return 0xc000017c;
        }
        let mut full_spelling = index.map_or_else(Vec::new, |i| keys[i].spelling.clone());
        if !full_spelling.is_empty() && !spelling.is_empty() {
            full_spelling.push(92);
        }
        full_spelling.extend_from_slice(&spelling);
        full_spelling = normalize_path(&full_spelling);
        let mut path = if handle == 0 {
            Vec::new()
        } else if let Some(i) = index {
            keys[i].path.clone()
        } else {
            return 0xc0000008;
        };
        if !path.is_empty() && !name.is_empty() {
            path.push(92);
        }
        path.extend_from_slice(&name);
        path = normalize_path(&path);
        if data & !11 != 0 { return 0xc000000d; }
        match resolve_links(&keys, &path, data & 10 != 0) {
            Ok(resolved) => {
                if resolved != path { full_spelling = resolved.clone(); }
                path = resolved;
            }
            Err(status) => return status,
        }
        let existing = keys.iter().position(|key| !key.deleted && key.path == path);
        let (index, disposition) = if let Some(i) = existing {
            if data & 2 != 0 { return 0xc0000035; }
            (i, 2)
        } else {
            if op == 0 {
                return 0xc0000034;
            }
            let Some(split) = path.iter().rposition(|&c| c == 92) else {
                return 0xc0000033;
            };
            if !keys
                .iter()
                .any(|key| !key.deleted && key.path == path[..split])
            {
                return 0xc0000034;
            }
            if let Some(parent) = keys.iter_mut().find(|k| !k.deleted && k.path == path[..split]) {
                parent.modified = stamp();
            }
            let i = keys.len();
            keys.push(Key {
                path,
                spelling: full_spelling,
                deleted: false,
                link: data & 2 != 0,
                modified: stamp(),
                values: Vec::new(),
            });
            (i, 1)
        };
        let slot = handles
            .keys
            .iter()
            .position(Option::is_none)
            .unwrap_or(handles.keys.len());
        if slot == handles.keys.len() {
            handles.keys.push(Some(index));
        } else {
            handles.keys[slot] = Some(index);
        }
        machine.write::<u32>(info as usize, BASE + slot as u32 * 4);
        machine.write::<u32>(info as usize + 4, disposition);
        return 0;
    }
    let Some(index) = index else {
        return 0xc0000008;
    };
    if op == 4 {
        handles.keys[((handle - BASE) / 4) as usize] = None;
        return 0;
    }
    if keys[index].deleted {
        return 0xc000017c;
    }
    if op == 9 {
        let mut prefix = keys[index].path.clone();
        prefix.push(92);
        if keys
            .iter()
            .any(|k| !k.deleted && k.path.starts_with(&prefix))
        {
            return 0xc0000121;
        }
        let parent = keys[index].path.iter().rposition(|&c| c == 92).map(|split| keys[index].path[..split].to_vec());
        if let Some(parent) = parent.and_then(|p| keys.iter_mut().find(|k| !k.deleted && k.path == p)) {
            parent.modified = stamp();
        }
        keys[index].deleted = true;
        keys[index].values.clear();
        return 0;
    }
    if op == 6 || op == 7 {
        // Enum index is passed in the name word, with no input string.
        let index = if op == 7 {
            let ordinal = args[2] as usize;
            let mut prefix = keys[index].path.clone();
            prefix.push(92);
            let Some(i) = keys
                .iter()
                .enumerate()
                .filter(|(_, k)| {
                    !k.deleted
                        && k.path.starts_with(&prefix)
                        && !k.path[prefix.len()..].contains(&92)
                })
                .nth(ordinal)
                .map(|(i, _)| i)
            else {
                return 0x8000001a;
            };
            i
        } else {
            index
        };
        let key = &keys[index];
        let mut prefix = key.path.clone();
        prefix.push(92);
        let children: Vec<&Key> = keys
            .iter()
            .filter(|k| {
                !k.deleted && k.path.starts_with(&prefix) && !k.path[prefix.len()..].contains(&92)
            })
            .collect();
        let label = if op == 7 {
            &key.spelling[key
                .spelling
                .iter()
                .rposition(|&c| c == 92)
                .map_or(0, |i| i + 1)..]
        } else {
            &key.spelling[..]
        };
        let metadata = [
            label.len() * 2,
            children.len(),
            children
                .iter()
                .map(|k| {
                    (k.spelling.len()
                        - k.spelling
                            .iter()
                            .rposition(|&c| c == 92)
                            .map_or(0, |i| i + 1))
                        * 2
                })
                .max()
                .unwrap_or(0),
            key.values.len(),
            key.values.iter().map(|v| v.3.len() * 2).max().unwrap_or(0),
            key.values.iter().map(|v| v.2.len()).max().unwrap_or(0),
        ];
        for (i, n) in metadata.into_iter().enumerate() {
            machine.write::<u32>(info as usize + i * 4, n as u32);
        }
        machine.write::<u64>(info as usize + 24, key.modified);
        for (i, c) in label.iter().take(size as usize / 2).enumerate() {
            machine.write::<u16>(data as usize + i * 2, *c);
        }
        return if size as usize >= label.len() * 2 {
            0
        } else {
            0x80000005
        };
    }
    if op == 8 {
        let Some(value) = keys[index].values.get(args[2] as usize) else {
            return 0x8000001a;
        };
        for (i, n) in [value.1, value.3.len() as u32 * 2, value.2.len() as u32]
            .into_iter()
            .enumerate()
        {
            machine.write::<u32>(info as usize + i * 4, n);
        }
        let mut bytes = Vec::with_capacity(value.0.len() * 2 + value.2.len());
        let mode = machine.read::<u32>(info as usize + 12);
        if mode != 1 {
            for c in &value.3 {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        if mode != 2 {
            bytes.extend_from_slice(&value.2);
        }
        let n = (size as usize).min(bytes.len());
        machine.copy_to(data as usize, &bytes[..n]);
        return if n < bytes.len() { 0x80000005 } else { 0 };
    }
    let key = &mut keys[index];
    if op == 5 {
        let Some(i) = key.values.iter().position(|v| v.0 == name) else {
            return 0xc0000034;
        };
        key.values.remove(i);
        key.modified = stamp();
        return 0;
    }
    if op == 3 {
        let mut bytes = vec![0; size as usize];
        machine.copy_from(data as usize, &mut bytes);
        let kind = machine.read::<u32>(info as usize);
        if key.link && (name != canonical(&"SymbolicLinkValue".encode_utf16().collect::<Vec<_>>()) || kind != 6 || size & 1 != 0) {
            return 0xc000000d;
        }
        key.modified = stamp();
        if let Some(value) = key.values.iter_mut().find(|v| v.0 == name) {
            value.1 = kind;
            value.2 = bytes;
        } else {
            key.values.push((name, kind, bytes, spelling));
        }
        return 0;
    }
    if op == 2 {
        let Some(value) = key.values.iter().find(|v| v.0 == name) else {
            return 0xc0000034;
        };
        machine.write::<u32>(info as usize, value.1);
        machine.write::<u32>(info as usize + 4, value.2.len() as u32);
        let count = (size as usize).min(value.2.len());
        if count != 0 {
            machine.copy_to(data as usize, &value.2[..count]);
        }
        return if count < value.2.len() { 0x80000005 } else { 0 };
    }
    0xc0000003
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(s: &str) -> Vec<u16> { s.encode_utf16().collect() }
    fn link(from: &str, to: &str) -> Key {
        Key { path: path(from), spelling: path(from), deleted: false, link: true, modified: 1,
            values: vec![(path("symboliclinkvalue"), 6, to.encode_utf16().flat_map(u16::to_le_bytes).collect(), path("SymbolicLinkValue"))] }
    }
    #[test]
    fn links_follow_prefixes_preserve_open_link_and_reject_cycles() {
        let keys = [link("\\a", "\\target"), link("\\b", "\\a")];
        assert_eq!(resolve_links(&keys, &path("\\b\\child"), false), Ok(path("\\target\\child")));
        assert_eq!(resolve_links(&keys, &path("\\a"), true), Ok(path("\\a")));
        assert_eq!(resolve_links(&keys, &path("\\ab"), false), Ok(path("\\ab")));
        assert_eq!(resolve_links(&keys, &path("\\b\\\\child\\"), false), Ok(path("\\target\\child")));
        assert_eq!(resolve_links(&[link("\\a", "\\b"), link("\\b", "\\a")], &path("\\a"), false), Err(0xc0000280));
    }
}
