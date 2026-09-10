//! DOS long-name namespace. Storage supplies names; DOS supplies folding,
//! OEM encoding, canonicalization and the shared short-alias view.
use super::{ci, DfsState};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use crate::kernel::vfs;

pub const PATH_MAX: usize = 260;
pub const NAME_MAX: usize = 255;
// Active DOS code page is 437. Bytes below 0x80 retain ASCII semantics.
const OEM_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";

pub fn decode_oem(name: &[u8]) -> Vec<u8> {
    name.iter().map(|&b| if b < 128 { b as char } else {
        OEM_HIGH.chars().nth((b - 128) as usize).unwrap_or('_')
    }).collect::<String>().into_bytes()
}

pub fn encode_oem(name: &[u8]) -> (Vec<u8>, bool) {
    let mut replaced = false;
    let result = String::from_utf8_lossy(name).chars().map(|ch| {
        if ch.is_ascii() { ch as u8 }
        else if let Some(index) = OEM_HIGH.chars().position(|c| c == ch) { 128 + index as u8 }
        else { replaced = true; b'_' }
    }).collect();
    (result, replaced)
}

pub fn equal(a: &[u8], b: &[u8]) -> bool {
    String::from_utf8_lossy(a).chars().flat_map(char::to_uppercase)
        .eq(String::from_utf8_lossy(b).chars().flat_map(char::to_uppercase))
}

pub struct Path {
    pub vfs: Vec<u8>,
    pub long: Vec<u8>, // OEM drive-qualified DOS name
    pub short: Vec<u8>,
}

impl DfsState {
    /// Lexical LFN normalization; preserves spaces and case. No disk lookup.
    pub fn resolve_lfn(&self, input: &[u8]) -> Result<Vec<u8>, u16> {
        let input = if input.first() == Some(&b'"') && input.last() == Some(&b'"') && input.len() >= 2 {
            &input[1..input.len() - 1]
        } else { input };
        if input.is_empty() { return Err(2); }
        if input.len() > PATH_MAX { return Err(206); }
        let (drive, rest) = if input.get(1) == Some(&b':') {
            (input[0].to_ascii_uppercase(), &input[2..])
        } else { (self.current_drive, input) };
        if !self.drive_available(drive) { return Err(15); }
        let mut combined = Vec::new();
        if !rest.starts_with(b"\\") && !rest.starts_with(b"/") {
            combined.extend_from_slice(self.get_cwd_for(drive).ok_or(15u16)?);
            combined.push(b'\\');
        }
        combined.extend_from_slice(rest);
        let mut components: Vec<&[u8]> = Vec::new();
        for part in combined.split(|b| *b == b'/' || *b == b'\\') {
            if part.is_empty() || part == b"." { continue; }
            if part == b".." { components.pop(); continue; }
            let end = part.iter().rposition(|b| *b != b' ' && *b != b'.').map_or(0, |i| i + 1);
            let part = &part[..end];
            if part.is_empty() || part.iter().any(|b| *b < 32 || b"\"<>|:".contains(b)) { return Err(123); }
            if part.len() > NAME_MAX { return Err(206); }
            components.push(part);
        }
        let mut result = alloc::vec![drive, b':', b'\\'];
        for (i, part) in components.iter().enumerate() {
            if i != 0 { result.push(b'\\'); }
            result.extend_from_slice(part);
        }
        if result.len() > PATH_MAX { return Err(206); }
        Ok(result)
    }

    pub fn lfn_path(&self, input: &[u8], allow_new: bool) -> Result<Path, u16> {
        let absolute = self.resolve_lfn(input)?;
        Self::walk_lfn(&absolute, allow_new)
    }

    pub fn walk_lfn(absolute: &[u8], allow_new: bool) -> Result<Path, u16> {
        let mut prefix = [0; super::DFS_PATH_MAX];
        let (len, rest) = super::strip_drive_prefix(absolute, &mut prefix).map_err(|e| e as u16)?;
        let mut result = Path { vfs: prefix[..len].to_vec(), long: absolute[..3].to_vec(), short: absolute[..3].to_vec() };
        if !vfs::dir_exists(&result.vfs) { return Err(3); }
        let parts: Vec<_> = rest.split(|b| *b == b'\\').filter(|p| !p.is_empty()).collect();
        for (i, part) in parts.iter().enumerate() {
            if part.contains(&b'*') || part.contains(&b'?') { return Err(123); }
            let last = i + 1 == parts.len();
            let decoded = decode_oem(part);
            let (name, alias) = match ci::lookup_lfn(&result.vfs, &decoded) {
                Some((alias, entry)) => {
                    if !last && !entry.is_dir { return Err(3); }
                    (entry.original.clone(), alias.to_vec())
                }
                None if last && allow_new => (decoded, part.to_vec()),
                None => return Err(if last { 2 } else { 3 }),
            };
            if !result.vfs.is_empty() { result.vfs.push(b'/'); }
            result.vfs.extend_from_slice(&name);
            if i != 0 { result.long.push(b'\\'); result.short.push(b'\\'); }
            result.long.extend_from_slice(&encode_oem(&name).0);
            result.short.extend_from_slice(&alias);
        }
        if result.vfs.len() > vfs::PATH_KEY_MAX || result.long.len() > PATH_MAX || result.short.len() > PATH_MAX { return Err(206); }
        Ok(result)
    }

    pub fn chdir_lfn(&mut self, input: &[u8]) -> Result<(), u16> {
        let path = self.lfn_path(input, false)?;
        if !vfs::dir_exists(&path.vfs) { return Err(3); }
        self.set_cwd_for(path.short[0], &path.short[3..]);
        Ok(())
    }

    pub fn cwd_lfn(&self, drive: u8) -> Result<Vec<u8>, u16> {
        let cwd = self.get_cwd_for(drive).ok_or(15u16)?;
        let mut input = alloc::vec![drive, b':', b'\\'];
        input.extend_from_slice(cwd);
        Ok(self.lfn_path(&input, false)?.long[3..].to_vec())
    }

    pub fn lfn_search(&self, input: &[u8], attributes: u16) -> Result<Search, u16> {
        let abs = self.resolve_lfn(input)?;
        let split = abs.iter().rposition(|b| *b == b'\\').ok_or(3u16)?;
        let directory = Self::walk_lfn(&abs[..if split == 2 { 3 } else { split }], false)?.vfs;
        if !vfs::dir_exists(&directory) { return Err(3); }
        let pattern = decode_oem(&abs[split + 1..]);
        if pattern.is_empty() { return Err(2); }
        Ok(Search { directory, pattern, attributes, cursor: 0 })
    }
}

pub struct Found {
    pub name: Vec<u8>,
    pub alias: Vec<u8>,
    pub path: Vec<u8>,
    pub size: u32,
    pub mtime: u32,
    pub attributes: u8,
    pub conversion: u16,
}

pub struct Search {
    directory: Vec<u8>,
    pattern: Vec<u8>,
    attributes: u16,
    cursor: usize,
}

impl Search {
    pub fn next(&mut self) -> Option<Found> {
        while let Some((alias, entry)) = ci::entry_at(&self.directory, self.cursor) {
            self.cursor += 1;
            if !wildcard(&self.pattern, &entry.original) && !wildcard(&self.pattern, &decode_oem(alias)) { continue; }
            let mut path = self.directory.clone();
            if !path.is_empty() { path.push(b'/'); }
            path.extend_from_slice(&entry.original);
            let attributes = vfs::dos_attributes(&path)?;
            if !attributes_match(self.attributes, attributes) { continue; }
            let (name, replaced) = encode_oem(&entry.original);
            return Some(Found { name, alias: alias.to_vec(), path, size: entry.size,
                mtime: entry.mtime, attributes, conversion: u16::from(replaced) });
        }
        None
    }
}

pub fn attributes_match(mask: u16, attributes: u8) -> bool {
    (((mask >> 8) as u8 & !attributes) & 0x3f) == 0 && ((!mask as u8 & attributes) & 0x1e) == 0
}

/// General glob matching (unlike the padded 8.3 FCB matcher). DOS's *.*
/// and trailing .* also match extensionless names.
pub fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    fn matches(pattern: &[char], name: &[char]) -> bool {
        let (mut p, mut n, mut star, mut retry) = (0, 0, None, 0);
        while n < name.len() {
            if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) { p += 1; n += 1; }
            else if p < pattern.len() && pattern[p] == '*' { star = Some(p); p += 1; retry = n; }
            else if let Some(s) = star { retry += 1; n = retry; p = s + 1; }
            else { return false; }
        }
        while p < pattern.len() && (pattern[p] == '*' || pattern[p] == '?') { p += 1; }
        p == pattern.len()
    }
    let p: Vec<char> = String::from_utf8_lossy(pattern).chars().flat_map(char::to_uppercase).collect();
    let n: Vec<char> = String::from_utf8_lossy(name).chars().flat_map(char::to_uppercase).collect();
    matches(&p, &n) || (p.ends_with(&['.', '*']) && matches(&p[..p.len() - 2], &n))
}

pub struct Searches { entries: BTreeMap<u16, Search>, next: u16 }
impl Searches {
    pub const fn new() -> Self { Self { entries: BTreeMap::new(), next: 1 } }
    pub fn insert(&mut self, search: Search) -> Result<u16, u16> {
        if self.entries.len() >= 64 { return Err(4); }
        // No live handle is evicted; handles are not tied to the legacy DTA.
        while self.entries.contains_key(&self.next) || self.next == 0 || self.next == 0xffff {
            self.next = self.next.wrapping_add(1);
        }
        let handle = self.next;
        self.next = self.next.wrapping_add(1);
        self.entries.insert(handle, search);
        Ok(handle)
    }
    pub fn next(&mut self, handle: u16) -> Result<Found, u16> {
        self.entries.get_mut(&handle).ok_or(6u16)?.next().ok_or(18)
    }
    pub fn close(&mut self, handle: u16) -> Result<(), u16> {
        self.entries.remove(&handle).map(|_| ()).ok_or(6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lfn_directory_and_alias_roundtrip_on_fat() {
        use crate::kernel::fs::fat::{FatFs, VolumeIo, tests::formatted};
        let (_, volume) = formatted(fatfs::FatType::Fat12, 2880);
        let fs = alloc::boxed::Box::leak(alloc::boxed::Box::new(FatFs::new(VolumeIo::new(volume, true)).unwrap()));
        vfs::mount(b"host/", fs);
        let mut dfs = DfsState::new_with_hostfs(true);
        let path = dfs.lfn_path(b"H:\\Long directory", true).unwrap();
        assert_eq!(vfs::mkdir(&path.vfs), 0);
        dfs.chdir_lfn(b"H:\\lONG DIRECTORY").unwrap();
        assert_eq!(dfs.cwd_lfn(b'H').unwrap(), b"Long directory");
        let path = dfs.lfn_path(b"H:Mixed case filename.txt", true).unwrap();
        let handle = vfs::create_to_handle(&path.vfs);
        assert!(handle >= 0);
        vfs::close_vfs_handle(handle);
        let path = dfs.lfn_path(b"H:mIXED CASE FILENAME.TXT", false).unwrap();
        assert_eq!(dfs.lfn_path(&path.short, false).unwrap().vfs, path.vfs);
        let mut legacy = alloc::vec![0; vfs::PATH_KEY_MAX];
        let len = DfsState::to_vfs_open(&path.short, &mut legacy).unwrap();
        assert_eq!(&legacy[..len], &path.vfs);
    }
    #[test]
    fn lfn_normalization_preserves_spaces_and_case() {
        let dfs = DfsState::new();
        assert_eq!(dfs.resolve_lfn(b"C:/Mixed case/../Long name.txt").unwrap(), b"C:\\Long name.txt");
        assert_eq!(dfs.resolve_lfn(b"C:\\Long name. ").unwrap(), b"C:\\Long name");
        assert_eq!(dfs.resolve_lfn(&[b'x'; 261]), Err(206));
        assert_eq!(dfs.resolve_lfn(b"Z:\\file"), Err(15));
    }
    #[test]
    fn oem_roundtrip_and_folding() {
        let all: Vec<u8> = (32..=255).collect();
        assert_eq!(OEM_HIGH.chars().count(), 128);
        assert_eq!(encode_oem(&decode_oem(&all)), (all, false));
        assert!(equal("Été.txt".as_bytes(), "été.TXT".as_bytes()));
        assert_eq!(encode_oem("snow☃.txt".as_bytes()), (b"snow_.txt".to_vec(), true));
    }
    #[test]
    fn lfn_wildcards_and_attributes() {
        for (p, n) in [("*.*", "README"), ("*mid*", "a middle.txt"), ("*.TXT", "Long name.txt"), ("name.*", "name")] {
            assert!(wildcard(p.as_bytes(), n.as_bytes()));
        }
        assert!(!wildcard(b"*mid", b"middle.txt"));
        assert!(!attributes_match(0, 0x10));
        assert!(attributes_match(0, 0x21));
        assert!(attributes_match(0x1010, 0x10));
        assert!(!attributes_match(0x1010, 0x20));
    }
}
