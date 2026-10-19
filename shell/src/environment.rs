//! Bounded, allocation-free session environment for the i486 launcher.
const CAPACITY: usize = 32768;
const MAX_ENTRIES: usize = 128;
pub struct Environment {
    bytes: [u8; CAPACITY],
    offsets: [usize; MAX_ENTRIES],
    used: usize,
    count: usize,
}
impl Environment {
    pub const fn new() -> Self {
        Self { bytes: [0; CAPACITY], offsets: [0; MAX_ENTRIES], used: 0, count: 0 }
    }
    fn entry(&self, index: usize) -> &[u8] {
        let bytes = &self.bytes[self.offsets[index]..self.used];
        &bytes[..bytes.iter().position(|&b| b == 0).unwrap()]
    }
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        (0..self.count).map(|i| self.entry(i)).find_map(|entry|
            entry.strip_prefix(name).and_then(|rest| rest.strip_prefix(b"=")))
    }
    pub fn insert(&mut self, entry: &[u8]) -> Result<(), ()> {
        let equal = entry.iter().position(|&b| b == b'=').ok_or(())?;
        if equal == 0 || entry.contains(&0) { return Err(()); }
        let previous = (0..self.count).find(|&i| self.entry(i).starts_with(&entry[..equal + 1]));
        if self.used + entry.len() + 1 > CAPACITY || previous.is_none() && self.count == MAX_ENTRIES { return Err(()); }
        let slot = previous.unwrap_or(self.count);
        if previous.is_none() { self.count += 1; }
        self.offsets[slot] = self.used;
        self.bytes[self.used..self.used + entry.len()].copy_from_slice(entry);
        self.used += entry.len() + 1;
        Ok(())
    }
    fn default(&mut self, name: &[u8], value: &[u8]) -> Result<(), ()> {
        if self.get(name).is_some() { return Ok(()); }
        let mut entry = [0; 4096];
        let len = name.len() + 1 + value.len();
        if len > entry.len() { return Err(()); }
        entry[..name.len()].copy_from_slice(name);
        entry[name.len()] = b'=';
        entry[name.len() + 1..len].copy_from_slice(value);
        self.insert(&entry[..len])
    }
    pub fn finish(&mut self) -> Result<(), ()> {
        self.default(b"HOME", b"/home/retroos")?;
        let mut home = [0; 1024];
        let value = self.get(b"HOME").ok_or(())?;
        if !value.starts_with(b"/") || value.len() > home.len() { return Err(()); }
        let len = if value == b"/" { 0 } else { value.len() - usize::from(value.ends_with(b"/")) };
        home[..len].copy_from_slice(&value[..len]);
        let mut path = [0; 2048];
        let suffix = b"/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";
        path[..len].copy_from_slice(&home[..len]);
        path[len..len + suffix.len()].copy_from_slice(suffix);
        self.default(b"PATH", &path[..len + suffix.len()])?;
        path[len..len + 5].copy_from_slice(b"/TEMP");
        self.default(b"TMPDIR", &path[..len + 5])?;
        self.default(b"SHELL", b"/bin/sh")?;
        self.default(b"TERM", b"linux")?;
        self.default(b"LANG", b"en_US.UTF-8")
    }
    pub fn pointers(&self) -> [*const u8; MAX_ENTRIES + 1] {
        let mut result = [core::ptr::null(); MAX_ENTRIES + 1];
        for (i, pointer) in result.iter_mut().take(self.count).enumerate() {
            *pointer = self.bytes.as_ptr().wrapping_add(self.offsets[i]);
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_follow_home_and_preserve_overrides() {
        let mut env = Environment::new();
        for e in [b"HOME=/custom/".as_slice(), b"LANG=nl_NL.UTF-8", b"CODEX_HOME=/private/codex"] { env.insert(e).unwrap(); }
        env.finish().unwrap();
        assert!(env.get(b"PATH").unwrap().starts_with(b"/custom/bin:/usr/local/bin:"));
        assert_eq!(env.get(b"TMPDIR"), Some(b"/custom/TEMP".as_slice()));
        assert_eq!(env.get(b"CODEX_HOME"), Some(b"/private/codex".as_slice()));
        assert_eq!(env.get(b"LANG"), Some(b"nl_NL.UTF-8".as_slice()));
        env.insert(b"PATH=").unwrap(); env.insert(b"TMPDIR=/override").unwrap(); env.finish().unwrap();
        assert_eq!(env.get(b"PATH"), Some(b"".as_slice()));
        assert_eq!(env.get(b"TMPDIR"), Some(b"/override".as_slice()));
    }
    #[test]
    fn root_home_and_bad_entries_are_not_truncated() {
        let mut env = Environment::new();
        env.insert(b"HOME=/").unwrap(); env.finish().unwrap();
        assert!(env.get(b"PATH").unwrap().starts_with(b"/bin:"));
        assert_eq!(env.get(b"TMPDIR"), Some(b"/TEMP".as_slice()));
        assert!(env.insert(&[b'x'; CAPACITY]).is_err());
        assert!(env.insert(b"BAD\0=entry").is_err());
        assert!(env.insert(b"missing_equals").is_err());
        env.insert(b"HOME=C:\\DOS").unwrap(); assert!(env.finish().is_err());
    }
}
