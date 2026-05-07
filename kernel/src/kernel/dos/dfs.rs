//! DFS — DOS File System wrapper over VFS.
//!
//! DFS exposes DOS semantics (drive letters, backslashes, uppercase canonical
//! form, case-insensitive lookup) over the case-sensitive VFS. Mirrors
//! DOSBox: the underlying filesystem is Linux-style; DFS walks it
//! component-by-component to map each DOS component to the real on-disk
//! case name. Single-drive-C for now; `H:` maps to the `host/` mount.
//!
//! All DOS INT 21h path-bearing handlers must route through DFS — never
//! touch the raw VFS directly from the DOS layer.
//!
//! Errors follow DOS conventions: 2=file not found, 3=path not found,
//! 15=invalid drive.
//!
//! Cwd is stored per the CDS convention: uppercase, no drive letter,
//! no leading or trailing backslash. Root is the empty string. e.g.
//! `"BORLANDC\BIN"`.
use crate::kernel::vfs;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const DFS_PATH_MAX: usize = 128;
pub const DFS_CWD_MAX: usize = 64;

// ─── CI cache ──────────────────────────────────────────────────────────────
//
// Per-VFS-dir cache mapping `8.3 alias` (uppercased, DOS-visible) → original
// VFS name. The DOS personality is the only place case-folding lives;
// the VFS itself is POSIX-strict.
//
// Cache key: VFS dir path with no trailing `/` ("" = root).
// Entries are kept sorted by alias for O(log N) lookup and cheap iteration
// (find_first/find_next walks in alias order).
//
// Long names that don't fit 8.3 (legal-char, ≤8 base, ≤3 ext) get an alias
// of the form `BASE~N.EXT` (FAT-style) so DOS programs can both see them in
// dir walks and reach them by name.

pub mod ci {
    use super::*;

    pub struct Entry {
        pub original: Vec<u8>,
        pub size: u32,
        pub is_dir: bool,
    }

    /// Per-dir mapping `alias → entry`, sorted by alias.
    type DirCi = Vec<(Vec<u8>, Entry)>;

    static mut CI_CACHE: BTreeMap<Vec<u8>, DirCi> = BTreeMap::new();

    fn cache() -> &'static mut BTreeMap<Vec<u8>, DirCi> {
        unsafe { &mut *(&raw mut CI_CACHE) }
    }

    /// Trim trailing `/` so cache keys are canonical.
    fn norm(vfs_dir: &[u8]) -> &[u8] {
        if vfs_dir.last() == Some(&b'/') { &vfs_dir[..vfs_dir.len() - 1] } else { vfs_dir }
    }

    fn build(vfs_dir: &[u8]) -> DirCi {
        // VFS readdir wants the prefix with a trailing `/` (or empty for root).
        let mut readdir_key = vfs_dir.to_vec();
        if !readdir_key.is_empty() && readdir_key.last() != Some(&b'/') {
            readdir_key.push(b'/');
        }
        let mut entries: DirCi = Vec::new();
        let mut idx = 0usize;
        while let Some(e) = vfs::readdir(&readdir_key, idx) {
            let original = e.name[..e.name_len].to_vec();
            let alias = compute_alias_8_3(&original, &entries);
            entries.push((alias, Entry { original, size: e.size, is_dir: e.is_dir }));
            idx += 1;
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    fn ensure_cached(vfs_dir: &[u8]) -> &'static DirCi {
        let key = norm(vfs_dir);
        let c = cache();
        if !c.contains_key(key) {
            let built = build(key);
            c.insert(key.to_vec(), built);
        }
        c.get(key).unwrap()
    }

    /// Look up `alias` (uppercase 8.3) in `vfs_dir`. Returns the original VFS
    /// name on hit. Populates the cache on miss.
    pub fn lookup(vfs_dir: &[u8], alias: &[u8]) -> Option<&'static [u8]> {
        let dir = ensure_cached(vfs_dir);
        dir.binary_search_by(|(k, _)| k.as_slice().cmp(alias)).ok()
            .map(|i| dir[i].1.original.as_slice())
    }

    /// Get the entry at `idx` in the cache's alias order. Returns `(alias,
    /// size, is_dir)`. Used by find_first/find_next.
    pub fn entry_at(vfs_dir: &[u8], idx: usize) -> Option<(&'static [u8], u32, bool)> {
        let dir = ensure_cached(vfs_dir);
        dir.get(idx).map(|(a, e)| (a.as_slice(), e.size, e.is_dir))
    }

    /// Drop cached entries for `vfs_dir`. Call after writes that can change
    /// the dir's contents (create / unlink / rename).
    pub fn invalidate(vfs_dir: &[u8]) {
        cache().remove(norm(vfs_dir));
    }
}

/// FAT-style 8.3 chars: A-Z 0-9 plus a small set of punctuation. Lowercase
/// letters are "legal" too (they uppercase fine); space and other punct are
/// not. Used to decide whether a name fits 8.3 and to filter chars when
/// generating an alias.
fn is_dos_legal(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\''
        | b'(' | b')' | b'-' | b'@' | b'^' | b'_'
        | b'`' | b'{' | b'}' | b'~')
}

/// True if the name fits a strict DOS 8.3 (single dot, ≤8 base, ≤3 ext, all
/// legal chars) — in which case its uppercase form IS the alias, no `~N`.
fn fits_8_3(name: &[u8]) -> bool {
    let dots: usize = name.iter().filter(|&&b| b == b'.').count();
    if dots > 1 { return false; }
    let (base, ext) = match name.iter().position(|&b| b == b'.') {
        Some(p) => (&name[..p], &name[p + 1..]),
        None => (&name[..], &b""[..]),
    };
    if base.len() > 8 || ext.len() > 3 { return false; }
    if base.is_empty() && ext.is_empty() { return false; }
    base.iter().all(|&b| is_dos_legal(b))
        && ext.iter().all(|&b| is_dos_legal(b))
}

/// Generate the 8.3 alias for `name`, avoiding collisions in `existing`.
/// Short legal names → uppercased verbatim. Long/illegal → `BASE~N.EXT` with
/// N grown until unique; base shrinks as digits grow so alias stays ≤8 base.
fn compute_alias_8_3(name: &[u8], existing: &[(Vec<u8>, ci::Entry)]) -> Vec<u8> {
    if fits_8_3(name) {
        return name.iter().map(|b| b.to_ascii_uppercase()).collect();
    }

    let last_dot = name.iter().rposition(|&b| b == b'.').unwrap_or(name.len());
    let base_src = &name[..last_dot];
    let ext_src = if last_dot < name.len() { &name[last_dot + 1..] } else { &b""[..] };

    let base_clean: Vec<u8> = base_src.iter()
        .filter(|&&b| is_dos_legal(b))
        .map(|b| b.to_ascii_uppercase())
        .collect();
    let ext_clean: Vec<u8> = ext_src.iter()
        .filter(|&&b| is_dos_legal(b))
        .map(|b| b.to_ascii_uppercase())
        .take(3)
        .collect();

    let alias_taken = |a: &[u8], existing: &[(Vec<u8>, ci::Entry)]| -> bool {
        existing.iter().any(|(k, _)| k.as_slice() == a)
    };

    for n in 1u32..=999_999 {
        let mut digits = [0u8; 8];
        let mut dlen = 0;
        let mut nn = n;
        let mut tmp = [0u8; 8];
        let mut tlen = 0;
        if nn == 0 { tmp[0] = b'0'; tlen = 1; }
        while nn > 0 { tmp[tlen] = b'0' + (nn % 10) as u8; tlen += 1; nn /= 10; }
        for i in 0..tlen { digits[i] = tmp[tlen - 1 - i]; }
        let dn = &digits[..tlen];

        // base + ~ + dn ≤ 8 chars; reserve room for `~` and the digits.
        let max_base = 8usize.saturating_sub(1 + dn.len());
        let prefix_len = base_clean.len().min(max_base);

        let mut alias = Vec::with_capacity(8 + 1 + 3);
        alias.extend_from_slice(&base_clean[..prefix_len]);
        alias.push(b'~');
        alias.extend_from_slice(dn);
        if !ext_clean.is_empty() {
            alias.push(b'.');
            alias.extend_from_slice(&ext_clean);
        }
        if !alias_taken(&alias, existing) {
            return alias;
        }
    }
    // Ran out of digits — fall back to a guaranteed-unique key. Shouldn't
    // happen in practice (>1M same-prefix files in one dir).
    name.iter().map(|b| b.to_ascii_uppercase()).collect()
}

/// Per-thread DOS filesystem state.
pub struct DfsState {
    cwd: [u8; DFS_CWD_MAX],
    cwd_len: u8,
}

impl DfsState {
    pub const fn new() -> Self {
        Self { cwd: [0; DFS_CWD_MAX], cwd_len: 0 }
    }

    /// Cwd per AH=47 convention: no drive, no leading `\`, no trailing `\`.
    pub fn get_cwd(&self) -> &[u8] {
        &self.cwd[..self.cwd_len as usize]
    }

    /// Overwrite cwd with `new_cwd` (expected already in AH=47 form).
    pub fn set_cwd(&mut self, new_cwd: &[u8]) {
        let n = new_cwd.len().min(DFS_CWD_MAX);
        self.cwd[..n].copy_from_slice(&new_cwd[..n]);
        self.cwd_len = n as u8;
    }

    /// Initialize DFS cwd from a VFS-form path (lowercase, forward-slash).
    /// Strips leading/trailing `/`, uppercases, converts `/` to `\`.
    /// Called when a DOS thread is spawned by non-DOS code.
    pub fn init_from_vfs(&mut self, vfs_cwd: &[u8]) {
        let mut s = vfs_cwd;
        while s.first() == Some(&b'/') { s = &s[1..]; }
        while s.last() == Some(&b'/') { s = &s[..s.len()-1]; }
        let n = s.len().min(DFS_CWD_MAX);
        for i in 0..n {
            let b = s[i];
            self.cwd[i] = if b == b'/' { b'\\' } else { b.to_ascii_uppercase() };
        }
        self.cwd_len = n as u8;
    }

    /// Resolve a DOS input path to absolute DOS form `"X:\UPPER\PATH"`.
    /// Rules (matching DOS/CDS semantics):
    ///   - "X:..."         → drive X (ignored cwd unless no `\` after colon)
    ///   - "\..." / "/..." → current drive's root
    ///   - other           → current drive's cwd + path
    /// All `/` become `\`, all letters uppercased.
    /// Currently only drive C has a tracked cwd; all other drives start at root.
    pub fn resolve(&self, dos_in: &[u8], out: &mut [u8; DFS_PATH_MAX]) -> Result<usize, i32> {
        let mut pos: usize = 0;

        // Parse optional drive prefix.
        let (drive, rest) = if dos_in.len() >= 2 && dos_in[1] == b':' {
            (dos_in[0].to_ascii_uppercase(), &dos_in[2..])
        } else {
            (b'C', dos_in)
        };

        // Emit "X:\"
        if pos + 3 > out.len() { return Err(3); }
        out[pos] = drive; out[pos+1] = b':'; out[pos+2] = b'\\';
        pos += 3;

        let absolute = !rest.is_empty() && (rest[0] == b'\\' || rest[0] == b'/');
        let rest = if absolute { &rest[1..] } else { rest };

        if !absolute && drive == b'C' {
            let cwd = self.get_cwd();
            for &b in cwd {
                if pos >= out.len() { return Err(3); }
                out[pos] = b; pos += 1;
            }
            if !cwd.is_empty() && !rest.is_empty() {
                if pos >= out.len() { return Err(3); }
                out[pos] = b'\\'; pos += 1;
            }
        }

        for &b in rest {
            if pos >= out.len() { return Err(3); }
            out[pos] = if b == b'/' { b'\\' } else { b.to_ascii_uppercase() };
            pos += 1;
        }

        // Collapse `.` and `..` components in place. NC issues
        // INT 21 AH=3Bh with literal ".." when navigating up; DN tracks
        // cwd itself and sends the parent absolute path, which is why
        // it never tripped this. Without collapsing, we hand
        // "C:\GAMES\PRINCE\.." to the VFS and get path-not-found.
        pos = collapse_dots(out, pos);

        // Collapse any trailing '\' except the one right after "X:"
        while pos > 3 && out[pos-1] == b'\\' { pos -= 1; }

        Ok(pos)
    }

    /// Convert an absolute DOS path (output of `resolve`) to the VFS form
    /// `vfs::open` expects. Walks each DOS component through DFS's per-dir
    /// CI cache to recover the canonical (mixed-case) VFS name; the VFS
    /// itself is POSIX-strict.
    pub fn to_vfs_open(abs_dos: &[u8], out: &mut [u8; DFS_PATH_MAX]) -> Result<usize, i32> {
        let (mut pos, rest) = strip_drive_prefix(abs_dos, out)?;
        walk_components(rest, out, &mut pos, /*allow_missing_last=*/false)?;
        Ok(pos)
    }

    /// Same as `to_vfs_open` but the final component may not exist yet —
    /// that basename is appended verbatim (uppercase, as produced by
    /// `resolve`). Intermediate directories must exist.
    /// Use for CREATE / UNLINK / RENAME (destination) / MKDIR.
    pub fn to_vfs_create(abs_dos: &[u8], out: &mut [u8; DFS_PATH_MAX]) -> Result<usize, i32> {
        let (mut pos, rest) = strip_drive_prefix(abs_dos, out)?;
        walk_components(rest, out, &mut pos, /*allow_missing_last=*/true)?;
        Ok(pos)
    }

    /// Change directory to `dos_in`. Returns 0 on success, else DOS error.
    /// Only drive C is supported.
    pub fn chdir(&mut self, dos_in: &[u8]) -> i32 {
        let mut abs = [0u8; DFS_PATH_MAX];
        let alen = match self.resolve(dos_in, &mut abs) {
            Ok(n) => n,
            Err(e) => return e,
        };
        // Only drive C can be current-dir'd (H: has no CDS slot yet).
        if abs[0] != b'C' { return 15; }

        // Walk the path as an existing directory.
        let mut vfs_buf = [0u8; DFS_PATH_MAX];
        let vlen = match Self::to_vfs_open(&abs[..alen], &mut vfs_buf) {
            Ok(n) => n,
            Err(e) => return e,
        };
        if !vfs::dir_exists(&vfs_buf[..vlen]) { return 3; }

        // Store new cwd as the chunk after "C:\", converted to AH=47 form.
        // `abs[3..alen]` is already uppercase backslash DOS form.
        let new_cwd = &abs[3..alen];
        self.set_cwd(new_cwd);
        0
    }
}

/// Convert a VFS-form path back to drive-qualified DOS form. Used only on
/// the initial exec path, where we have an already-resolved VFS path and
/// need a DOS form for the env program-path suffix. `host/foo` → `H:\FOO`,
/// anything else → `C:\REST` (uppercased, `/` → `\`).
pub fn vfs_to_dos(vfs: &[u8], out: &mut [u8; DFS_PATH_MAX]) -> usize {
    let mut s = vfs;
    while s.first() == Some(&b'/') { s = &s[1..]; }
    let (drive, rest) = if s.len() >= 5 && s[..5].eq_ignore_ascii_case(b"host/") {
        (b'H', &s[5..])
    } else if s.len() == 4 && s.eq_ignore_ascii_case(b"host") {
        (b'H', &b""[..])
    } else {
        (b'C', s)
    };
    let mut pos = 0;
    if pos + 3 > out.len() { return pos; }
    out[pos] = drive; out[pos+1] = b':'; out[pos+2] = b'\\';
    pos += 3;
    for &b in rest {
        if pos >= out.len() { break; }
        out[pos] = if b == b'/' { b'\\' } else { b.to_ascii_uppercase() };
        pos += 1;
    }
    pos
}

// ─── internal helpers ────────────────────────────────────────────────────────

/// Map `"X:\..."` → VFS prefix. Writes the prefix into `out`, returns the new
/// `pos` and the remaining DOS path (after `"X:\"`).
fn strip_drive_prefix<'a>(abs_dos: &'a [u8], out: &mut [u8; DFS_PATH_MAX])
    -> Result<(usize, &'a [u8]), i32>
{
    if abs_dos.len() < 3 || abs_dos[1] != b':' || abs_dos[2] != b'\\' {
        return Err(3);
    }
    let prefix: &[u8] = match abs_dos[0] {
        b'C' => b"",
        b'H' => b"host",
        _ => return Err(15),
    };
    let mut pos = 0;
    for &b in prefix {
        out[pos] = b; pos += 1;
    }
    Ok((pos, &abs_dos[3..]))
}

/// Walk DOS path components, mapping each through the CI cache to its
/// VFS-canonical name. Each component arrives uppercased (output of
/// `resolve`); the cache key is also uppercase so it's a direct match.
/// Writes the resolved VFS path into `out` starting at `*pos`.
///
/// `allow_missing_last`: when true, a final component that's not in the
/// cache is written verbatim (used by CREATE — the basename doesn't exist
/// yet). Otherwise a missing final component is `2` (file not found) and a
/// missing intermediate is `3` (path not found).
fn walk_components(
    rest: &[u8],
    out: &mut [u8; DFS_PATH_MAX],
    pos: &mut usize,
    allow_missing_last: bool,
) -> Result<(), i32> {
    if rest.is_empty() { return Ok(()); }

    let mut i = 0;
    while i < rest.len() {
        let start = i;
        while i < rest.len() && rest[i] != b'\\' { i += 1; }
        let comp = &rest[start..i];
        let is_last = i == rest.len();

        if comp.is_empty() {
            if !is_last { i += 1; }
            continue;
        }

        // `pos > 0` ⇒ we've already written a parent path, append a slash
        // before the next component. The `out[..*pos]` slice (without the
        // trailing slash) is the cache key.
        let dir_slice = &out[..*pos];
        match ci::lookup(dir_slice, comp) {
            Some(original) => {
                if *pos > 0 {
                    if *pos >= out.len() { return Err(3); }
                    out[*pos] = b'/'; *pos += 1;
                }
                for &b in original {
                    if *pos >= out.len() { return Err(3); }
                    out[*pos] = b; *pos += 1;
                }
            }
            None => {
                if is_last && allow_missing_last {
                    if *pos > 0 {
                        if *pos >= out.len() { return Err(3); }
                        out[*pos] = b'/'; *pos += 1;
                    }
                    for &b in comp {
                        if *pos >= out.len() { return Err(3); }
                        out[*pos] = b; *pos += 1;
                    }
                } else if is_last {
                    return Err(2); // file not found
                } else {
                    return Err(3); // path not found
                }
            }
        }

        if !is_last { i += 1; }
    }
    Ok(())
}

/// Collapse `.` and `..` components in an absolute DOS path
/// `"X:\..."`. `..` pops the previous component; never goes below the
/// `"X:\"` root. Returns new length.
fn collapse_dots(buf: &mut [u8], len: usize) -> usize {
    const ROOT_END: usize = 3; // "X:\"
    if len <= ROOT_END { return len; }
    let mut write = ROOT_END;
    let mut read = ROOT_END;
    while read < len {
        while read < len && buf[read] == b'\\' { read += 1; }
        if read >= len { break; }
        let comp_start = read;
        while read < len && buf[read] != b'\\' { read += 1; }
        let comp_len = read - comp_start;
        let is_dot = comp_len == 1 && buf[comp_start] == b'.';
        let is_dotdot = comp_len == 2 && buf[comp_start] == b'.' && buf[comp_start + 1] == b'.';
        if is_dot {
            // skip
        } else if is_dotdot {
            // pop last written component (and its leading '\')
            while write > ROOT_END && buf[write - 1] != b'\\' { write -= 1; }
            if write > ROOT_END { write -= 1; }
        } else {
            if write > ROOT_END {
                buf[write] = b'\\';
                write += 1;
            }
            // write <= comp_start always (read advances first), so the
            // forward in-place copy can't clobber unread source bytes.
            for i in 0..comp_len {
                buf[write + i] = buf[comp_start + i];
            }
            write += comp_len;
        }
    }
    write
}
