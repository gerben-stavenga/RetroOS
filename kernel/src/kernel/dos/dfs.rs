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

pub const DFS_PATH_MAX: usize = 128;
pub const DFS_CWD_MAX: usize = 64;

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

        // Collapse any trailing '\' except the one right after "X:"
        while pos > 3 && out[pos-1] == b'\\' { pos -= 1; }

        Ok(pos)
    }

    /// Convert an absolute DOS path (output of `resolve`) to the VFS form
    /// `vfs::open` expects: drive prefix mapped, `\` → `/`, components
    /// passed through as-is. Both backing filesystems (`tarfs`, `ext4fs`)
    /// match names case-insensitively, so we don't need the
    /// component-by-component canonical-case walk that walked the index
    /// O(N) per component for every open.
    pub fn to_vfs_open(abs_dos: &[u8], out: &mut [u8; DFS_PATH_MAX]) -> Result<usize, i32> {
        let (mut pos, rest) = strip_drive_prefix(abs_dos, out)?;
        for &b in rest {
            if pos >= out.len() { return Err(3); }
            out[pos] = if b == b'\\' { b'/' } else { b };
            pos += 1;
        }
        Ok(pos)
    }

    /// Same as `to_vfs_open` but the final component may not exist yet —
    /// that basename is appended verbatim (uppercase, as produced by
    /// `resolve`). Intermediate directories must exist.
    /// Use for CREATE / UNLINK / RENAME (destination) / MKDIR.
    pub fn to_vfs_create(abs_dos: &[u8], out: &mut [u8; DFS_PATH_MAX]) -> Result<usize, i32> {
        let (mut pos, rest) = strip_drive_prefix(abs_dos, out)?;
        walk_existing(rest, out, &mut pos, /*allow_missing_last=*/true)?;
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
        b'H' => b"host/",
        _ => return Err(15),
    };
    let mut pos = 0;
    for &b in prefix {
        out[pos] = b; pos += 1;
    }
    Ok((pos, &abs_dos[3..]))
}

/// Split `rest` on `\`, look each component up in the current VFS dir
/// (`out[..*pos]`), append the real-case name. Writes `/` separators.
fn walk_existing(
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
            // Double backslash — skip.
            if !is_last { i += 1; }
            continue;
        }

        // Look up `comp` case-insensitively in the directory at out[..*pos].
        let dir_slice = &out[..*pos];
        match find_entry_ci(dir_slice, comp) {
            Some((real, rlen)) => {
                for k in 0..rlen {
                    if *pos >= out.len() { return Err(3); }
                    out[*pos] = real[k]; *pos += 1;
                }
            }
            None => {
                if is_last && allow_missing_last {
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

        if !is_last {
            if *pos >= out.len() { return Err(3); }
            out[*pos] = b'/'; *pos += 1;
            i += 1; // skip '\'
        }
    }
    Ok(())
}

/// Case-insensitive lookup of `name` in directory `dir`. Returns the
/// real-case entry name (up to 100 bytes — TarFs's DirEntry name size).
fn find_entry_ci(dir: &[u8], name: &[u8]) -> Option<([u8; 100], usize)> {
    let mut idx = 0usize;
    loop {
        let entry = vfs::readdir(dir, idx)?;
        let entry_name = &entry.name[..entry.name_len];
        if eq_ignore_case(entry_name, name) {
            let mut buf = [0u8; 100];
            buf[..entry.name_len].copy_from_slice(entry_name);
            return Some((buf, entry.name_len));
        }
        idx += 1;
    }
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == y.to_ascii_uppercase())
}
