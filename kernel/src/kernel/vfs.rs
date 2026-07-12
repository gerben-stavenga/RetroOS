//! Virtual Filesystem layer
//!
//! Provides file open/read/close/seek via a global file table.
//! Thread FD arrays index into this table. FDs 0/1/2 are reserved
//! for stdin/stdout/stderr and handled directly in syscall handlers.
//!
//! Writable overlay: a BTreeMap<Vec<u8>, Vec<u8>> holds RAM-backed files
//! created by DOS programs. create() inserts, open() checks overlay
//! before the backing filesystem, read()/write()/seek() dispatch on the backing type.
//!
//! All VFS state — the mount table, the open-file table, the RAM overlay, and
//! the path/dir caches — is a single kernel-wide singleton (`Vfs`) behind a
//! `spin::Mutex`, so access is borrow-checked and correct under multiple cores.
//! The lock is taken only from kernel/event-loop context (ISRs merely queue), so
//! a plain spinlock suffices. To stay deadlock-free, the *state* lives in `&mut
//! self` methods on `Vfs` (which call each other via `self`, never re-locking);
//! the public free functions are thin wrappers that lock once, and the
//! orchestrators (`open`/`read`/…, which only juggle the caller's fd array and
//! call other public wrappers) never hold the lock across a call. The backing
//! filesystems never call back into `vfs`, so holding the lock across `fs.read`/
//! `fs.open` is safe.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::kernel::thread::FdKind;

/// Maximum simultaneous open files system-wide
const MAX_OPEN_FILES: usize = 64;

/// Maximum file descriptors per thread (must match thread::MAX_FDS)
const MAX_FDS: usize = 32;

/// First usable file descriptor (0=stdin, 1=stdout, 2=stderr)
const FIRST_FD: usize = 3;

/// Sentinel: handle value meaning "RAM-backed file"
const RAM_SENTINEL: u64 = u64::MAX;

/// Maximum length of a normalized path key
const PATH_KEY_MAX: usize = 164;

/// Filesystem trait — implemented by TarFs, Ext4Fs, etc. POSIX-strict; the
/// DOS personality wraps this layer with its own case-folding cache (DFS).
///
/// This is 9P-shaped: `open(path)` is a fused Twalk+Topen returning a fid
/// (`Vnode::handle`), `read`/`write` carry the offset per call (like `Tread`/
/// `Twrite`, so a fid can be shared across independent offsets), `clunk`
/// releases a fid (`Tclunk`), and `remove` deletes a path (`Tremove`).
/// In-process servers implement it as direct calls; a future wire codec can
/// marshal the same operations over virtio-9p / TCP behind this trait.
pub trait Filesystem {
    /// Look up a file by normalized path, case-sensitively (POSIX).
    /// Fused Twalk+Topen: returns a fid (`Vnode::handle`).
    fn open(&self, path: &[u8]) -> Option<Vnode>;

    /// Read from a file identified by handle at given byte offset (Tread).
    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32;

    /// Enumerate directory entries at index. Returns None at end.
    fn readdir(&self, dir: &[u8], index: usize) -> Option<DirEntry>;

    /// Check if a directory path exists.
    fn dir_exists(&self, path: &[u8]) -> bool;

    /// Create (or truncate) a file. Returns vnode on success. Default = R/O.
    fn create(&self, _path: &[u8]) -> Option<Vnode> { None }

    /// Write to a file identified by handle at given byte offset (Twrite).
    /// Returns bytes written, or negative errno. Default = R/O (silently accept).
    fn write(&self, _handle: u64, _offset: u32, data: &[u8]) -> i32 {
        data.len() as i32
    }

    /// Release a fid (Tclunk). Called by the VFS when the last reference to an
    /// open file closes (`close_handle`). Default = no-op, for backends whose
    /// handle owns no per-open resource (TarFs's archive offset). Backends that
    /// allocate per-open server state — ext4's `File` cursor, hostfs's COM1 /
    /// native fid, a future 9P client — override this to free it.
    fn clunk(&self, _handle: u64) {}

    /// Remove a file by path (Tremove). Default = -1 (read-only / unsupported).
    fn remove(&self, _path: &[u8]) -> i32 { -1 }
}

/// Identifies an open file on a filesystem — effectively a 9P fid plus the
/// cached stat fields (`size`, `mode`) the qid/Tstat would carry. An explicit
/// `Tstat` message is deferred until the wire codec needs it.
#[derive(Clone, Copy)]
pub struct Vnode {
    pub handle: u64,  // 9P fid: filesystem-specific opaque handle (RAM_SENTINEL for overlay)
    pub size: u32,
    /// POSIX permission bits (lower 12 — perms + setuid/setgid/sticky).
    /// Carried through from the backing filesystem (TAR's USTAR mode field,
    /// ext4's stat, etc.). Linux personality returns these in stat64.
    pub mode: u16,
}

/// Directory entry returned by readdir
pub struct DirEntry {
    pub name: [u8; 100],
    pub name_len: usize,
    pub size: u32,
    pub is_dir: bool,
    /// POSIX permission bits (same convention as `Vnode::mode`).
    pub mode: u16,
}

/// Stable inode from a path (FNV-1a, forced nonzero). Same path → same ino,
/// distinct paths → distinct ino (modulo hash collisions) — enough for the
/// dynamic linker's object dedup.
fn path_ino(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in path { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    h | 1
}

/// An open file in the global file table
pub struct FileEntry {
    pub vnode: Vnode,
    pub offset: u32,
    pub refcount: u16,
    /// Stable per-file inode (FNV hash of the path). fstat reports it so the
    /// dynamic linker's (st_dev, st_ino) dedup distinguishes libraries — without
    /// it every file shares ino 0 and ld.so thinks libc == the main binary.
    pub ino: u64,
    /// Index into the mount table (which filesystem owns this file)
    pub mount_idx: u8,
    /// For RAM-backed files: normalized path key into the RAM overlay
    pub ram_key: [u8; PATH_KEY_MAX],
    pub ram_key_len: u8,
}

/// How a mount composes with any bindings already at its prefix — Plan 9's
/// mount modes, trimmed to the two we use:
/// - `Replace` — the single-winner mount (Plan 9 MREPL). Mounting `Replace` at
///   a prefix first drops any existing bindings there, so the group has exactly
///   one member. This reproduces the old longest-prefix table bit-for-bit and
///   is the default; every startup mount uses it.
/// - `Union` — stack a layer on top without removing what's there (Plan 9
///   MBEFORE). A union group resolves most-recently-mounted first; `readdir`
///   merges the members (an upper layer shadows a lower one on a name clash).
///
/// (Plan 9's MAFTER — stack at the *bottom* — has no consumer yet.)
#[derive(Clone, Copy, PartialEq)]
enum MountMode { Replace, Union }

/// What a binding points at.
#[derive(Clone, Copy)]
enum BindTarget {
    /// A real filesystem served at this prefix (a mount).
    Server(&'static dyn Filesystem),
    /// A redirect to another namespace path (a bind): a lookup here is retried
    /// as `src_prefix + subpath`, so an existing subtree appears at a second
    /// place (e.g. `bind disk1/games/ → games/`) with no backing fs of its own.
    Alias { src_prefix: &'static [u8] },
}

/// One entry in the namespace: a prefix, what it points at, how it composes,
/// and a monotonic sequence number that gives union members a stable order.
///
/// Prefixes and alias targets are `&'static` — boot-time mounts leak their
/// (one-time, boot-lifetime) prefix, the same discipline the old fixed table
/// used. The table is built entirely at startup before any file is opened, so
/// the `mount_idx` values stored in `file_table` (Vec indices) stay stable —
/// do not mutate the table after boot without revisiting that.
#[derive(Clone, Copy)]
struct Binding {
    prefix: &'static [u8],  // e.g. b"" for root, b"boot/" for sub-mount
    target: BindTarget,
    // NB: the mount MODE (Replace vs Union) is applied when the binding is
    // added (Replace drops peers at the prefix; see `add_binding`) — it does
    // not need to persist per-binding, so it is not stored here.
    seq: u32,
}

/// Max members in one union group (fixed scratch, no alloc on resolve). A
/// union stack is tiny in practice; overflow drops the oldest layers (logged).
const MAX_UNION: usize = 8;

/// Alias (bind) expansion depth cap — breaks any accidental bind cycle.
const ALIAS_DEPTH: u8 = 8;

/// Single-directory readdir cache (avoids O(n²) re-scanning for sequential
/// readdir). One directory cached at a time, growable so a flat dir with
/// hundreds of entries doesn't get truncated.
struct DirCache {
    dir: [u8; 96],
    dir_len: usize,
    entries: Vec<DirEntry>,
    valid: bool,
}

impl DirCache {
    const fn new() -> Self {
        DirCache { dir: [0; 96], dir_len: 0, entries: Vec::new(), valid: false }
    }
}

/// Fallback filesystem for "nothing mounted": every lookup misses.
struct EmptyFs;
impl Filesystem for EmptyFs {
    fn open(&self, _path: &[u8]) -> Option<Vnode> { None }
    fn read(&self, _h: u64, _o: u32, _b: &mut [u8], _s: u32) -> i32 { -2 }
    fn readdir(&self, _dir: &[u8], _index: usize) -> Option<DirEntry> { None }
    fn dir_exists(&self, _path: &[u8]) -> bool { false }
}
static EMPTY_FS: EmptyFs = EmptyFs;

// ============================================================================
// The VFS singleton
// ============================================================================

/// All VFS state, behind one lock. See the module docs for the locking model.
struct Vfs {
    /// The namespace: an ordered, stackable, bind-capable mount table (the
    /// composer). Built at startup; a Replace group is a single member.
    mounts: Vec<Binding>,
    next_seq: u32,
    /// Writable file overlay — persists across open/close cycles.
    ram_files: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Global file table — slot is free when refcount == 0.
    file_table: [FileEntry; MAX_OPEN_FILES],
    dir_cache: DirCache,
}

impl Vfs {
    const fn new() -> Self {
        const EMPTY: FileEntry = FileEntry {
            vnode: Vnode { handle: 0, size: 0, mode: 0 },
            ino: 0,
            offset: 0,
            refcount: 0,
            mount_idx: 0,
            ram_key: [0; PATH_KEY_MAX],
            ram_key_len: 0,
        };
        Vfs {
            mounts: Vec::new(),
            next_seq: 0,
            ram_files: BTreeMap::new(),
            file_table: [EMPTY; MAX_OPEN_FILES],
            dir_cache: DirCache::new(),
        }
    }

    // ── mount table (namespace composer) ─────────────────────────────────

    /// Visit the members serving `path`, highest-priority first, each resolved
    /// to `(mount_idx, fs, subpath)`, calling `f` per member; return the first
    /// `Some` it yields (short-circuit). So `open` stops at the first hit and
    /// `dir_exists` at the first existing dir, while a `readdir` closure that
    /// always returns `None` visits every member in order (union merge). Alias
    /// (bind) targets are expanded by retrying under `src_prefix`, depth-capped.
    ///
    /// For a `Replace` group (every startup mount) there is exactly one member,
    /// so this reduces to the old single-winner longest-prefix lookup.
    fn resolve_members<R>(
        &self,
        path: &[u8],
        depth: u8,
        f: &mut impl FnMut(u8, &'static dyn Filesystem, &[u8]) -> Option<R>,
    ) -> Option<R> {
        // Longest matching prefix length across all bindings.
        let mut best: Option<usize> = None;
        for b in &self.mounts {
            if match_prefix(b.prefix, path).is_some() {
                best = Some(best.map_or(b.prefix.len(), |x| x.max(b.prefix.len())));
            }
        }
        let best = best?;

        // Members at that prefix, ordered most-recently-mounted (highest seq)
        // first. A Replace group is a single member; a union stacks here.
        let mut members = [(0usize, 0u32); MAX_UNION];
        let mut n = 0;
        for (i, b) in self.mounts.iter().enumerate() {
            if b.prefix.len() == best && match_prefix(b.prefix, path).is_some() {
                if n < MAX_UNION {
                    members[n] = (i, b.seq);
                    n += 1;
                } else {
                    crate::dbg_println!(
                        "vfs: union group exceeds {} layers; dropping oldest", MAX_UNION);
                }
            }
        }
        members[..n].sort_by_key(|&(_, seq)| core::cmp::Reverse(seq)); // most-recent (highest seq) first

        for &(i, _) in &members[..n] {
            let b = self.mounts[i];
            let start = match_prefix(b.prefix, path).unwrap();
            let subpath = &path[start..];
            match b.target {
                BindTarget::Server(fs) => {
                    if let Some(r) = f(i as u8, fs, subpath) { return Some(r); }
                }
                BindTarget::Alias { src_prefix } => {
                    if depth == 0 { continue; }
                    // Retry the lookup as `src_prefix + subpath`.
                    let mut buf = [0u8; PATH_KEY_MAX];
                    let (pl, sl) = (src_prefix.len(), subpath.len());
                    if pl + sl > buf.len() { continue; }
                    buf[..pl].copy_from_slice(src_prefix);
                    buf[pl..pl + sl].copy_from_slice(subpath);
                    if let Some(r) = self.resolve_members(&buf[..pl + sl], depth - 1, f) {
                        return Some(r);
                    }
                }
            }
        }
        None
    }

    /// The single highest-priority `Server` member at the longest matching
    /// prefix (non-allocating). Used by `create`/`delete`, which write to the
    /// top layer. Alias heads and an empty table fall back to `EmptyFs` (so a
    /// create on a bound or unmounted path lands on the RAM overlay).
    fn resolve_head<'a>(&self, path: &'a [u8]) -> (u8, &'static dyn Filesystem, &'a [u8]) {
        let mut best: Option<(usize, u32, usize, usize)> = None; // (plen, seq, idx, start)
        for (i, b) in self.mounts.iter().enumerate() {
            if let BindTarget::Server(_) = b.target
                && let Some(start) = match_prefix(b.prefix, path) {
                let better = match best {
                    None => true,
                    Some((bl, bseq, _, _)) =>
                        b.prefix.len() > bl || (b.prefix.len() == bl && b.seq > bseq),
                };
                if better { best = Some((b.prefix.len(), b.seq, i, start)); }
            }
        }
        match best {
            Some((_, _, i, start)) => match self.mounts[i].target {
                BindTarget::Server(fs) => (i as u8, fs, &path[start..]),
                BindTarget::Alias { .. } => unreachable!(),
            },
            None => (0, &EMPTY_FS, path),
        }
    }

    /// If `parent/<name>` (case-insensitive) is itself a mount/bind point,
    /// return its directory component (e.g. parent=`home/retroos`, name=`BOOT`
    /// → `b"boot"`). DFS uses this so a VFS mount point is a traversable
    /// directory even though the parent's *backing* fs has no such readdir
    /// entry. Both Server and Alias bindings expose their prefix here.
    fn mount_child(&self, parent: &[u8], name: &[u8]) -> Option<&'static [u8]> {
        let mut par = parent;
        while par.first() == Some(&b'/') { par = &par[1..]; }
        while par.last() == Some(&b'/') { par = &par[..par.len() - 1]; }
        for b in &self.mounts {
            let prefix: &'static [u8] = b.prefix;
            // Drop the trailing slash mount prefixes carry.
            let p: &'static [u8] = if prefix.last() == Some(&b'/') {
                &prefix[..prefix.len() - 1]
            } else { prefix };
            if p.is_empty() { continue; } // root mount: no child name
            let (dir, last): (&[u8], &'static [u8]) = match p.iter().rposition(|&b| b == b'/') {
                Some(idx) => (&p[..idx], &p[idx + 1..]),
                None => (&b""[..], p),
            };
            if eq_ignore_case(dir, par) && eq_ignore_case(last, name) {
                return Some(last);
            }
        }
        None
    }

    fn mount_fs(&self, idx: u8) -> &'static dyn Filesystem {
        match self.mounts[idx as usize].target {
            BindTarget::Server(fs) => fs,
            // A file handle only ever records a Server member (open resolves
            // through Alias to the fs that actually held the file).
            BindTarget::Alias { .. } => panic!("VFS: file handle points at a bind alias"),
        }
    }

    /// Add a binding. `Replace` first drops any existing bindings at the exact
    /// same prefix (single-winner); `Union` stacks on top. The whole table is
    /// built at startup before any open, so this never reindexes live handles.
    fn add_binding(&mut self, prefix: &'static [u8], target: BindTarget, mode: MountMode) {
        if mode == MountMode::Replace {
            self.mounts.retain(|b| !eq_ignore_case(b.prefix, prefix));
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.mounts.push(Binding { prefix, target, seq });
    }

    fn mount(&mut self, prefix: &'static [u8], fs: &'static dyn Filesystem) {
        self.add_binding(prefix, BindTarget::Server(fs), MountMode::Replace);
    }

    fn mount_union(&mut self, prefix: &'static [u8], fs: &'static dyn Filesystem) {
        self.add_binding(prefix, BindTarget::Server(fs), MountMode::Union);
    }

    fn bind(&mut self, prefix: &'static [u8], src_prefix: &'static [u8], mode: MountMode) {
        self.add_binding(prefix, BindTarget::Alias { src_prefix }, mode);
    }

    // ── file table ───────────────────────────────────────────────────────

    fn alloc_file_entry(&self) -> Option<usize> {
        (0..MAX_OPEN_FILES).find(|&i| self.file_table[i].refcount == 0)
    }

    /// Drop one reference to a file-table entry; at refcount 0 release the slot
    /// and `clunk` the backing fid (Tclunk).
    ///
    /// This is correct because every `open()` gets its *own* fid — there is no
    /// shared-fid cache — so refcount 0 means the last reference to *this* fid
    /// is gone. `dup`/`fork` share one file-table entry (refcount > 1), so the
    /// fid is clunked exactly once, when the last of them closes; two
    /// independent opens of the same path hold distinct fids and clunk
    /// independently. RAM-overlay entries own no backing fid (skip).
    fn close_handle(&mut self, idx: i32) {
        if idx < 0 || (idx as usize) >= MAX_OPEN_FILES { return; }
        let i = idx as usize;
        if self.file_table[i].refcount == 0 { return; }
        self.file_table[i].refcount -= 1;
        if self.file_table[i].refcount == 0 {
            let handle = self.file_table[i].vnode.handle;
            if handle != RAM_SENTINEL {
                let midx = self.file_table[i].mount_idx;
                self.mount_fs(midx).clunk(handle);
            }
        }
    }

    fn add_ref(&mut self, idx: i32) {
        if idx >= 0 && (idx as usize) < MAX_OPEN_FILES {
            self.file_table[idx as usize].refcount += 1;
        }
    }

    // ── dir cache ────────────────────────────────────────────────────────

    fn invalidate_dir_cache(&mut self) {
        self.dir_cache.valid = false;
    }

    /// Populate the directory cache for `dir` (single pass). Layers, top to
    /// bottom (a name from a higher layer shadows the same name lower down):
    /// the RAM overlay (writable, shadows the backing fs — matching `open`'s
    /// RAM-first check), then the union stack of mounted filesystems (most-
    /// recent first), then synthesized mount/bind-point directories.
    fn populate_dir_cache(&mut self, dir: &[u8]) {
        let dlen = dir.len().min(self.dir_cache.dir.len());
        self.dir_cache.dir[..dlen].copy_from_slice(&dir[..dlen]);
        self.dir_cache.dir_len = dlen;

        let mut entries: Vec<DirEntry> = Vec::new();

        // RAM overlay files (writable layer, highest priority).
        for (key, data) in self.ram_files.iter() {
            if let Some(basename) = entry_in_ram_dir(key, dir)
                && !dir_entries_has(&entries, basename) {
                let len = basename.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100], name_len: len, size: data.len() as u32,
                    is_dir: false, mode: 0o644,
                };
                de.name[..len].copy_from_slice(&basename[..len]);
                entries.push(de);
            }
        }

        // Union merge: visit every member of the group in priority order (most
        // recent first); an upper layer shadows a lower one on a name clash.
        // For a Replace group this is just the one backing fs (== old behavior).
        self.resolve_members(dir, ALIAS_DEPTH, &mut |_idx, fs, subpath| {
            let mut idx = 0usize;
            while let Some(e) = fs.readdir(subpath, idx) {
                if !dir_entries_has(&entries, &e.name[..e.name_len]) {
                    entries.push(e);
                }
                idx += 1;
            }
            None::<()>
        });

        // Synthesize mount/bind-point directories that live directly under `dir`.
        for b in &self.mounts {
            if let Some(name) = mount_child_in_dir(b.prefix, dir)
                && !dir_entries_has(&entries, name) {
                let name_len = name.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100], name_len, size: 0, is_dir: true, mode: 0o755,
                };
                de.name[..name_len].copy_from_slice(&name[..name_len]);
                entries.push(de);
            }
        }

        self.dir_cache.entries = entries;
        self.dir_cache.valid = true;
    }

    fn readdir(&mut self, dir: &[u8], index: usize) -> Option<DirEntry> {
        let stale = !self.dir_cache.valid
            || self.dir_cache.dir_len != dir.len()
            || self.dir_cache.dir[..self.dir_cache.dir_len] != *dir;
        if stale {
            self.populate_dir_cache(dir);
        }
        self.dir_cache.entries.get(index).map(clone_dir_entry)
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        // True if any member of the group has this dir. A mount root (and the
        // VFS root) is structurally a directory — a member with an empty
        // subpath answers true without querying the backing fs, which avoids
        // blocking on a mount whose transport is unresponsive (e.g. `ls /`
        // stats the /host mount; a hostfs read with no server attached hangs).
        self.resolve_members(path, ALIAS_DEPTH, &mut |_idx, fs, subpath| {
            if subpath.is_empty() || fs.dir_exists(subpath) { Some(()) } else { None }
        }).is_some()
    }

    // ── open / create / read / write / seek ──────────────────────────────

    fn open_to_handle(&mut self, path: &[u8]) -> i32 {
        // Check RAM overlay first.
        if let Some(data) = self.ram_files.get(path) {
            let size = data.len() as u32;
            let table_idx = match self.alloc_file_entry() {
                Some(i) => i,
                None => return -24,
            };
            let key_len = path.len().min(PATH_KEY_MAX) as u8;
            let mut ram_key = [0u8; PATH_KEY_MAX];
            ram_key[..key_len as usize].copy_from_slice(&path[..key_len as usize]);
            self.file_table[table_idx] = FileEntry {
                vnode: Vnode { handle: RAM_SENTINEL, size, mode: 0o644 },
                ino: path_ino(path),
                offset: 0,
                refcount: 1,
                mount_idx: 0,
                ram_key,
                ram_key_len: key_len,
            };
            return table_idx as i32;
        }

        // Try each member of the group in priority order; first hit wins and
        // its mount_idx is recorded (a Replace group = the single backing fs).
        // Every open gets its OWN fid from `fs.open` — fids are never cached or
        // shared, so `close_handle` can `clunk` this fid at refcount 0 without
        // affecting any other open (see `close_handle`).
        let (midx, vnode) = match self.resolve_members(path, ALIAS_DEPTH, &mut |idx, fs, subpath| {
            fs.open(subpath).map(|v| (idx, v))
        }) {
            Some(x) => x,
            None => return -2,
        };

        let table_idx = match self.alloc_file_entry() {
            Some(i) => i,
            None => return -24,
        };
        self.file_table[table_idx] = FileEntry {
            vnode,
            ino: path_ino(path),
            offset: 0,
            refcount: 1,
            mount_idx: midx,
            ram_key: [0; PATH_KEY_MAX],
            ram_key_len: 0,
        };
        table_idx as i32
    }

    fn create_to_handle(&mut self, path: &[u8]) -> i32 {
        let (midx, fs, subpath) = self.resolve_head(path);
        if let Some(vnode) = fs.create(subpath) {
            let table_idx = match self.alloc_file_entry() {
                Some(i) => i,
                None => return -24,
            };
            self.file_table[table_idx] = FileEntry {
                vnode,
                ino: path_ino(path),
                offset: 0,
                refcount: 1,
                mount_idx: midx,
                ram_key: [0; PATH_KEY_MAX],
                ram_key_len: 0,
            };
            self.invalidate_dir_cache();
            return table_idx as i32;
        }

        let key_len = path.len().min(PATH_KEY_MAX) as u8;
        self.ram_files.insert(path.to_vec(), Vec::new());
        self.invalidate_dir_cache();

        let table_idx = match self.alloc_file_entry() {
            Some(i) => i,
            None => return -24,
        };
        let mut ram_key = [0u8; PATH_KEY_MAX];
        ram_key[..key_len as usize].copy_from_slice(&path[..key_len as usize]);
        self.file_table[table_idx] = FileEntry {
            vnode: Vnode { handle: RAM_SENTINEL, size: 0, mode: 0o644 },
            ino: path_ino(path),
            offset: 0,
            refcount: 1,
            mount_idx: 0,
            ram_key,
            ram_key_len: key_len,
        };
        table_idx as i32
    }

    fn delete(&mut self, path: &[u8]) -> i32 {
        if self.ram_files.remove(path).is_some() {
            self.invalidate_dir_cache();
            return 0;
        }
        // Not a RAM-overlay file: ask the backing filesystem (Tremove). Backends
        // that can't (or are read-only) return the default -1.
        let (_midx, fs, subpath) = self.resolve_head(path);
        let r = fs.remove(subpath);
        if r >= 0 {
            self.invalidate_dir_cache();
        }
        r
    }

    fn read_by_handle(&mut self, handle: i32, buf: &mut [u8]) -> i32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        if self.file_table[h].vnode.handle == RAM_SENTINEL {
            let off = self.file_table[h].offset as usize;
            let klen = self.file_table[h].ram_key_len as usize;
            let key = self.file_table[h].ram_key[..klen].to_vec();
            if let Some(data) = self.ram_files.get(&key) {
                if off >= data.len() { return 0; }
                let avail = data.len() - off;
                let n = buf.len().min(avail);
                buf[..n].copy_from_slice(&data[off..off + n]);
                self.file_table[h].offset += n as u32;
                return n as i32;
            }
            return 0;
        }

        let (mount_idx, fs_handle, offset, size) = {
            let e = &self.file_table[h];
            (e.mount_idx, e.vnode.handle, e.offset, e.vnode.size)
        };
        let n = self.mount_fs(mount_idx).read(fs_handle, offset, buf, size);
        if n > 0 { self.file_table[h].offset += n as u32; }
        n
    }

    fn write_by_handle<A: crate::Arch>(&mut self, _machine: &mut A, handle: i32, data: &[u8]) -> i32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        if self.file_table[h].vnode.handle == RAM_SENTINEL {
            let off = self.file_table[h].offset as usize;
            let klen = self.file_table[h].ram_key_len as usize;
            let key = self.file_table[h].ram_key[..klen].to_vec();
            if let Some(file_data) = self.ram_files.get_mut(&key) {
                let end = off + data.len();
                if end > file_data.len() { file_data.resize(end, 0); }
                file_data[off..end].copy_from_slice(data);
                let new_size = file_data.len() as u32;
                self.file_table[h].offset = end as u32;
                self.file_table[h].vnode.size = new_size;
                return data.len() as i32;
            }
            return -9;
        }

        let (mount_idx, fs_handle, offset) = {
            let e = &self.file_table[h];
            (e.mount_idx, e.vnode.handle, e.offset)
        };
        let n = self.mount_fs(mount_idx).write(fs_handle, offset, data);
        if n > 0 {
            let e = &mut self.file_table[h];
            e.offset += n as u32;
            if e.offset > e.vnode.size { e.vnode.size = e.offset; }
        }
        n
    }

    fn seek_by_handle(&mut self, handle: i32, offset: i32, whence: i32) -> i32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        let size = if self.file_table[h].vnode.handle == RAM_SENTINEL {
            let klen = self.file_table[h].ram_key_len as usize;
            let key = self.file_table[h].ram_key[..klen].to_vec();
            self.ram_files.get(&key).map(|d| d.len() as u32).unwrap_or(0)
        } else {
            self.file_table[h].vnode.size
        };

        let cur = self.file_table[h].offset;
        let new_offset = match whence {
            0 => offset as i64,
            1 => cur as i64 + offset as i64,
            2 => size as i64 + offset as i64,
            _ => return -22,
        };
        if new_offset < 0 { return -22; }
        self.file_table[h].offset = new_offset as u32;
        self.file_table[h].offset as i32
    }

    fn file_size_by_handle(&self, handle: i32) -> u32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        if e.vnode.handle == RAM_SENTINEL {
            let key = &e.ram_key[..e.ram_key_len as usize];
            return self.ram_files.get(key).map(|d| d.len() as u32).unwrap_or(0);
        }
        e.vnode.size
    }

    fn file_ino_by_handle(&self, handle: i32) -> u64 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        e.ino
    }

    fn file_mode_by_handle(&self, handle: i32) -> u16 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        e.vnode.mode
    }
}

// `Vfs` holds `&'static dyn Filesystem`, and some backends are not thread-safe
// in isolation (the ext4 wrapper uses `Rc`/`RefCell` because `ext4_view` is
// single-threaded). This `Send` is nonetheless sound — and SMP-correct, not a
// single-core assumption — because *every* filesystem access goes through
// `&mut self` while the VFS `spin::Mutex` is held, so no filesystem (and no
// `Rc` refcount) is ever touched by two cores at once. The lock serializes all
// FS use; this is the one `unsafe` the locking model earns, in place of the 22
// scattered `static mut` accesses it replaced.
unsafe impl Send for Vfs {}

static VFS: Mutex<Vfs> = Mutex::new(Vfs::new());

// ============================================================================
// Pure helpers (no VFS state)
// ============================================================================

/// Case-insensitive comparison of two byte slices
pub fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Does mount `prefix` match `path`? Returns the index in `path` where the
/// subpath (path-after-prefix) begins, or `None`. The empty prefix (root)
/// matches everything at 0; a path equal to a prefix sans its trailing `/`
/// (e.g. `path="boot"` vs `prefix="boot/"`) matches with an empty subpath.
fn match_prefix(prefix: &[u8], path: &[u8]) -> Option<usize> {
    let plen = prefix.len();
    if prefix.is_empty() {
        Some(0)
    } else if path.len() >= plen && eq_ignore_case(&path[..plen], prefix) {
        Some(plen)
    } else if prefix.last() == Some(&b'/')
        && path.len() == plen - 1
        && eq_ignore_case(path, &prefix[..plen - 1])
    {
        Some(path.len())
    } else {
        None
    }
}

fn alloc_fd(fds: &[FdKind; MAX_FDS]) -> Option<usize> {
    (FIRST_FD..MAX_FDS).find(|&fd| fds[fd].is_none())
}

/// Extract VFS handle from an FdKind, or return -9 (EBADF).
fn vfs_handle(fds: &[FdKind; MAX_FDS], fd: i32) -> Result<i32, i32> {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 { return Err(-9); }
    match fds[fd as usize] {
        FdKind::Vfs(idx) => Ok(idx),
        _ => Err(-9),
    }
}

/// Case-insensitive membership test over already-collected dir entries — the
/// union-merge shadow rule (a name from a higher layer hides it below).
fn dir_entries_has(entries: &[DirEntry], name: &[u8]) -> bool {
    entries.iter().any(|e| eq_ignore_case(&e.name[..e.name_len], name))
}

fn clone_dir_entry(e: &DirEntry) -> DirEntry {
    DirEntry {
        name: e.name,
        name_len: e.name_len,
        size: e.size,
        is_dir: e.is_dir,
        mode: e.mode,
    }
}

/// If a mount prefix is a direct child of `dir`, return the child name.
/// e.g. mount "boot/" in dir "" → Some("boot"), mount "a/b/" in dir "a/" → Some("b").
fn mount_child_in_dir<'a>(prefix: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if prefix.len() <= dir.len() { return None; }
    if !dir.is_empty() && !eq_ignore_case(&prefix[..dir.len()], dir) { return None; }
    let rest = &prefix[dir.len()..];
    let name = rest.strip_suffix(b"/")?;
    if name.is_empty() || name.contains(&b'/') { return None; }
    Some(name)
}

fn entry_in_ram_dir<'a>(entry_name: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if entry_name.len() <= dir.len() { return None; }
    if !dir.is_empty() && !eq_ignore_case(&entry_name[..dir.len()], dir) { return None; }
    let rest = &entry_name[dir.len()..];
    if rest.contains(&b'/') { return None; }
    Some(rest)
}

// ============================================================================
// Public API — thin locking wrappers + lock-free orchestrators.
// Called by syscalls.rs and vm86.rs.
// ============================================================================

/// Mount a filesystem at a prefix (single-winner). Empty prefix = root.
/// Replaces any binding already at that exact prefix.
pub fn mount(prefix: &'static [u8], fs: &'static dyn Filesystem) {
    VFS.lock().mount(prefix, fs);
}

/// Union-mount a filesystem at a prefix: stack it on top of whatever is there
/// (Plan 9 MBEFORE). Lookups try it first; `readdir` merges the layers.
pub fn mount_union(prefix: &'static [u8], fs: &'static dyn Filesystem) {
    VFS.lock().mount_union(prefix, fs);
}

/// Bind: make the subtree at `src_prefix` also appear at `prefix` (a path
/// redirect, no backing fs of its own). `Replace` = single-winner at `prefix`;
/// pass a union bind to stack it over an existing mount there.
pub fn bind(prefix: &'static [u8], src_prefix: &'static [u8]) {
    VFS.lock().bind(prefix, src_prefix, MountMode::Replace);
}

/// Union-bind: like [`bind`] but stacked on top (Plan 9 MBEFORE) so both the
/// bound subtree and whatever was already at `prefix` compose there.
pub fn bind_union(prefix: &'static [u8], src_prefix: &'static [u8]) {
    VFS.lock().bind(prefix, src_prefix, MountMode::Union);
}

/// Open a file by absolute VFS path. Returns fd (>= 3) or negative error.
/// POSIX-strict case-sensitive lookup. (Orchestrator: no lock held across the
/// `open_to_handle` / `close_vfs_handle` wrapper calls.)
pub fn open(path: &[u8], fds: &mut [FdKind; MAX_FDS]) -> i32 {
    let handle = open_to_handle(path);
    if handle < 0 { return handle; }
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => { close_vfs_handle(handle); return -24; }
    };
    fds[fd] = FdKind::Vfs(handle);
    fd as i32
}

/// Read from an open file descriptor. Returns bytes read or negative error.
pub fn read(fd: i32, buf: &mut [u8], fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => read_by_handle(handle, buf),
        Err(e) => e,
    }
}

/// Read entire file contents via fd into a kernel buffer (ignores current offset).
pub fn read_raw(fd: i32, buf: &mut [u8], fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => read_by_handle(handle, buf),
        Err(e) => e,
    }
}

/// Close a file descriptor.
pub fn close(fd: i32, fds: &mut [FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => {
            fds[fd as usize] = FdKind::None;
            close_vfs_handle(handle);
            0
        }
        Err(e) => e,
    }
}

/// Create (or truncate) a writable RAM-backed file by absolute VFS path.
pub fn create(path: &[u8], fds: &mut [FdKind; MAX_FDS]) -> i32 {
    let handle = create_to_handle(path);
    if handle < 0 { return handle; }
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => { close_vfs_handle(handle); return -24; }
    };
    fds[fd] = FdKind::Vfs(handle);
    fd as i32
}

/// Create (or truncate) a file. If the path's mount FS supports `create`,
/// it owns the file; otherwise we fall back to the RAM overlay.
pub fn create_to_handle(path: &[u8]) -> i32 {
    VFS.lock().create_to_handle(path)
}

/// Write to an open file descriptor.
pub fn write<A: crate::Arch>(machine: &mut A, fd: i32, data: &[u8], fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => write_by_handle(machine, handle, data),
        Err(e) => e,
    }
}

/// Delete a RAM-backed file by absolute VFS path.
pub fn delete(path: &[u8]) -> i32 {
    VFS.lock().delete(path)
}

/// Get the size of an open file descriptor.
pub fn file_size(fd: i32, fds: &[FdKind; MAX_FDS]) -> u32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => file_size_by_handle(handle),
        Err(_) => 0,
    }
}

/// Seek on an open file descriptor. whence: 0=SET, 1=CUR, 2=END
pub fn seek(fd: i32, offset: i32, whence: i32, fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => seek_by_handle(handle, offset, whence),
        Err(e) => e,
    }
}

/// Enumerate directory entries at index. Uses a single-pass cache.
pub fn readdir(dir: &[u8], index: usize) -> Option<DirEntry> {
    VFS.lock().readdir(dir, index)
}

/// Check if a directory exists on a mounted filesystem.
pub fn dir_exists(path: &[u8]) -> bool {
    VFS.lock().dir_exists(path)
}

/// If `parent/<name>` (case-insensitive) is a mount point, return its directory
/// component (so a VFS mount is traversable by DFS's component walk).
pub fn mount_child(parent: &[u8], name: &[u8]) -> Option<&'static [u8]> {
    VFS.lock().mount_child(parent, name)
}

// ── Directory handles (Linux `FdKind::Dir`) ─────────────────────────────────
//
// An opendir'd fd must remember WHICH directory it names: getdents64 reads the
// path back through this table. (Listing the thread's cwd instead was a
// busybox-era shortcut — busybox only ever opendir'd "." — that broke
// `ls /path` from real coreutils.) Fixed-size and refcounted like FILE_TABLE;
// fork/dup add a reference, close releases the slot at zero.

const DIR_HANDLES: usize = 32;
pub const DIR_PATH_MAX: usize = 164;

#[derive(Clone, Copy)]
struct DirHandle {
    path: [u8; DIR_PATH_MAX],
    len: u8,
    refcount: u8,
}

static DIR_TABLE: Mutex<[DirHandle; DIR_HANDLES]> =
    Mutex::new([DirHandle { path: [0; DIR_PATH_MAX], len: 0, refcount: 0 }; DIR_HANDLES]);

/// Allocate a directory handle recording `path` (refcount 1), or -24 (EMFILE).
pub fn open_dir_handle(path: &[u8]) -> i32 {
    let mut t = DIR_TABLE.lock();
    for (i, e) in t.iter_mut().enumerate() {
        if e.refcount == 0 {
            let n = path.len().min(DIR_PATH_MAX);
            e.path[..n].copy_from_slice(&path[..n]);
            e.len = n as u8;
            e.refcount = 1;
            return i as i32;
        }
    }
    -24
}

/// Copy the handle's directory path into `buf`; returns its length (0 for a
/// dead/invalid handle — the caller falls back to cwd, the pre-table behavior).
pub fn dir_handle_path(idx: i32, buf: &mut [u8; DIR_PATH_MAX]) -> usize {
    if !(0..DIR_HANDLES as i32).contains(&idx) {
        return 0;
    }
    let t = DIR_TABLE.lock();
    let e = &t[idx as usize];
    if e.refcount == 0 {
        return 0;
    }
    buf[..e.len as usize].copy_from_slice(&e.path[..e.len as usize]);
    e.len as usize
}

/// Increment a dir handle's refcount (Linux fork/dup).
pub fn add_dir_ref(idx: i32) {
    if let Some(e) = DIR_TABLE.lock().get_mut(idx as usize)
        && e.refcount > 0
    {
        e.refcount += 1;
    }
}

/// Decrement a dir handle's refcount; the slot frees at zero.
pub fn close_dir_handle(idx: i32) {
    if let Some(e) = DIR_TABLE.lock().get_mut(idx as usize) {
        e.refcount = e.refcount.saturating_sub(1);
    }
}

/// Decrement refcount for a VFS file table entry (Linux FdKind::Vfs close).
pub fn close_vfs_handle(idx: i32) {
    VFS.lock().close_handle(idx);
}

/// Increment refcount for a VFS file table entry (Linux fork/dup).
pub fn add_vfs_ref(idx: i32) {
    VFS.lock().add_ref(idx);
}

/// Open a file and return the VFS file table index (not an fd slot).
/// Used by Linux syscalls that manage their own FdKind table.
pub fn open_to_handle(path: &[u8]) -> i32 {
    VFS.lock().open_to_handle(path)
}

/// Read from a VFS file table entry by handle index.
pub fn read_by_handle(handle: i32, buf: &mut [u8]) -> i32 {
    VFS.lock().read_by_handle(handle, buf)
}

/// Write to a VFS file table entry by handle index.
pub fn write_by_handle<A: crate::Arch>(machine: &mut A, handle: i32, data: &[u8]) -> i32 {
    VFS.lock().write_by_handle(machine, handle, data)
}

/// Seek on a VFS handle directly.
pub fn seek_by_handle(handle: i32, offset: i32, whence: i32) -> i32 {
    VFS.lock().seek_by_handle(handle, offset, whence)
}

/// Get file size by VFS handle.
pub fn file_size_by_handle(handle: i32) -> u32 {
    VFS.lock().file_size_by_handle(handle)
}

/// Stable inode for an open handle — fstat's st_ino (dynamic-linker dedup).
pub fn file_ino_by_handle(handle: i32) -> u64 {
    VFS.lock().file_ino_by_handle(handle)
}

/// Get POSIX mode bits by VFS handle. Returns 0 for an invalid handle.
pub fn file_mode_by_handle(handle: i32) -> u16 {
    VFS.lock().file_mode_by_handle(handle)
}
