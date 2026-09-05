//! Virtual Filesystem layer
//!
//! Provides file open/read/close/seek via a global file table.
//! Thread FD arrays index into this table. FDs 0/1/2 are reserved
//! for stdin/stdout/stderr and handled directly in syscall handlers.
//!
//! Disk volatility is composed below filesystems by the block-device RAM
//! overlay. VFS itself has no RAM-specific data path.
//!
//! All VFS state — the mount table, open-file table, and path/dir caches — is
//! a single kernel-wide singleton (`Vfs`) behind a
//! `spin::Mutex`, so access is borrow-checked and correct under multiple cores.
//! The lock is taken only from kernel/event-loop context (ISRs merely queue), so
//! a plain spinlock suffices. To stay deadlock-free, the *state* lives in `&mut
//! self` methods on `Vfs` (which call each other via `self`, never re-locking);
//! the public free functions are thin wrappers that lock once, and the
//! orchestrators (`open`/`read`/…, which only juggle the caller's fd array and
//! call other public wrappers) never hold the lock across a call. The backing
//! filesystems never call back into `vfs`, so holding the lock across `fs.read`/
//! `fs.open` is safe.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;
use crate::kernel::thread::{FdKind, MAX_FDS};
use crate::kernel::fs::grant::WriteAccess;

/// First usable file descriptor (0=stdin, 1=stdout, 2=stderr)
const FIRST_FD: usize = 3;

/// Maximum length of a normalized path key
const PATH_KEY_MAX: usize = 164;

type LayerVisitor<'a> =
    dyn FnMut(u8, &'static dyn Filesystem, &[u8]) -> bool + 'a;

/// Filesystem trait — implemented by PortableExt4Fs, HostFs, etc. POSIX-strict; the
/// DOS personality wraps this layer with its own case-folding cache (DFS).
///
/// This is 9P-shaped: `open(path)` is a fused Twalk+Topen returning a fid
/// (`Vnode::handle`), `read`/`write` carry the offset per call (like `Tread`/
/// `Twrite`, so a fid can be shared across independent offsets), `clunk`
/// releases a fid (`Tclunk`), and `remove` deletes a path (`Tremove`).
/// In-process servers implement it as direct calls; a future wire codec can
/// marshal the same operations over virtio-9p / TCP behind this trait.
/// Ownership and permission FACTS about an object — what the filesystem
/// records, with no judgement about what it means.
///
/// Deciding whether RetroOS may write something is policy and lives above
/// (see `kernel::fs::grant`); a filesystem only reports.
#[derive(Clone, Copy)]
pub struct Meta {
    pub uid: u32,
    pub gid: u32,
    /// POSIX mode bits.
    pub mode: u32,
}

pub trait Filesystem {
    /// Look up a file by normalized path, case-sensitively (POSIX).
    /// Fused Twalk+Topen: returns a fid (`Vnode::handle`).
    fn open(&self, path: &[u8]) -> Option<Vnode>;

    /// Open an opaque node identity previously returned by `readdir`.
    /// Backends without stable node identities retain path-based lookup.
    fn open_node(&self, _node: u64) -> Option<Vnode> { None }

    /// Decode the content of a symlink node. This exposes filesystem format;
    /// interpreting the returned path belongs to the VFS.
    fn readlink_node(&self, _node: u64, _out: &mut [u8]) -> Option<usize> { None }

    /// Root identity and inode-based directory enumeration for filesystems
    /// whose native interface is node-oriented.
    fn root_node(&self) -> Option<u64> { None }
    fn readdir_node(
        &self,
        _node: u64,
        _cookie: u64,
        _out: &mut Vec<DirEntry>,
        _max: usize,
    ) -> Option<u64> {
        None
    }

    /// Read a symbolic link without following its final component.
    /// Returns the number of target bytes copied (there is no trailing NUL).
    fn readlink(&self, _path: &[u8], _out: &mut [u8]) -> Option<usize> {
        None
    }

    /// Look up an object without allocating a persistent open handle.  This
    /// keeps stat/lstat from doing separate directory, symlink, and file
    /// probes, which is especially expensive for block-backed filesystems.
    fn stat(&self, path: &[u8], follow_final: bool) -> Option<Stat> {
        if !follow_final {
            let mut target = [0u8; DIR_PATH_MAX];
            if let Some(size) = self.readlink(path, &mut target) {
                return Some(Stat {
                    size: size as u32,
                    mode: 0o777,
                    is_dir: false,
                    is_symlink: true,
                    ino: 0,
                });
            }
        }
        if self.dir_exists(path) {
            return Some(Stat { size: 0, mode: 0o755, is_dir: true, is_symlink: false, ino: 0 });
        }
        let vnode = self.open(path)?;
        let result = Stat {
            size: vnode.size,
            mode: vnode.mode,
            is_dir: false,
            is_symlink: false,
            ino: 0,
        };
        self.clunk(vnode.handle);
        Some(result)
    }

    /// Read from a file identified by handle at given byte offset (Tread).
    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32;

    /// Append up to `max` directory entries to `out`, resuming at `cookie`
    /// (`READDIR_START` begins a fresh enumeration). Returns the cookie to
    /// resume from, or `None` once the directory is exhausted.
    ///
    /// The cookie is OPAQUE and filesystem-defined — a backend may use its raw
    /// directory byte offset, tarfs a logical entry index. A caller may only
    /// ever pass back a value this same filesystem handed it; synthesizing
    /// one, or doing arithmetic on one, is meaningless.
    ///
    /// This is deliberately not an "entry at index N" call. That shape forces
    /// every backend to restart the directory on each entry — n opens and
    /// n(n+1)/2 dirent steps to list n files — because a bare index carries
    /// no resumable state. It is also a question ext4 cannot answer cheaply:
    /// htree directories are hash-ordered, so "the 47th entry" only exists by
    /// counting to it.
    ///
    /// Implementations MUST make progress: either append at least one entry,
    /// or return a cookie different from the one passed in (or `None`).
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64>;

    /// Check if a directory path exists.
    fn dir_exists(&self, path: &[u8]) -> bool;

    /// Create (or truncate) a file. Returns vnode on success. Default = R/O.
    fn create(&self, _path: &[u8]) -> Option<Vnode> { None }

    /// Does this backend implement `create` at all?
    ///
    /// Distinguishes an unsupported operation from a supported create that
    /// failed. VFS never substitutes another filesystem.
    fn supports_create(&self) -> bool { false }

    /// Create a directory. Returns 0 on success, negative errno on failure.
    fn mkdir(&self, _path: &[u8]) -> i32 { -38 }

    /// Does this backend implement directory creation?
    fn supports_mkdir(&self) -> bool { false }

    fn rmdir(&self, _path: &[u8]) -> i32 { -38 }
    fn rename(&self, _path: &[u8], _new_path: &[u8]) -> i32 { -38 }
    fn supports_directory_mutation(&self) -> bool { false }
    fn flush(&self, _path: &[u8]) -> i32 { 0 }
    fn mtime(&self, _path: &[u8]) -> Option<u32> { None }
    fn set_mtime(&self, _path: &[u8], _mtime: u32) -> bool { false }

    /// Write to a file identified by handle at given byte offset (Twrite).
    /// Returns bytes written, or negative errno. Default = R/O (silently accept).
    fn write(&self, _handle: u64, _offset: u32, data: &[u8]) -> i32 {
        data.len() as i32
    }

    /// Release a fid (Tclunk). Called by the VFS when the last reference to an
    /// open file closes (`close_handle`). Default = no-op, for backends whose
    /// handle owns no per-open resource (TarFs's archive offset). Backends that
    /// allocate per-open server state — an ext inode, hostfs's COM1 /
    /// native fid, a future 9P client — override this to free it.
    fn clunk(&self, _handle: u64) {}

    /// Remove a file by path (Tremove). Default = -1 (read-only / unsupported).
    fn remove(&self, _path: &[u8]) -> i32 { -1 }

    /// Ownership/permission facts for `path`, if this filesystem keeps any.
    /// `None` = it has no such concept (a TAR, say), which callers must read
    /// as "cannot be judged", not "permitted".
    fn meta(&self, _path: &[u8]) -> Option<Meta> {
        None
    }

    /// Set ownership and mode. False if unsupported or the write failed.
    fn set_meta(&self, _path: &[u8], _uid: u32, _gid: u32, _mode: u32) -> bool {
        false
    }

}

/// Identifies an open file on a filesystem — effectively a 9P fid plus the
/// cached stat fields (`size`, `mode`) the qid/Tstat would carry. An explicit
/// `Tstat` message is deferred until the wire codec needs it.
#[derive(Clone, Copy)]
pub struct Vnode {
    pub handle: u64,  // filesystem-specific opaque handle
    pub size: u32,
    /// POSIX permission bits (lower 12 — perms + setuid/setgid/sticky).
    /// Carried through from the backing filesystem (TAR's USTAR mode field,
    /// ext4's stat, etc.). Linux personality returns these in stat64.
    pub mode: u16,
}

/// Path metadata used by stat-like calls. Unlike `Vnode`, this does not own a
/// filesystem handle and can describe directories and symbolic links.
#[derive(Clone, Copy)]
pub struct Stat {
    pub size: u32,
    pub mode: u16,
    pub is_dir: bool,
    pub is_symlink: bool,
    /// Stable VFS inode. Backends may leave this zero; the namespace layer
    /// fills it from the resolved path.
    pub ino: u64,
}

/// Directory entry returned by readdir
pub struct DirEntry {
    pub name: [u8; 100],
    pub name_len: usize,
    pub size: u32,
    pub is_dir: bool,
    /// The entry itself is a symbolic link. `is_dir` describes the entry,
    /// not its target; personalities may choose whether links are transparent.
    pub is_symlink: bool,
    /// POSIX permission bits (same convention as `Vnode::mode`).
    pub mode: u16,
    /// Last-modified time, seconds since the Unix epoch. `0` = unknown, which
    /// backends without a clock (tarfs entries predating the field, the COM1
    /// hostfs wire) report; DOS renders that as an empty date rather than as
    /// 1970, which would look like a real timestamp.
    pub mtime: u32,
    /// Opaque identity supplied by the backing filesystem. A zero identity
    /// means that this backend supports path-based lookup only.
    pub(crate) node: u64,
    /// Filled by the VFS while merging a directory's mounted layers.
    pub(crate) mount_idx: u8,
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
    /// Decided once at open/create, when the PATH was still in hand: may
    /// RetroOS write through this handle? `write` only receives a handle, so
    /// the verdict has to be remembered rather than re-derived.
    pub writable: bool,
    pub access: OpenAccess,
    pub share: SharePolicy,
    /// Resolved path retained for path-oriented metadata operations.
    pub path: [u8; PATH_KEY_MAX],
    pub path_len: u8,
}

#[derive(Clone, Copy)]
struct FileLock { ino: u64, owner: i32, start: u32, len: u32 }

#[derive(Clone, Copy)]
pub enum OpenAccess { Read, Write, ReadWrite }

#[derive(Clone, Copy)]
pub enum SharePolicy { Compatibility, DenyAll, DenyWrite, DenyRead, DenyNone }

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

/// One entry in the namespace: a prefix, what it points at, and its write
/// policy. Bindings are stored oldest-to-newest; reverse iteration is union
/// priority order.
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
    /// Who decides writes here. Enforced by the VFS itself (see `may_write`) —
    /// never by a driver, and never by a wrapper a mount site could forget.
    access: crate::kernel::fs::grant::WriteAccess,
    // NB: the mount MODE (Replace vs Union) is applied when the binding is
    // added (Replace drops peers at the prefix; see `add_binding`) — it does
    // not need to persist per-binding, so it is not stored here.
}

struct ResolvedObject {
    mount_idx: u8,
    fs: &'static dyn Filesystem,
    subpath: [u8; PATH_KEY_MAX],
    subpath_len: u8,
    stat: Stat,
}

impl ResolvedObject {
    fn new(
        mount_idx: u8,
        fs: &'static dyn Filesystem,
        subpath: &[u8],
        stat: Stat,
    ) -> Option<Self> {
        if subpath.len() > PATH_KEY_MAX { return None; }
        let subpath_len = u8::try_from(subpath.len()).ok()?;
        let mut path = [0; PATH_KEY_MAX];
        path[..subpath.len()].copy_from_slice(subpath);
        Some(Self { mount_idx, fs, subpath: path, subpath_len, stat })
    }

    fn subpath(&self) -> &[u8] {
        &self.subpath[..usize::from(self.subpath_len)]
    }
}

/// Max members visited in one union group. A union stack is tiny in practice;
/// overflow drops the oldest layers (logged).
const MAX_UNION: usize = 8;

/// Alias (bind) expansion depth cap — breaks any accidental bind cycle.
const ALIAS_DEPTH: u8 = 8;

/// The cookie that starts a fresh directory enumeration.
pub const READDIR_START: u64 = 0;

/// Entries requested per `Filesystem::readdir` call. Each batch costs one
/// directory open in the backend, so this trades a little scratch memory for
/// far fewer opens: a 341-entry directory takes 6 calls instead of 341.
const READDIR_BATCH: usize = 64;

/// A directory listing owned by the namespace layer. Backends enumerate;
/// name lookup is performed against these retained listings.
struct DirCache {
    dir: Vec<u8>,
    entries: Vec<DirEntry>,
    names: BTreeMap<Vec<u8>, usize>,
}

impl DirCache {
    fn new(
        dir: &[u8],
        entries: Vec<DirEntry>,
        names: BTreeMap<Vec<u8>, usize>,
    ) -> Self {
        Self { dir: dir.to_vec(), entries, names }
    }
}

/// Fallback filesystem for "nothing mounted": every lookup misses.
struct EmptyFs;
impl Filesystem for EmptyFs {
    fn open(&self, _path: &[u8]) -> Option<Vnode> { None }
    fn read(&self, _h: u64, _o: u32, _b: &mut [u8], _s: u32) -> i32 { -2 }
    fn readdir(&self, _d: &[u8], _c: u64, _o: &mut Vec<DirEntry>, _m: usize) -> Option<u64> { None }
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
    /// Metadata overrides for backends which cannot persist it.
    modes: BTreeMap<Vec<u8>, u32>,
    mtimes: BTreeMap<Vec<u8>, u32>,
    locks: Vec<FileLock>,
    /// Stable open-file indices. Closed slots are reused and the table grows
    /// with demand; process handle limits belong to each process's fd/JFT.
    file_table: Vec<FileEntry>,
    dir_cache: Vec<DirCache>,
    /// Changes whenever directory-visible metadata may have changed. DOS's
    /// 8.3 cache keys off this so a file grown after create is not forever
    /// reported with its original zero size.
    dir_generation: u64,
}

impl Vfs {
    const fn new() -> Self {
        Vfs {
            mounts: Vec::new(),
            modes: BTreeMap::new(),
            mtimes: BTreeMap::new(),
            locks: Vec::new(),
            file_table: Vec::new(),
            dir_cache: Vec::new(),
            dir_generation: 0,
        }
    }

    // ── mount table (namespace composer) ─────────────────────────────────

    fn longest_prefix(&self, path: &[u8]) -> Option<usize> {
        self.mounts
            .iter()
            .filter(|binding| match_prefix(binding.prefix, path).is_some())
            .map(|binding| binding.prefix.len())
            .max()
    }

    /// Find the first object supplied by the highest-priority matching layer.
    fn resolve_object(&self, path: &[u8], depth: u8) -> Option<ResolvedObject> {
        let best = self.longest_prefix(path)?;
        let mut visited = 0;
        for (index, binding) in self.mounts.iter().enumerate().rev() {
            if binding.prefix.len() != best { continue; }
            let Some(start) = match_prefix(binding.prefix, path) else { continue };
            if visited == MAX_UNION {
                crate::dbg_println!(
                    "vfs: union group exceeds {} layers; dropping oldest", MAX_UNION);
                break;
            }
            visited += 1;
            let subpath = &path[start..];
            match binding.target {
                BindTarget::Server(fs) => {
                    let stat = if subpath.is_empty() {
                        Some(Stat {
                            size: 0,
                            mode: 0o755,
                            is_dir: true,
                            is_symlink: false,
                            ino: fs.root_node().unwrap_or(0),
                        })
                    } else {
                        fs.stat(subpath, false)
                    };
                    if let Some(stat) = stat {
                        return ResolvedObject::new(index as u8, fs, subpath, stat);
                    }
                }
                BindTarget::Alias { src_prefix } if depth != 0 => {
                    let mut rewritten = [0; PATH_KEY_MAX];
                    let len = src_prefix.len().checked_add(subpath.len())?;
                    if len > rewritten.len() { continue; }
                    rewritten[..src_prefix.len()].copy_from_slice(src_prefix);
                    rewritten[src_prefix.len()..len].copy_from_slice(subpath);
                    if let Some(object) = self.resolve_object(&rewritten[..len], depth - 1) {
                        return Some(object);
                    }
                }
                BindTarget::Alias { .. } => {}
            }
        }
        None
    }

    /// Locate an object whose owning layer is already known from a directory
    /// entry. The listing is the existence proof, so this only translates the
    /// namespace path (including aliases); it does not repeat backend lookup.
    fn resolve_listed(
        &self,
        path: &[u8],
        depth: u8,
        mount_idx: u8,
        stat: Stat,
    ) -> Option<ResolvedObject> {
        let best = self.longest_prefix(path)?;
        for (index, binding) in self.mounts.iter().enumerate().rev() {
            if binding.prefix.len() != best { continue; }
            let Some(start) = match_prefix(binding.prefix, path) else { continue };
            let subpath = &path[start..];
            match binding.target {
                BindTarget::Server(fs) if index as u8 == mount_idx => {
                    return ResolvedObject::new(mount_idx, fs, subpath, stat);
                }
                BindTarget::Alias { src_prefix } if depth != 0 => {
                    let mut rewritten = [0; PATH_KEY_MAX];
                    let len = src_prefix.len().checked_add(subpath.len())?;
                    if len > rewritten.len() { continue; }
                    rewritten[..src_prefix.len()].copy_from_slice(src_prefix);
                    rewritten[src_prefix.len()..len].copy_from_slice(subpath);
                    if let Some(object) = self.resolve_listed(
                        &rewritten[..len], depth - 1, mount_idx, stat,
                    ) {
                        return Some(object);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Visit every matching layer for union directory enumeration. Returning
    /// `true` stops the walk. Object lookup uses [`Self::resolve_object`].
    fn visit_layers(
        &self,
        path: &[u8],
        depth: u8,
        visit: &mut LayerVisitor<'_>,
    ) -> bool {
        let Some(best) = self.longest_prefix(path) else { return false };

        // Bindings are appended oldest-to-newest, so reverse iteration is
        // already union priority order. A Replace group is a single member.
        let mut n = 0;
        for (i, b) in self.mounts.iter().enumerate().rev() {
            if b.prefix.len() != best { continue; }
            let Some(start) = match_prefix(b.prefix, path) else { continue };
            if n == MAX_UNION {
                crate::dbg_println!(
                    "vfs: union group exceeds {} layers; dropping oldest", MAX_UNION);
                break;
            }
            n += 1;
            let subpath = &path[start..];
            match b.target {
                BindTarget::Server(fs) => {
                    if visit(i as u8, fs, subpath) { return true; }
                }
                BindTarget::Alias { src_prefix } => {
                    if depth == 0 { continue; }
                    // Retry the lookup as `src_prefix + subpath`.
                    let mut buf = [0u8; PATH_KEY_MAX];
                    let (pl, sl) = (src_prefix.len(), subpath.len());
                    if pl + sl > buf.len() { continue; }
                    buf[..pl].copy_from_slice(src_prefix);
                    buf[pl..pl + sl].copy_from_slice(subpath);
                    if self.visit_layers(&buf[..pl + sl], depth - 1, visit) { return true; }
                }
            }
        }
        false
    }

    /// The single highest-priority `Server` member at the longest matching
    /// prefix (non-allocating). Used by `create`/`delete`, which write to the
    /// top layer. Alias heads and an empty table fall back to `EmptyFs`.
    fn resolve_head<'a>(&self, path: &'a [u8]) -> (u8, &'static dyn Filesystem, &'a [u8]) {
        let mut best: Option<(usize, usize, usize)> = None; // (prefix length, index, path start)
        for (i, b) in self.mounts.iter().enumerate().rev() {
            if let BindTarget::Server(_) = b.target
                && let Some(start) = match_prefix(b.prefix, path) {
                let better = match best {
                    None => true,
                    Some((best_len, _, _)) => b.prefix.len() > best_len,
                };
                if better { best = Some((b.prefix.len(), i, start)); }
            }
        }
        match best {
            Some((_, i, start)) => match self.mounts[i].target {
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

    /// May RetroOS write `subpath` on mount `midx`? THE enforcement point:
    /// every write, create and delete in the system funnels through here, so
    /// the rule cannot be bypassed by reaching a driver directly.
    ///
    /// No grant on the mount means nothing on it is writable.
    fn may_write(&self, midx: u8, subpath: &[u8]) -> bool {
        match self.mounts[midx as usize].access {
            WriteAccess::None => false,
            WriteAccess::Delegated => true,
            WriteAccess::Granted(grant) => {
                let fs = self.mount_fs(midx);
                fs.meta(subpath).is_some_and(|m| grant.allows(&m))
            }
        }
    }

    /// May RetroOS create or delete `subpath`? The Unix rule: that mutates the
    /// PARENT directory, so the parent's ownership decides.
    fn may_write_parent(&self, midx: u8, subpath: &[u8]) -> bool {
        match crate::kernel::fs::grant::parent_of(subpath) {
            Some(parent) => self.may_write(midx, parent),
            None => false,
        }
    }

    /// Stamp a newly created object as RetroOS's own, so it can be reopened
    /// for writing later.
    fn claim(&self, midx: u8, subpath: &[u8]) {
        let WriteAccess::Granted(grant) = self.mounts[midx as usize].access else { return };
        let fs = self.mount_fs(midx);
        if let Some(m) = fs.meta(subpath) {
            fs.set_meta(subpath, m.uid, grant.gid(), grant.claim_mode(m.mode));
        }
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
        self.mounts.push(Binding {
            prefix,
            target,
            access: WriteAccess::Delegated,
        });
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

    fn alloc_file_entry(&self) -> usize {
        self.file_table.iter().position(|entry| entry.refcount == 0)
            .unwrap_or(self.file_table.len())
    }

    fn install_handle(
        &mut self,
        path: &[u8],
        ino: u64,
        mount_idx: u8,
        vnode: Vnode,
        writable: bool,
    ) -> i32 {
        let index = self.alloc_file_entry();
        let path_len = path.len().min(PATH_KEY_MAX);
        let mut path_key = [0; PATH_KEY_MAX];
        path_key[..path_len].copy_from_slice(&path[..path_len]);
        let entry = FileEntry {
            vnode,
            offset: 0,
            refcount: 1,
            ino,
            mount_idx,
            writable,
            access: OpenAccess::Read,
            share: SharePolicy::DenyNone,
            path: path_key,
            path_len: path_len as u8,
        };
        if index == self.file_table.len() {
            self.file_table.push(entry);
        } else {
            self.file_table[index] = entry;
        }
        index as i32
    }

    /// Drop one reference to a file-table entry; at refcount 0 release the slot
    /// and `clunk` the backing fid (Tclunk).
    ///
    /// This is correct because every `open()` gets its *own* fid — there is no
    /// shared-fid cache — so refcount 0 means the last reference to *this* fid
    /// is gone. `dup`/`fork` share one file-table entry (refcount > 1), so the
    /// fid is clunked exactly once, when the last of them closes; two
    /// independent opens of the same path hold distinct fids and clunk
    /// independently.
    fn close_handle(&mut self, idx: i32) {
        if idx < 0 || (idx as usize) >= self.file_table.len() { return; }
        let i = idx as usize;
        if self.file_table[i].refcount == 0 { return; }
        self.file_table[i].refcount -= 1;
        if self.file_table[i].refcount == 0 {
            self.locks.retain(|l| l.owner != idx);
            let handle = self.file_table[i].vnode.handle;
            let midx = self.file_table[i].mount_idx;
            self.mount_fs(midx).clunk(handle);
        }
    }

    fn add_ref(&mut self, idx: i32) {
        if idx >= 0 && (idx as usize) < self.file_table.len() {
            self.file_table[idx as usize].refcount += 1;
        }
    }

    // ── dir cache ────────────────────────────────────────────────────────

    fn invalidate_dir_cache(&mut self) {
        self.dir_cache.clear();
        self.dir_generation = self.dir_generation.wrapping_add(1);
    }

    fn cached_directory_node(&self, dir: &[u8], mount_idx: u8) -> Option<u64> {
        let (parent, name) = split_parent_bytes(dir)?;
        let cached = self.dir_cache.iter().find(|cached| cached.dir == parent)?;
        let entry = cached.entries.get(*cached.names.get(name)?)?;
        (entry.mount_idx == mount_idx && entry.node != 0 && entry.is_dir)
            .then_some(entry.node)
    }

    /// Populate the directory cache for `dir` (single pass). Layers, top to
    /// bottom (a name from a higher layer shadows the same name lower down),
    /// followed by synthesized mount/bind-point directories. Writable RAM
    /// overlays are ordinary members of that union stack.
    fn populate_dir_cache(&mut self, dir: &[u8]) {
        let mut entries: Vec<DirEntry> = Vec::new();
        let mut visible_names: BTreeMap<Vec<u8>, usize> = BTreeMap::new();

        // Union merge: visit every member of the group in priority order (most
        // recent first); an upper layer shadows a lower one on a name clash.
        // For a Replace group this is just the one backing fs (== old behavior).
        self.visit_layers(dir, ALIAS_DEPTH, &mut |idx, fs, subpath| {
            let mut batch: Vec<DirEntry> = Vec::new();
            let mut cookie = READDIR_START;
            let directory_node = if subpath.is_empty() {
                fs.root_node()
            } else {
                self.cached_directory_node(dir, idx)
            };
            loop {
                batch.clear();
                let next = if let Some(node) = directory_node {
                    fs.readdir_node(node, cookie, &mut batch, READDIR_BATCH)
                } else {
                    fs.readdir(subpath, cookie, &mut batch, READDIR_BATCH)
                };
                for mut e in batch.drain(..) {
                    e.mount_idx = idx;
                    if claim_visible_name(
                        &mut visible_names,
                        &e.name[..e.name_len],
                        entries.len(),
                    ) {
                        entries.push(e);
                    }
                }
                match next {
                    // A backend that neither advanced its cookie nor produced
                    // an entry would spin here forever. The trait forbids it;
                    // this makes a buggy backend a truncated listing rather
                    // than a hung kernel.
                    Some(c) if c != cookie => cookie = c,
                    _ => break,
                }
            }
            false
        });

        // Synthesize mount/bind-point directories that live directly under `dir`.
        for b in &self.mounts {
            if let Some(name) = mount_child_in_dir(b.prefix, dir)
                && claim_visible_name(&mut visible_names, name, entries.len()) {
                let name_len = name.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100], name_len, size: 0, is_dir: true,
                    is_symlink: false, mode: 0o755,
                    mtime: 0,
                    node: 0,
                    mount_idx: 0,
                };
                de.name[..name_len].copy_from_slice(&name[..name_len]);
                entries.push(de);
            }
        }

        self.dir_cache.push(DirCache::new(dir, entries, visible_names));
    }

    fn readdir(&mut self, dir: &[u8], index: usize) -> Option<DirEntry> {
        if !self.dir_cache.iter().any(|cached| cached.dir == dir) {
            self.populate_dir_cache(dir);
        }
        self.dir_cache
            .iter()
            .find(|cached| cached.dir == dir)
            .and_then(|cached| cached.entries.get(index))
            .map(clone_dir_entry)
    }

    fn cached_child(&mut self, parent: &[u8], name: &[u8]) -> Option<DirEntry> {
        if !self.dir_cache.iter().any(|cached| cached.dir == parent) {
            self.populate_dir_cache(parent);
        }
        let cached = self.dir_cache.iter().find(|cached| cached.dir == parent)?;
        Some(clone_dir_entry(cached.entries.get(*cached.names.get(name)?)?))
    }

    fn readlink_entry(&self, path: &[u8], entry: &DirEntry, out: &mut [u8]) -> Option<usize> {
        if entry.node != 0
            && let Some(len) = self.mount_fs(entry.mount_idx).readlink_node(entry.node, out)
        {
            return Some(len);
        }
        let object = self.resolve_listed(path, ALIAS_DEPTH, entry.mount_idx, Stat {
            size: entry.size,
            mode: entry.mode,
            is_dir: entry.is_dir,
            is_symlink: entry.is_symlink,
            ino: entry.node,
        })?;
        object.fs.readlink_node(object.stat.ino, out)
            .or_else(|| object.fs.readlink(object.subpath(), out))
    }

    /// Expand symlinks as namespace objects. Backends only expose link bytes;
    /// relative/absolute interpretation, `..`, mount crossing, and the loop
    /// limit all live here.
    fn resolve_symlinks(&mut self, path: &[u8], follow_final: bool) -> Option<Vec<u8>> {
        if path.contains(&0) {
            return None;
        }
        let mut resolved: Vec<Vec<u8>> = Vec::new();
        let mut pending: VecDeque<Vec<u8>> = path
            .split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty() && *component != b".")
            .map(|component| component.to_vec())
            .collect();
        let mut links = 0;
        while !pending.is_empty() {
            let component = pending.pop_front()?;
            if component == b".." {
                resolved.pop();
                continue;
            }
            let parent = join_path_components(&resolved);
            let entry = self.cached_child(&parent, &component)?;
            let is_final = pending.is_empty();
            if entry.is_symlink && (follow_final || !is_final) {
                links += 1;
                if links > 40 {
                    return None;
                }
                let mut candidate = parent;
                if !candidate.is_empty() {
                    candidate.push(b'/');
                }
                candidate.extend_from_slice(&entry.name[..entry.name_len]);
                let mut target = [0u8; DIR_PATH_MAX];
                let len = self.readlink_entry(&candidate, &entry, &mut target)?;
                if len == 0 || target[..len].contains(&0) {
                    return None;
                }
                if target[..len].first() == Some(&b'/') {
                    resolved.clear();
                }
                let mut expanded: VecDeque<Vec<u8>> = target[..len]
                    .split(|byte| *byte == b'/')
                    .filter(|part| !part.is_empty() && *part != b".")
                    .map(|part| part.to_vec())
                    .collect();
                expanded.append(&mut pending);
                pending = expanded;
                continue;
            }
            resolved.push(entry.name[..entry.name_len].to_vec());
        }
        Some(join_path_components(&resolved))
    }

    fn resolve_parent_symlinks(&mut self, path: &[u8]) -> Option<Vec<u8>> {
        let (parent, name) = split_parent_bytes(path)?;
        if name.is_empty() || name == b"." || name == b".." {
            return None;
        }
        let mut resolved = self.resolve_symlinks(parent, true)?;
        if !resolved.is_empty() {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(name);
        Some(resolved)
    }

    /// Resolve the last path component from VFS-owned directory listings and,
    /// when the backend supplied a stable identity, open it without asking the
    /// backend to repeat name lookup.
    fn open_cached_node(&mut self, path: &[u8]) -> Option<(u8, Vnode, Vec<u8>)> {
        let (parent, name) = match path.iter().rposition(|byte| *byte == b'/') {
            Some(separator) => (&path[..separator], &path[separator + 1..]),
            None => (&b""[..], path),
        };
        if name.is_empty() {
            return None;
        }
        let entry = {
            self.cached_child(parent, name)?
        };
        // Resolution has already removed followed links. Directories are not
        // openable files; an unfollowed final link belongs to lstat/readlink.
        if entry.node == 0 || entry.is_dir || entry.is_symlink {
            return None;
        }
        let object = self.resolve_listed(path, ALIAS_DEPTH, entry.mount_idx, Stat {
            size: entry.size,
            mode: entry.mode,
            is_dir: entry.is_dir,
            is_symlink: entry.is_symlink,
            ino: entry.node,
        })?;
        let vnode = object.fs.open_node(entry.node)?;
        Some((entry.mount_idx, vnode, object.subpath().to_vec()))
    }

    fn dir_exists(&mut self, path: &[u8]) -> bool {
        let Some(path) = self.resolve_symlinks(path, true) else { return false };
        let path = path.as_slice();
        if let Some((parent, name)) = split_parent_bytes(path)
            && let Some(entry) = self.cached_child(parent, name)
        {
            return entry.is_dir;
        }
        self.resolve_object(path, ALIAS_DEPTH)
            .is_some_and(|object| object.stat.is_dir)
    }

    fn readlink(&mut self, path: &[u8], out: &mut [u8]) -> Option<usize> {
        let resolved = self.resolve_symlinks(path, false)?;
        let (parent, name) = split_parent_bytes(&resolved)?;
        let entry = self.cached_child(parent, name)?;
        if !entry.is_symlink {
            return None;
        }
        self.readlink_entry(&resolved, &entry, out)
    }

    fn stat(&mut self, path: &[u8], follow_final: bool) -> Option<Stat> {
        let resolved = self.resolve_symlinks(path, follow_final)?;
        let path = resolved.as_slice();
        let override_mode = self.modes.get(path).copied();
        if let Some((parent, name)) = split_parent_bytes(path)
            && let Some(entry) = self.cached_child(parent, name)
        {
            return Some(Stat {
                size: entry.size,
                mode: override_mode.unwrap_or(u32::from(entry.mode)) as u16,
                is_dir: entry.is_dir,
                is_symlink: entry.is_symlink,
                ino: path_ino(path),
            });
        }
        let mut stat = self.resolve_object(path, ALIAS_DEPTH)?.stat;
        if let Some(mode) = override_mode { stat.mode = mode as u16; }
        if stat.ino == 0 { stat.ino = path_ino(path); }
        Some(stat)
    }

    fn mkdir(&mut self, path: &[u8]) -> i32 {
        if self.dir_exists(path) {
            return -17; // EEXIST
        }
        let resolved = match self.resolve_parent_symlinks(path) {
            Some(path) => path,
            None => return -2,
        };
        let path = resolved.as_slice();
        let (midx, fs, subpath) = self.resolve_head(path);
        if !fs.supports_mkdir() { return -38; }
        if !self.may_write_parent(midx, subpath) { return -13; }
        let rc = fs.mkdir(subpath);
        if rc < 0 { return rc; }
        self.claim(midx, subpath);
        self.invalidate_dir_cache();
        0
    }

    // ── open / create / read / write / seek ──────────────────────────────

    fn open_to_handle(&mut self, path: &[u8]) -> i32 {
        let original_ino = path_ino(path);
        let resolved_path = match self.resolve_symlinks(path, true) {
            Some(path) => path,
            None => return -2,
        };
        let path = resolved_path.as_slice();
        // Try each member of the group in priority order; first hit wins and
        // its mount_idx is recorded (a Replace group = the single backing fs).
        // Every open gets its OWN fid from `fs.open` — fids are never cached or
        // shared, so `close_handle` can `clunk` this fid at refcount 0 without
        // affecting any other open (see `close_handle`).
        // Carry the subpath out too: the write verdict must be taken against
        // the member that actually opened the file, not against whatever
        // `resolve_head` would pick.
        let resolved = self.open_cached_node(path).or_else(|| {
            let object = self.resolve_object(path, ALIAS_DEPTH)?;
            if object.stat.is_dir || object.stat.is_symlink { return None; }
            let vnode = object.fs.open_node(object.stat.ino)
                .or_else(|| object.fs.open(object.subpath()))?;
            Some((object.mount_idx, vnode, object.subpath().to_vec()))
        });
        let (midx, vnode, sub) = match resolved {
            Some(x) => x,
            None => return -2,
        };

        let writable = self.may_write(midx, &sub);
        self.install_handle(path, original_ino, midx, vnode, writable)
    }

    fn create_to_handle(&mut self, path: &[u8]) -> i32 {
        let original_ino = path_ino(path);
        let resolved = self
            .resolve_symlinks(path, true)
            .or_else(|| self.resolve_parent_symlinks(path));
        let Some(resolved) = resolved else { return -2 };
        let path = resolved.as_slice();
        let (midx, fs, subpath) = self.resolve_head(path);
        if !fs.supports_create() { return -38; }
        // Did it already exist? Decides both which permission applies and
        // whether a successful create needs stamping as ours.
        let existed = fs.meta(subpath).is_some();
        // Creating or truncating is a write: an existing object must itself
        // be ours, a new one needs write permission on its parent.
        let permitted = if existed {
            self.may_write(midx, subpath)
        } else {
            self.may_write_parent(midx, subpath)
        };
        if !permitted {
            return -13; // EACCES
        }
        if let Some(vnode) = fs.create(subpath) {
            if !existed {
                self.claim(midx, subpath);
            }
            self.invalidate_dir_cache();
            return self.install_handle(path, original_ino, midx, vnode, true);
        }

        -13
    }

    fn rmdir(&mut self, path: &[u8]) -> i32 {
        let Some(resolved) = self.resolve_parent_symlinks(path) else { return -2 };
        let path = resolved.as_slice();
        let (midx, fs, subpath) = self.resolve_head(path);
        if !fs.supports_directory_mutation() { return -38; }
        if !self.may_write_parent(midx, subpath) || !self.may_write(midx, subpath) {
            return -13;
        }
        let rc = fs.rmdir(subpath);
        if rc >= 0 {
            self.modes.remove(path);
            self.mtimes.remove(path);
            self.invalidate_dir_cache();
        }
        rc
    }

    fn rename(&mut self, old: &[u8], new: &[u8]) -> i32 {
        let Some(old_resolved) = self.resolve_parent_symlinks(old) else { return -2 };
        let Some(new_resolved) = self.resolve_parent_symlinks(new) else { return -2 };
        let old = old_resolved.as_slice();
        let new = new_resolved.as_slice();
        if self.path_exists(new) { return -17; }
        let (old_idx, old_fs, old_sub) = self.resolve_head(old);
        let (new_idx, _new_fs, new_sub) = self.resolve_head(new);
        if old_idx != new_idx { return -18; } // EXDEV
        if !old_fs.supports_directory_mutation() { return -38; }
        if !self.may_write(old_idx, old_sub)
            || !self.may_write_parent(old_idx, old_sub)
            || !self.may_write_parent(new_idx, new_sub) { return -13; }
        let rc = old_fs.rename(old_sub, new_sub);
        if rc < 0 { return rc; }
        self.rekey_open_paths(old, new);
        if let Some(v) = self.modes.remove(old) { self.modes.insert(new.to_vec(), v); }
        if let Some(v) = self.mtimes.remove(old) { self.mtimes.insert(new.to_vec(), v); }
        self.invalidate_dir_cache();
        0
    }

    fn rekey_open_paths(&mut self, old: &[u8], new: &[u8]) {
        for e in &mut self.file_table {
            let len = e.path_len as usize;
            if e.refcount != 0 && &e.path[..len] == old && new.len() <= PATH_KEY_MAX {
                e.path[..new.len()].copy_from_slice(new);
                e.path_len = new.len() as u8;
            }
        }
    }

    fn path_exists(&mut self, path: &[u8]) -> bool {
        let Some(resolved) = self.resolve_symlinks(path, true) else { return false };
        let path = resolved.as_slice();
        if let Some((parent, name)) = split_parent_bytes(path)
            && self.cached_child(parent, name).is_some()
        {
            return true;
        }
        if path.is_empty() { return true; }
        self.resolve_object(path, ALIAS_DEPTH).is_some()
    }

    fn path_mode(&mut self, path: &[u8]) -> Option<(u32, bool)> {
        if !self.path_exists(path) { return None; }
        let resolved = self.resolve_symlinks(path, true)?;
        let path = resolved.as_slice();
        let is_dir = self.dir_exists(path);
        if let Some(&mode) = self.modes.get(path) { return Some((mode, is_dir)); }
        let object = self.resolve_object(path, ALIAS_DEPTH)?;
        if let Some(m) = object.fs.meta(object.subpath()) { return Some((m.mode, is_dir)); }
        if is_dir { return Some((0o555, true)); }
        Some((u32::from(object.stat.mode), false))
    }

    fn set_path_mode(&mut self, path: &[u8], mode: u32) -> i32 {
        if !self.path_exists(path) { return -2; }
        let Some(resolved) = self.resolve_symlinks(path, true) else { return -2 };
        let path = resolved.as_slice();
        let (midx, fs, subpath) = self.resolve_head(path);
        if fs.meta(subpath).is_some() && !self.may_write(midx, subpath) { return -13; }
        if let Some(m) = fs.meta(subpath)
            && !fs.set_meta(subpath, m.uid, m.gid, mode) { return -13; }
        self.modes.insert(path.to_vec(), mode);
        self.invalidate_dir_cache();
        0
    }

    fn handle_path(&self, handle: i32) -> Option<&[u8]> {
        let e = self.file_table.get(handle as usize)?;
        if e.refcount == 0 { return None; }
        Some(&e.path[..e.path_len as usize])
    }

    fn flush_handle(&mut self, handle: i32) -> i32 {
        let Some(path) = self.handle_path(handle).map(|p| p.to_vec()) else { return -9; };
        let (_idx, fs, subpath) = self.resolve_head(&path);
        fs.flush(subpath)
    }

    fn handle_mtime(&self, handle: i32) -> Option<u32> {
        let path = self.handle_path(handle)?;
        if let Some(&t) = self.mtimes.get(path) { return Some(t); }
        let (_idx, fs, subpath) = self.resolve_head(path);
        fs.mtime(subpath)
    }

    fn set_handle_mtime(&mut self, handle: i32, mtime: u32) -> i32 {
        let Some(path) = self.handle_path(handle).map(|p| p.to_vec()) else { return -9; };
        let (midx, fs, subpath) = self.resolve_head(&path);
        if fs.meta(subpath).is_some() && !self.may_write(midx, subpath) { return -13; }
        if fs.meta(subpath).is_some() && !fs.set_mtime(subpath, mtime) { return -13; }
        self.mtimes.insert(path, mtime);
        self.invalidate_dir_cache();
        0
    }

    fn delete(&mut self, path: &[u8]) -> i32 {
        let Some(resolved) = self.resolve_parent_symlinks(path) else { return -2 };
        let path = resolved.as_slice();
        // Ask the backing filesystem (Tremove). Read-only backends reject it.
        let (midx, fs, subpath) = self.resolve_head(path);
        // Unlinking mutates the parent, so the parent must be ours — and the
        // victim too, so a link we may traverse can't delete something we may
        // not write. Only meaningful where the mount has a rule at all.
        if fs.meta(subpath).is_some()
            && (!self.may_write_parent(midx, subpath) || !self.may_write(midx, subpath))
        {
            return -13; // EACCES
        }
        let r = fs.remove(subpath);
        if r >= 0 {
            self.invalidate_dir_cache();
        }
        r
    }

    fn read_by_handle(&mut self, handle: i32, buf: &mut [u8]) -> i32 {
        if handle < 0 || (handle as usize) >= self.file_table.len() { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        let (mount_idx, fs_handle, offset, size) = {
            let e = &self.file_table[h];
            (e.mount_idx, e.vnode.handle, e.offset, e.vnode.size)
        };
        let n = self.mount_fs(mount_idx).read(fs_handle, offset, buf, size);
        if n > 0 { self.file_table[h].offset += n as u32; }
        n
    }

    fn write_by_handle<A: crate::Arch>(&mut self, _machine: &mut A, handle: i32, data: &[u8]) -> i32 {
        if handle < 0 || (handle as usize) >= self.file_table.len() { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        if !self.file_table[h].writable {
            return -30; // EROFS — this handle was opened on something not ours
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
            self.invalidate_dir_cache();
        }
        n
    }

    fn seek_by_handle(&mut self, handle: i32, offset: i32, whence: i32) -> i32 {
        if handle < 0 || (handle as usize) >= self.file_table.len() { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        let size = self.file_table[h].vnode.size;

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
        if handle < 0 || (handle as usize) >= self.file_table.len() { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        e.vnode.size
    }

    fn handle_writable(&self, handle: i32) -> bool {
        if handle < 0 || (handle as usize) >= self.file_table.len() { return false; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return false; }
        e.writable
    }

    fn configure_open(&mut self, handle: i32, access: OpenAccess, share: SharePolicy) -> i32 {
        let Some(entry) = self.file_table.get(handle as usize) else { return -9; };
        if entry.refcount == 0 { return -9; }
        let ino = entry.ino;
        let reads = |a: OpenAccess| !matches!(a, OpenAccess::Write);
        let writes = |a: OpenAccess| !matches!(a, OpenAccess::Read);
        let denied = |s: SharePolicy, a: OpenAccess| match s {
            SharePolicy::DenyAll => reads(a) || writes(a),
            SharePolicy::DenyWrite => writes(a),
            SharePolicy::DenyRead => reads(a),
            _ => false,
        };
        for (idx, other) in self.file_table.iter().enumerate() {
            if idx != handle as usize && other.refcount != 0 && other.ino == ino
                && (denied(other.share, access) || denied(share, other.access)) {
                return -13;
            }
        }
        self.file_table[handle as usize].access = access;
        self.file_table[handle as usize].share = share;
        0
    }

    fn lock_range(&mut self, handle: i32, unlock: bool, start: u32, len: u32) -> i32 {
        let Some(entry) = self.file_table.get(handle as usize) else { return -9; };
        if entry.refcount == 0 { return -9; }
        let ino = entry.ino;
        if unlock {
            if let Some(i) = self.locks.iter().position(|l| l.owner == handle && l.start == start && l.len == len) {
                self.locks.remove(i);
                return 0;
            }
            return -33;
        }
        let end = start.saturating_add(len);
        if self.locks.iter().any(|l| l.ino == ino && l.owner != handle
            && start < l.start.saturating_add(l.len) && l.start < end) {
            return -33;
        }
        self.locks.push(FileLock { ino, owner: handle, start, len });
        0
    }

    fn file_ino_by_handle(&self, handle: i32) -> u64 {
        if handle < 0 || (handle as usize) >= self.file_table.len() { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        e.ino
    }

    fn file_mode_by_handle(&self, handle: i32) -> u16 {
        if handle < 0 || (handle as usize) >= self.file_table.len() { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        e.vnode.mode
    }
}

// `Vfs` holds `&'static dyn Filesystem`, and some backends are not thread-safe
// in isolation (the portable ext4 wrapper uses `RefCell`). This `Send` is
// nonetheless sound — and SMP-correct, not a
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
// Accepts fd 0-2 too: DOS AH=46h can redirect a std handle to a VFS file, and
// reads/writes on it must reach that file. Non-Vfs kinds still Err below.
fn vfs_handle(fds: &[FdKind; MAX_FDS], fd: i32) -> Result<i32, i32> {
    if fd < 0 || fd >= MAX_FDS as i32 { return Err(-9); }
    match fds[fd as usize] {
        FdKind::Vfs(idx) => Ok(idx),
        _ => Err(-9),
    }
}

/// Claim an exact name for union merging. The first (highest) layer wins.
fn claim_visible_name(
    names: &mut BTreeMap<Vec<u8>, usize>,
    name: &[u8],
    index: usize,
) -> bool {
    if names.contains_key(name) { return false; }
    names.insert(name.to_vec(), index);
    true
}

fn clone_dir_entry(e: &DirEntry) -> DirEntry {
    DirEntry {
        name: e.name,
        name_len: e.name_len,
        size: e.size,
        is_dir: e.is_dir,
        is_symlink: e.is_symlink,
        mode: e.mode,
        mtime: e.mtime,
        node: e.node,
        mount_idx: e.mount_idx,
    }
}

fn join_path_components(components: &[Vec<u8>]) -> Vec<u8> {
    let capacity = components.iter().map(Vec::len).sum::<usize>()
        .saturating_add(components.len().saturating_sub(1));
    let mut path = Vec::with_capacity(capacity);
    for component in components {
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(component);
    }
    path
}

fn split_parent_bytes(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.is_empty() {
        return None;
    }
    Some(match path.iter().rposition(|byte| *byte == b'/') {
        Some(separator) => (&path[..separator], &path[separator + 1..]),
        None => (&b""[..], path),
    })
}

/// If a mount prefix is a direct child of `dir`, return the child name.
/// e.g. mount "boot/" in dir "" → Some("boot"), mount "a/b/" in dir "a/" → Some("b").
fn mount_child_in_dir<'a>(prefix: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    let prefix = prefix.strip_suffix(b"/").unwrap_or(prefix);
    let dir = dir.strip_suffix(b"/").unwrap_or(dir);
    let (parent, name) = split_parent_bytes(prefix)?;
    (!name.is_empty() && eq_ignore_case(parent, dir)).then_some(name)
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

/// Mount `fs` and give it a write grant derived from the group owning `home`
/// (a path within the new mount). Without this a mount is read-only, which is
/// the safe default: a mount site cannot accidentally grant write access, only
/// deliberately.
pub fn mount_writable(prefix: &'static [u8], fs: &'static dyn Filesystem, home: &[u8]) {
    let mut v = VFS.lock();
    v.mount(prefix, fs);
    let access = match crate::kernel::fs::grant::Grant::from_home(fs, home) {
        Some(g) => WriteAccess::Granted(g),
        // Unreadable identity ⇒ no grant at all, rather than a guessed gid.
        None => WriteAccess::None,
    };
    if let Some(b) = v.mounts.iter_mut().find(|b| b.prefix == prefix) {
        b.access = access;
    }
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
#[inline(never)]
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
#[inline(never)]
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
#[inline(never)]
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

/// Create or truncate a file by absolute VFS path.
#[inline(never)]
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

/// Create or truncate a file on the filesystem mounted at its path.
#[inline(never)]
pub fn create_to_handle(path: &[u8]) -> i32 {
    VFS.lock().create_to_handle(path)
}

/// Create a directory on the filesystem mounted at its path.
#[inline(never)]
pub fn mkdir(path: &[u8]) -> i32 {
    VFS.lock().mkdir(path)
}

#[inline(never)]
pub fn rmdir(path: &[u8]) -> i32 { VFS.lock().rmdir(path) }
#[inline(never)]
pub fn rename(old: &[u8], new: &[u8]) -> i32 { VFS.lock().rename(old, new) }
#[inline(never)]
pub fn path_exists(path: &[u8]) -> bool { VFS.lock().path_exists(path) }
#[inline(never)]
pub fn path_mode(path: &[u8]) -> Option<(u32, bool)> { VFS.lock().path_mode(path) }
#[inline(never)]
pub fn set_path_mode(path: &[u8], mode: u32) -> i32 { VFS.lock().set_path_mode(path, mode) }

#[inline(never)]
pub fn flush(fd: i32, fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => VFS.lock().flush_handle(handle),
        Err(e) => e,
    }
}

#[inline(never)]
pub fn handle_mtime(fd: i32, fds: &[FdKind; MAX_FDS]) -> Option<u32> {
    vfs_handle(fds, fd).ok().and_then(|h| VFS.lock().handle_mtime(h))
}

#[inline(never)]
pub fn set_handle_mtime(fd: i32, mtime: u32, fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => VFS.lock().set_handle_mtime(handle, mtime),
        Err(e) => e,
    }
}

/// Write to an open file descriptor.
#[inline(never)]
pub fn write<A: crate::Arch>(machine: &mut A, fd: i32, data: &[u8], fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => write_by_handle(machine, handle, data),
        Err(e) => e,
    }
}

/// Delete a file by absolute VFS path.
#[inline(never)]
pub fn delete(path: &[u8]) -> i32 {
    VFS.lock().delete(path)
}

/// Get the size of an open file descriptor.
#[inline(never)]
pub fn file_size(fd: i32, fds: &[FdKind; MAX_FDS]) -> u32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => file_size_by_handle(handle),
        Err(_) => 0,
    }
}

/// May this open fd be written? (The verdict was decided at open/create time
/// while the path was in hand — see `FileEntry::writable`.) Lets DOS open
/// honor the requested access mode: a write-mode open of something not ours
/// must fail up front with "access denied", where programs actually check,
/// instead of surfacing per-write errors most of them ignore.
#[inline(never)]
pub fn fd_writable(fd: i32, fds: &[FdKind; MAX_FDS]) -> bool {
    match vfs_handle(fds, fd) {
        Ok(handle) => VFS.lock().handle_writable(handle),
        Err(_) => false,
    }
}

#[inline(never)]
pub fn configure_open(
    fd: i32,
    access: OpenAccess,
    share: SharePolicy,
    fds: &[FdKind; MAX_FDS],
) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => VFS.lock().configure_open(handle, access, share),
        Err(e) => e,
    }
}

#[inline(never)]
pub fn lock_range(fd: i32, unlock: bool, start: u32, len: u32, fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => VFS.lock().lock_range(handle, unlock, start, len),
        Err(e) => e,
    }
}

/// Seek on an open file descriptor. whence: 0=SET, 1=CUR, 2=END
#[inline(never)]
pub fn seek(fd: i32, offset: i32, whence: i32, fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => seek_by_handle(handle, offset, whence),
        Err(e) => e,
    }
}

/// Enumerate directory entries at index. Uses a single-pass cache.
pub fn readdir(dir: &[u8], index: usize) -> Option<DirEntry> {
    let mut vfs = VFS.lock();
    let resolved = vfs.resolve_symlinks(dir, true)?;
    vfs.readdir(&resolved, index)
}

/// Namespace/metadata generation used by personality-level directory caches.
pub fn directory_generation() -> u64 {
    VFS.lock().dir_generation
}

/// A mounted proxy changed the directory tree it serves without changing the
/// mount table itself (for example CD insertion/ejection).
pub fn mounted_media_changed() {
    VFS.lock().invalidate_dir_cache();
}

/// Check if a directory exists on a mounted filesystem.
pub fn dir_exists(path: &[u8]) -> bool {
    VFS.lock().dir_exists(path)
}

/// Read a symbolic-link target without following the final path component.
pub fn readlink(path: &[u8], out: &mut [u8]) -> Option<usize> {
    VFS.lock().readlink(path, out)
}

/// Fetch path metadata with either stat (follow final link) or lstat
/// semantics in one backing-filesystem lookup.
pub fn stat(path: &[u8], follow_final: bool) -> Option<Stat> {
    VFS.lock().stat(path, follow_final)
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

/// A direct line to the filesystem behind one file, resolved once at open.
///
/// The media slots (CD-ROM, floppy) read and write their backing image
/// through this WITHOUT re-entering the VFS: slot I/O runs *inside* VFS
/// operations (guest reads D:\FOO → VFS → slot → image file), and the
/// global VFS lock is not reentrant. `Filesystem` calls are positional
/// (pread/pwrite-style), so no offset state lives here either.
///
/// Deliberately `Copy` with an explicit [`BackingFile::close`]: the slot
/// owns the lifecycle (clunk once, on eject), while its cursor types hold
/// working copies. If the VFS ever grows a block cache, it belongs behind
/// this seam.
#[derive(Clone, Copy)]
pub struct BackingFile {
    fs: &'static dyn Filesystem,
    handle: u64,
    size: u32,
}

// Same soundness rule as `unsafe impl Send for Vfs`: every backing-fs call
// happens with the VFS lock held — implicitly when a slot method runs inside
// a VFS operation, explicitly via [`serialize_fs`] when media code reaches
// the backing from outside (INT 13h sector I/O, insert/eject). No filesystem
// is ever entered by two cores at once.
unsafe impl Send for BackingFile {}
unsafe impl Sync for BackingFile {}

/// Hold the VFS lock without performing a VFS operation — the serialization
/// guard for direct [`BackingFile`] access from OUTSIDE a VFS call path.
/// Acquire it BEFORE any slot-internal lock (the lock order everywhere is
/// VFS → slot). Never take it inside a `Filesystem` implementation: those
/// run under the lock already.
pub struct FsSerial(#[allow(dead_code)] spin::MutexGuard<'static, Vfs>);

pub fn serialize_fs() -> FsSerial {
    FsSerial(VFS.lock())
}

impl BackingFile {
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Read at an absolute offset. Returns bytes read or negative errno.
    pub fn read_at(&self, offset: u32, buf: &mut [u8]) -> i32 {
        self.fs.read(self.handle, offset, buf, buf.len() as u32)
    }

    /// Write at an absolute offset. Returns bytes written or negative errno.
    pub fn write_at(&self, offset: u32, data: &[u8]) -> i32 {
        self.fs.write(self.handle, offset, data)
    }

    /// Release the backing fs's per-open state.
    pub fn close(self) {
        self.fs.clunk(self.handle);
    }
}

/// Open `path` directly on its backing mount for media use. The resolution
/// holds the VFS lock; the returned handle never touches it again.
///
pub fn open_backing(path: &[u8]) -> Option<BackingFile> {
    let mut vfs = VFS.lock();
    let resolved = vfs.resolve_symlinks(path, true)?;
    if let Some((mount_idx, vnode, _)) = vfs.open_cached_node(&resolved) {
        return Some(BackingFile {
            fs: vfs.mount_fs(mount_idx),
            handle: vnode.handle,
            size: vnode.size,
        });
    }
    let (_mount_idx, fs, subpath) = vfs.resolve_head(&resolved);
    let vnode = fs.open(subpath)?;
    Some(BackingFile { fs, handle: vnode.handle, size: vnode.size })
}

/// Mount prefix of the filesystem behind an open fd — `b"cdrom/"` for the CD
/// slot, `b"floppya/"`/`b"floppyb/"` for the floppy slots, `b""` for the root
/// mount. The DOS layer maps this to the drive number IOCTL 4400h reports;
/// installers verify a just-opened file really lives on the drive they are
/// probing (Tomb Raider's CD check).
pub fn mount_prefix(fd: i32, fds: &[FdKind; MAX_FDS]) -> Option<&'static [u8]> {
    let handle = vfs_handle(fds, fd).ok()?;
    let vfs = VFS.lock();
    let entry = vfs.file_table.get(handle as usize)?;
    if entry.refcount == 0 {
        return None;
    }
    Some(vfs.mounts.get(entry.mount_idx as usize)?.prefix)
}

/// Stable inode for an open handle — fstat's st_ino (dynamic-linker dedup).
pub fn file_ino_by_handle(handle: i32) -> u64 {
    VFS.lock().file_ino_by_handle(handle)
}

/// Get POSIX mode bits by VFS handle. Returns 0 for an invalid handle.
pub fn file_mode_by_handle(handle: i32) -> u16 {
    VFS.lock().file_mode_by_handle(handle)
}

#[cfg(test)]
mod tests {
    use super::{
        DirEntry, Filesystem, Vfs, Vnode, WriteAccess, mount_child_in_dir,
    };
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static CREATE_CALLED: AtomicBool = AtomicBool::new(false);
    static READDIR_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PATH_OPEN_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NODE_OPEN_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct FailingCreateFs;
    static FAILING_CREATE_FS: FailingCreateFs = FailingCreateFs;

    impl Filesystem for FailingCreateFs {
        fn open(&self, _path: &[u8]) -> Option<Vnode> { None }

        fn read(&self, _handle: u64, _offset: u32, _buf: &mut [u8], _size: u32) -> i32 {
            -5
        }

        fn readdir(
            &self,
            _dir: &[u8],
            _cookie: u64,
            _out: &mut Vec<DirEntry>,
            _max: usize,
        ) -> Option<u64> {
            None
        }

        fn dir_exists(&self, _path: &[u8]) -> bool { false }

        fn create(&self, _path: &[u8]) -> Option<Vnode> {
            CREATE_CALLED.store(true, Ordering::Relaxed);
            None
        }

        fn supports_create(&self) -> bool { true }
    }

    #[test]
    fn failed_supported_create_is_not_reported_as_unsupported() {
        CREATE_CALLED.store(false, Ordering::Relaxed);
        let mut vfs = Vfs::new();
        vfs.mount(b"", &FAILING_CREATE_FS);
        vfs.mounts[0].access = WriteAccess::Delegated;

        assert_eq!(vfs.create_to_handle(b"failed.txt"), -13);
        assert!(CREATE_CALLED.load(Ordering::Relaxed));
        assert!(vfs.resolve_object(b"failed.txt", 8).is_none());
    }

    #[test]
    fn nested_mounts_accept_normalized_directory_paths() {
        assert_eq!(
            mount_child_in_dir(b"home/retroos/proc/", b"home/retroos"),
            Some(&b"proc"[..]),
        );
        assert_eq!(
            mount_child_in_dir(b"home/retroos/proc/", b"home/retroos/"),
            Some(&b"proc"[..]),
        );
    }

    struct NodeFs;
    static NODE_FS: NodeFs = NodeFs;

    impl Filesystem for NodeFs {
        fn root_node(&self) -> Option<u64> { Some(2) }

        fn open(&self, _path: &[u8]) -> Option<Vnode> {
            PATH_OPEN_CALLS.fetch_add(1, Ordering::Relaxed);
            None
        }

        fn open_node(&self, node: u64) -> Option<Vnode> {
            NODE_OPEN_CALLS.fetch_add(1, Ordering::Relaxed);
            Some(Vnode { handle: node, size: 1, mode: 0o444 })
        }

        fn readlink_node(&self, node: u64, out: &mut [u8]) -> Option<usize> {
            let target = match node {
                13 => b"one".as_slice(),
                21 => b"dir".as_slice(),
                _ => return None,
            };
            if out.len() < target.len() { return None; }
            out[..target.len()].copy_from_slice(target);
            Some(target.len())
        }

        fn read(&self, _handle: u64, _offset: u32, _buf: &mut [u8], _size: u32) -> i32 { 0 }

        fn readdir(
            &self,
            dir: &[u8],
            cookie: u64,
            out: &mut Vec<DirEntry>,
            _max: usize,
        ) -> Option<u64> {
            READDIR_CALLS.fetch_add(1, Ordering::Relaxed);
            if cookie != 0 {
                return None;
            }
            let entries: &[(&[u8], u64, bool, bool)] = match dir {
                b"" => &[
                    (b"one", 11, false, false),
                    (b"two", 12, false, false),
                    (b"link", 13, true, false),
                    (b"dir", 20, false, true),
                    (b"dlink", 21, true, false),
                ],
                b"dir" => &[(b"child", 22, false, false)],
                _ => return None,
            };
            for &(name, node, is_symlink, is_dir) in entries {
                let mut entry = DirEntry {
                    name: [0; 100], name_len: name.len(), size: 1,
                    is_dir, is_symlink, mode: 0o444, mtime: 0,
                    node, mount_idx: 0,
                };
                entry.name[..name.len()].copy_from_slice(name);
                out.push(entry);
            }
            None
        }

        fn readdir_node(
            &self,
            node: u64,
            cookie: u64,
            out: &mut Vec<DirEntry>,
            max: usize,
        ) -> Option<u64> {
            match node {
                2 => self.readdir(b"", cookie, out, max),
                20 => self.readdir(b"dir", cookie, out, max),
                _ => None,
            }
        }

        fn dir_exists(&self, path: &[u8]) -> bool { path.is_empty() }
    }

    #[test]
    fn union_members_follow_reverse_insertion_order_without_sorting() {
        let mut vfs = Vfs::new();
        vfs.add_binding(
            b"stack/",
            super::BindTarget::Server(&FAILING_CREATE_FS),
            super::MountMode::Replace,
        );
        vfs.add_binding(
            b"stack/",
            super::BindTarget::Server(&NODE_FS),
            super::MountMode::Union,
        );

        let mut visited = Vec::new();
        assert_eq!(
            vfs.visit_layers(b"stack/file", 8, &mut |idx, _, _| {
                visited.push(idx);
                false
            }),
            false,
        );
        assert_eq!(visited, [1, 0]);
        assert_eq!(vfs.resolve_head(b"stack/file").0, 1);
        assert_eq!(vfs.resolve_object(b"stack", 8).unwrap().mount_idx, 1);
    }

    #[test]
    fn opens_nodes_from_one_vfs_owned_directory_listing() {
        READDIR_CALLS.store(0, Ordering::Relaxed);
        PATH_OPEN_CALLS.store(0, Ordering::Relaxed);
        NODE_OPEN_CALLS.store(0, Ordering::Relaxed);
        let mut vfs = Vfs::new();
        vfs.mount(b"", &NODE_FS);

        assert!(vfs.open_to_handle(b"one") >= 0);
        assert!(vfs.open_to_handle(b"two") >= 0);
        assert_eq!(READDIR_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(PATH_OPEN_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(NODE_OPEN_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(vfs.cached_child(b"", b"one").unwrap().node, 11);
        assert!(vfs.cached_child(b"", b"ONE").is_none());
    }

    #[test]
    fn vfs_interprets_symlink_content_and_opens_its_target_node() {
        READDIR_CALLS.store(0, Ordering::Relaxed);
        PATH_OPEN_CALLS.store(0, Ordering::Relaxed);
        NODE_OPEN_CALLS.store(0, Ordering::Relaxed);
        let mut vfs = Vfs::new();
        vfs.mount(b"", &NODE_FS);

        let handle = vfs.open_to_handle(b"link");
        assert!(handle >= 0);
        assert_eq!(vfs.file_table[handle as usize].vnode.handle, 11);
        assert_eq!(READDIR_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(PATH_OPEN_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(NODE_OPEN_CALLS.load(Ordering::Relaxed), 1);

        let nested = vfs.open_to_handle(b"dlink/child");
        assert!(nested >= 0);
        assert_eq!(vfs.file_table[nested as usize].vnode.handle, 22);
        assert_eq!(PATH_OPEN_CALLS.load(Ordering::Relaxed), 0);
    }
}
