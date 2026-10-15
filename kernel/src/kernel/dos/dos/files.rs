//! DOS file handles, path resolution, directory searches and timestamps.

use crate::Regs;
use super::clock::unix_to_dos_datetime;
use crate::kernel::thread;
use crate::kernel::dos::{dfs, machine, seg_offset};
use super::int21::DosExit;
use super::lowmem::{Psp, psp_struct_seg, sft_set_file};

/// True for VFS paths on immutable removable media — the CD-ROM slot mount:
/// mutation must fail rather than fall through to the RAM-overlay scratch
/// path that read-only archive mounts get (CD installers write-test drives
/// to tell a disc from a hard disk). Floppies are NOT here: their slots are
/// genuinely writable, straight through to the image file.
pub(super) fn immutable_media_path(path: &[u8]) -> bool {
    let prefix = b"cdrom";
    path == prefix
        || (path.len() > prefix.len() && path.starts_with(prefix) && path[prefix.len()] == b'/')
}

pub(super) fn finish_file_read<A: crate::Arch>(
    machine: &mut A,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
    buf_addr: u32,
    buf: &[u8],
) {
    let got = buf.len();
    machine::vga::copy_to_guest(machine, &mut dos.pc.vga, buf_addr as usize, buf);
    // An overlay reload can drop fresh code onto a page that a prior CLI
    // window was learned at; discard those stale entries.
    if got > 0 && let Some(dpmi) = dos.dpmi.as_mut() {
        for page in (buf_addr >> 12)..=((buf_addr + got as u32 - 1) >> 12) {
            dpmi.vif.invalidate_page(page);
        }
    }
    regs.rax = (regs.rax & !0xFFFF) | got as u64;
    regs.clear_flag32(1);
}

/// Complete an image-backed CD read only after its modeled transfer deadline.
/// The guest remains parked, not the kernel: normal PIT advancement and IRQ0
/// delivery continue while the DOS call is outstanding.
pub(super) fn cdrom_read_resume<A: crate::Arch>(
    _machine: &mut A,
    deadline_ns: u64,
    buf_addr: u32,
    buf: alloc::vec::Vec<u8>,
) -> crate::kernel::dos::ResumeCallback<A> {
    crate::kernel::dos::ResumeCallback(alloc::boxed::Box::new(move |machine: &mut A,
              _kt: &mut thread::KernelThread<A>,
              dos: &mut thread::DosState<A>,
              regs: &mut Regs| -> Option<crate::kernel::dos::ResumeCallback<A>> {
        if machine.now() < deadline_ns {
            return Some(cdrom_read_resume(
                machine, deadline_ns, buf_addr, buf));
        }
        finish_file_read(machine, dos, regs, buf_addr, &buf);
        None
    }))
}

/// Copy a guest ASCIIZ string while reserving the output's last byte for its
/// implicit terminator. Callers use the returned length and never need to
/// materialize that terminator.
#[inline(never)]
pub(super) fn read_asciiz<A: crate::Arch>(machine: &mut A, address: u32, output: &mut [u8]) -> usize {
    let mut len = 0;
    while len + 1 < output.len() {
        let byte = machine.read::<u8>(address as usize + len);
        if byte == 0 { break; }
        output[len] = byte;
        len += 1;
    }
    len
}

/// First handle AH=45h may hand out (0-2 are the std slots).
pub(super) const FIRST_USER_HANDLE: usize = 3;

/// What a DOS handle refers to, for AH=45h/46h duplication. The std handles'
/// slots are empty until something redirects them — their implicit console is
/// made explicit here so a saved copy survives the redirect.
pub(super) fn dos_dup_fdkind<A: crate::Arch>(kt: &thread::KernelThread<A>, handle: usize) -> Option<thread::FdKind> {
    if handle >= thread::MAX_FDS { return None; }
    match kt.fds[handle] {
        thread::FdKind::None if handle <= 2 => Some(thread::FdKind::ConsoleOut),
        thread::FdKind::None => None,
        k => Some(k),
    }
}

/// Two error namespaces funnel through here: VFS negative errnos (2/9/13/24)
/// and DFS path-resolution errors, which are already DOS codes (2/3/15). The
/// value sets don't collide, and 2 means "file not found" in both.
pub(super) fn dos_error_from_errno(err: i32) -> u16 {
    match -err {
        2 => 2,   // ENOENT / file not found
        3 => 3,   // DFS: path not found
        15 => 15, // DFS: invalid drive
        17 => 5,  // EEXIST -> access denied (directory already exists)
        18 => 17, // EXDEV -> not same device
        38 => 1,  // ENOSYS -> invalid function
        39 => 5,  // ENOTEMPTY -> access denied
        9 => 6,   // EBADF -> invalid handle
        13 => 5,  // EACCES -> access denied
        24 => 4,  // EMFILE -> too many open files
        30 => 5,  // EROFS (handle not writable) -> access denied
        _ => 1,   // invalid function / generic failure
    }
}

pub(super) fn open_policies(mode: u8) -> Option<(crate::kernel::vfs::OpenAccess, crate::kernel::vfs::SharePolicy)> {
    use crate::kernel::vfs::{OpenAccess, SharePolicy};
    let access = match mode & 3 {
        0 => OpenAccess::Read,
        1 => OpenAccess::Write,
        2 => OpenAccess::ReadWrite,
        _ => return None,
    };
    let share = match (mode >> 4) & 7 {
        0 => SharePolicy::Compatibility,
        1 => SharePolicy::DenyAll,
        2 => SharePolicy::DenyWrite,
        3 => SharePolicy::DenyRead,
        4 => SharePolicy::DenyNone,
        _ => return None,
    };
    Some((access, share))
}

/// Make an already-open VFS descriptor visible through DOS's JFT and SFT.
/// Failure consumes the descriptor, so the three tables cannot disagree.
#[inline(never)]
fn publish_file_handle<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    dos: &thread::DosState<A>,
    fd: i32,
    size: u32,
) -> Result<u16, i32> {
    if fd < 0 { return Err(fd); }
    if Psp::set_jft(machine, psp_struct_seg(dos), fd as usize, fd as u8).is_err() {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        return Err(-24); // EMFILE
    }
    sft_set_file(machine, fd as u16, size);
    Ok(fd as u16)
}

/// Apply DOS open/share semantics, then publish the descriptor as a handle.
#[inline(never)]
pub(super) fn accept_open_file<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    dos: &thread::DosState<A>,
    fd: i32,
    mode: u8,
) -> Result<u16, i32> {
    if fd < 0 { return Err(fd); }
    let policy = open_policies(mode);
    let writable = mode & 3 == 0 || (crate::kernel::vfs::fd_writable(fd, &kt.fds)
        && crate::kernel::vfs::fd_dos_attributes(fd, &kt.fds).is_some_and(|a| a & 1 == 0));
    let rc = policy.map_or(-22, |(access, share)| {
        if writable { crate::kernel::vfs::configure_open(fd, access, share, &kt.fds) }
        else { -13 }
    });
    if rc < 0 {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        return Err(rc);
    }
    let size = crate::kernel::vfs::file_size(fd, &kt.fds);
    publish_file_handle(machine, kt, dos, fd, size)
}

/// Create a VFS object and publish its descriptor as a new DOS handle.
#[inline(never)]
pub(super) fn create_file_handle<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    dos: &thread::DosState<A>,
    path: &[u8],
) -> Result<u16, i32> {
    if crate::kernel::vfs::dos_attributes(path).is_some_and(|attributes| attributes & 1 != 0) { return Err(-13); }
    let fd = crate::kernel::vfs::create(path, &mut kt.fds);
    publish_file_handle(machine, kt, dos, fd, 0)
}

pub(super) struct VfsPath {
    bytes: alloc::vec::Vec<u8>,
    len: usize,
}

impl VfsPath {
    pub(super) fn as_bytes(&self) -> &[u8] { &self.bytes[..self.len] }
}

pub(super) enum PathTarget { Existing, New }

/// Read and resolve a DOS path. A new target permits only the final component
/// to be absent, as required by create and rename destinations.
#[inline(never)]
pub(super) fn resolve_guest_path<A: crate::Arch>(
    machine: &mut A,
    dos: &thread::DosState<A>,
    regs: &Regs,
    segment: u16,
    offset: u32,
    target: PathTarget,
) -> Result<VfsPath, i32> {
    let mut raw = [0; dfs::DFS_PATH_MAX];
    let address = seg_offset(dos, regs, segment, offset);
    let len = read_asciiz(machine, address, &mut raw);
    let (bytes, len) = match target {
        PathTarget::Existing => dfs_open_existing(dos, &raw[..len])?,
        PathTarget::New => dfs_create_path(dos, &raw[..len])?,
    };
    Ok(VfsPath { bytes, len })
}

/// Resolve a DOS filespec while preserving its wildcard leaf. The directory
/// becomes a VFS path and the leaf remains in DOS 8.3 matching form.
#[inline(never)]
pub(super) fn resolve_search_path(
    dfs: &dfs::DfsState,
    filespec: &[u8],
    output: &mut [u8],
) -> Result<usize, i32> {
    let mut absolute = [0; dfs::DFS_PATH_MAX];
    let len = dfs.resolve(filespec, &mut absolute)?;
    let split = absolute[..len].iter().rposition(|&b| b == b'\\').unwrap_or(0);
    let (directory, pattern) = absolute[..len].split_at(split + 1);
    let directory = if directory.len() > 3 {
        &directory[..directory.len() - 1]
    } else {
        directory
    };
    let mut vfs = alloc::vec![0; crate::kernel::vfs::PATH_KEY_MAX];
    let vfs_len = dfs::DfsState::to_vfs_open(directory, &mut vfs)?;
    if vfs_len + usize::from(vfs_len > 0) + pattern.len() > output.len() { return Err(3); }
    let mut len = vfs_len;
    output[..len].copy_from_slice(&vfs[..len]);
    if vfs_len > 0 && len < output.len() {
        output[len] = b'/';
        len += 1;
    }
    let count = pattern.len().min(output.len() - len);
    output[len..len + count].copy_from_slice(&pattern[..count]);
    Ok(len + count)
}

/// Match a filename against a DOS wildcard pattern (e.g. "*.*", "*.EXE").
/// Case-insensitive. Supports '*' and '?' wildcards.
pub(super) fn dos_wildcard_match(pattern: &[u8], name: &[u8]) -> bool {
    // Convert both pattern and name to 11-byte FCB format (8.3, space-padded)
    // then compare. In FCB format, '?' matches any char including space (padding).
    let to_fcb = |s: &[u8]| -> [u8; 11] {
        let mut fcb = [b' '; 11];
        let mut i = 0;
        let mut pos = 0;
        // Base name (up to 8 chars)
        while i < s.len() && s[i] != b'.' && pos < 8 {
            if s[i] == b'*' {
                while pos < 8 { fcb[pos] = b'?'; pos += 1; }
                i += 1;
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        // Skip to dot
        while i < s.len() && s[i] != b'.' { i += 1; }
        if i < s.len() && s[i] == b'.' { i += 1; }
        // Extension (up to 3 chars)
        pos = 8;
        while i < s.len() && pos < 11 {
            if s[i] == b'*' {
                while pos < 11 { fcb[pos] = b'?'; pos += 1; }
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        fcb
    };

    let pat_fcb = to_fcb(pattern);
    let name_fcb = to_fcb(name);

    for i in 0..11 {
        if pat_fcb[i] != b'?' && pat_fcb[i] != name_fcb[i] {
            return false;
        }
    }
    true
}

/// Resolve a raw DOS path to a VFS path for OPEN (all components must exist).
/// Returns a heap-backed VFS path and its length, or a DOS error code.
/// (2 = file not found, 3 = path not found, 15 = invalid drive).
pub(crate) fn dfs_open_existing<A: crate::Arch>(dos: &thread::DosState<A>, dos_in: &[u8])
    -> Result<(alloc::vec::Vec<u8>, usize), i32>
{
    // An empty name is not a file. `resolve` would fold it into the current
    // directory and `to_vfs_open` would hand back a perfectly good handle to
    // that *directory*, so a caller that built its filename wrongly gets a
    // successful open and reads garbage instead of an error it can act on.
    // Real DOS reports "file not found" here, and so do we.
    //
    // Seen for real: DOS/4GW passes an open's filename in a low-memory
    // transfer buffer via a real-mode-call structure. When that structure
    // arrives with DS=0 the buffer address resolves to the wrong linear
    // address, which reads as an empty string — Dark Forces then opened
    // C:\GAMES\DFORCES itself eight times and gave up. That DS=0 is a
    // separate bug; this guard makes it fail honestly rather than silently.
    if dos_in.is_empty() {
        return Err(2); // DOS error 2 — file not found
    }
    let mut abs = [0u8; dfs::DFS_PATH_MAX];
    let alen = dos.dfs.resolve(dos_in, &mut abs)?;
    let mut out = alloc::vec![0u8; crate::kernel::vfs::PATH_KEY_MAX];
    let vlen = dfs::DfsState::to_vfs_open(&abs[..alen], &mut out)?;
    Ok((out, vlen))
}

/// Resolve a raw DOS path to a VFS path for CREATE (final component may not
/// exist yet). Intermediate dirs must exist.
pub(crate) fn dfs_create_path<A: crate::Arch>(dos: &thread::DosState<A>, dos_in: &[u8])
    -> Result<(alloc::vec::Vec<u8>, usize), i32>
{
    let mut abs = [0u8; dfs::DFS_PATH_MAX];
    let alen = dos.dfs.resolve(dos_in, &mut abs)?;
    let mut out = alloc::vec![0u8; crate::kernel::vfs::PATH_KEY_MAX];
    let vlen = dfs::DfsState::to_vfs_create(&abs[..alen], &mut out)?;
    Ok((out, vlen))
}

/// Offsets of our search bookkeeping inside the DTA's 21-byte reserved area
/// (0x00-0x14). Real DOS puts a drive, an 11-byte template, an attribute and
/// a directory index here; we keep the same spirit — enough state to resume —
/// in the tail of that area, and leave the front zeroed.
pub(super) mod dta {
    pub const CURSOR: usize = 0x0D; // u16: next entry index
    pub const SLOT: usize = 0x0F; // u8: index into DosState::searches
    pub const GENERATION: usize = 0x10; // u8: must match the slot's
    pub const MAGIC: usize = 0x11; // u16: this DTA really holds our state
    pub const MAGIC_VALUE: u16 = 0x4F53; // 'SO'
    /// First byte of the caller-visible result (attribute). Everything below
    /// this is the reserved area and must survive across a FindNext.
    pub const RESULT: usize = 0x15;
}

/// Stamp a search's identity and cursor into the caller's DTA.
pub(super) fn write_search_state<A: crate::Arch>(machine: &mut A, dta: usize, slot: u8, generation: u8, cursor: u16) {
    machine.write::<u16>(dta + dta::CURSOR, cursor);
    machine.write::<u8>(dta + dta::SLOT, slot);
    machine.write::<u8>(dta + dta::GENERATION, generation);
    machine.write::<u16>(dta + dta::MAGIC, dta::MAGIC_VALUE);
}

/// Recover `(slot, cursor)` from a DTA, or `None` if it holds no live search
/// of ours — an unpaired FindNext, a DTA the program has since overwritten,
/// or a stale one whose slot has been recycled.
fn read_search_state<A: crate::Arch>(machine: &mut A, dos: &thread::DosState<A>, dta: usize) -> Option<(usize, u16)> {
    if machine.read::<u16>(dta + dta::MAGIC) != dta::MAGIC_VALUE {
        return None;
    }
    let slot = machine.read::<u8>(dta + dta::SLOT) as usize;
    let generation = machine.read::<u8>(dta + dta::GENERATION);
    let s = dos.searches.get(slot)?;
    if !s.in_use || s.generation != generation {
        return None;
    }
    Some((slot, machine.read::<u16>(dta + dta::CURSOR)))
}

/// Claim a search slot, round-robin. Slots are never explicitly freed — DOS
/// has no "close search" call — so the oldest simply gets recycled, and its
/// generation bump invalidates any DTA still pointing at it.
pub(super) fn alloc_search_slot<A: crate::Arch>(dos: &mut thread::DosState<A>) -> usize {
    let slot = dos.search_next as usize % dos.searches.len();
    dos.search_next = dos.search_next.wrapping_add(1);
    let s = &mut dos.searches[slot];
    s.generation = s.generation.wrapping_add(1);
    s.in_use = true;
    slot
}

#[cfg(test)]
mod tests {
    use super::find_attributes_match;

    #[test]
    fn findfirst_requires_directory_attribute_for_directories() {
        assert!(find_attributes_match(0, false));
        assert!(!find_attributes_match(0, true));
        assert!(find_attributes_match(0x10, true));
    }
}

/// FindFirst/FindNext helper: resume the search this DTA identifies, writing
/// the match into the DTA and advancing the cursor kept there.
pub(super) fn find_matching_file<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>) -> DosExit {
    let dta = dos.dta as usize;
    let Some((slot, cursor)) = read_search_state(machine, dos, dta) else {
        // FindNext with no live search in this DTA.
        return DosExit::Error(18); // no more files
    };
    // The search path is an absolute VFS path like "DN/DN*.SWP" or "*.*".
    // The directory part includes any trailing slash; the pattern is the
    // basename (filespec with wildcards).
    let path_len = dos.searches[slot].path.len();
    let full = &dos.searches[slot].path;
    let split = full.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    let dir_buf = {
        let b = full[..split].to_vec();
        (b, split)
    };
    let pat_buf = {
        let mut b = [0u8; 32];
        let plen = (path_len - split).min(b.len());
        b[..plen].copy_from_slice(&full[split..split + plen]);
        (b, plen)
    };
    let dir = &dir_buf.0[..dir_buf.1];
    let pat = &pat_buf.0[..pat_buf.1];

    let mut idx = cursor as usize;
    let generation = dos.searches[slot].generation;
    let attributes = dos.searches[slot].attributes;

    // Iterate DFS's per-dir CI cache. Keys are 8.3 aliases (uppercase),
    // already in the form DOS expects in the DTA filename slot — long VFS
    // names live as `BASE~N.EXT` aliases here. Wildcard match runs against
    // the alias, not the long name.
    let dir_for_ci = if dir.last() == Some(&b'/') { &dir[..dir.len() - 1] } else { dir };
    loop {
        match dfs::ci::entry_at(dir_for_ci, idx) {
            Some((alias, entry)) => {
                idx += 1;
                // Ordinary files always participate; directories require the
                // directory bit in the FindFirst attribute mask.
                if find_attributes_match(attributes, entry.is_dir)
                    && dos_wildcard_match(pat, alias)
                {
                    let found_attributes = entry.attributes;
                    if !dfs::lfn::attributes_match(u16::from(attributes), found_attributes) { continue; }
                    // Clear only the result fields: the reserved area below
                    // holds this search's cursor, and wiping it would strand
                    // the enumeration after its first entry.
                    machine.zero(dta + dta::RESULT, 43 - dta::RESULT);
                    write_search_state(machine, dta, slot as u8, generation, idx as u16);
                    let (time, date) = unix_to_dos_datetime(entry.mtime);
                    machine.write::<u8>(dta + 0x15, found_attributes);
                    machine.write::<u16>(dta + 0x16, time);
                    machine.write::<u16>(dta + 0x18, date);
                    machine.write::<u32>(dta + 0x1A, entry.size);
                    let name_len = alias.len().min(12);
                    machine.copy_to(dta + 0x1E, &alias[..name_len]);
                    machine.write::<u8>(dta + 0x1E + name_len, 0);
                    return DosExit::Ok;
                }
            }
            None => {
                return DosExit::Error(18); // no more files
            }
        }
    }
}

#[inline]
fn find_attributes_match(attributes: u8, is_dir: bool) -> bool {
    !is_dir || attributes & 0x10 != 0
}
