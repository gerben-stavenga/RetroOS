//! Two hot-swappable floppy slots (DOS A: and B:) and their `C:\FLOPPY`
//! image catalogue.
//!
//! Same shape as the CD-ROM slot: each drive is mounted once (`floppya/`,
//! `floppyb/`); inserting media replaces only the FAT filesystem held behind
//! the proxy, so VFS mount indices stay stable, and a generation counter
//! invalidates handles from before a swap.
//!
//! Media is the catalogue image FILE, not a RAM copy: every read and write
//! goes through a [`vfs::BackingFile`] straight to the image, so guest
//! writes persist by construction (no flush-back lifecycle) and a 4MB
//! machine pays for no image buffer — caching, if ever needed, is the
//! VFS's job at that seam. Writes are LIVE: rust-fatfs allocates clusters
//! and updates directories in place on the image.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::kernel::vfs::{self, BackingFile, DirEntry, Filesystem, Vnode};

pub const DRIVES: usize = 2;
const SLOT_PREFIXES: [&[u8]; DRIVES] = [b"floppya/", b"floppyb/"];
const DRIVE_LETTERS: [u8; DRIVES] = *b"AB";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    OutOfBounds,
    Io,
    /// The image did not parse as a FAT volume.
    BadFilesystem,
}

// ── The image file behind fatfs's byte-stream io traits ─────────────────────

/// `std::io::Cursor` semantics over the backing image file: seeks anywhere
/// ≥ 0, reads past the end return 0 bytes. Writes go straight through to the
/// image file; the media size is fixed (a floppy cannot grow), so writing
/// past the end is an error rather than an extension.
struct ImageCursor {
    file: BackingFile,
    pos: u64,
}

impl ImageCursor {
    fn len(&self) -> u64 {
        self.file.size() as u64
    }
}

impl fatfs::IoBase for ImageCursor {
    type Error = ();
}

impl fatfs::Read for ImageCursor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        if self.pos >= self.len() {
            return Ok(0);
        }
        let avail = (self.len() - self.pos) as usize;
        let want = buf.len().min(avail);
        let n = self.file.read_at(self.pos as u32, &mut buf[..want]);
        if n < 0 {
            return Err(());
        }
        self.pos += n as u64;
        Ok(n as usize)
    }
}

impl fatfs::Write for ImageCursor {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ()> {
        let end = self.pos.checked_add(buf.len() as u64).ok_or(())?;
        if end > self.len() {
            return Err(());
        }
        let n = self.file.write_at(self.pos as u32, buf);
        if n <= 0 && !buf.is_empty() {
            return Err(());
        }
        self.pos += n as u64;
        Ok(n as usize)
    }

    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl fatfs::Seek for ImageCursor {
    fn seek(&mut self, pos: fatfs::SeekFrom) -> Result<u64, ()> {
        let new = match pos {
            fatfs::SeekFrom::Start(n) => Some(n),
            fatfs::SeekFrom::End(n) => self.len().checked_add_signed(n),
            fatfs::SeekFrom::Current(n) => self.pos.checked_add_signed(n),
        };
        match new {
            Some(n) => {
                self.pos = n;
                Ok(n)
            }
            None => Err(()),
        }
    }
}

type Media = fatfs::FileSystem<ImageCursor>;

// ── CHS shape of the inserted medium (the INT 13h view) ─────────────────────

/// Read from the image's BPB — every DOS FORMAT and mkfs writes real
/// sectors-per-track/head counts there, so no size→geometry guess table
/// is needed for the shape itself.
#[derive(Clone, Copy)]
pub struct ChsGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors_per_track: u8,
    pub total_sectors: u32,
    /// BIOS drive type (INT 13h AH=08h BL): 1=360K, 2=1.2M, 3=720K,
    /// 4=1.44M, 5=2.88M.
    pub drive_type: u8,
}

fn parse_chs(boot_sector: &[u8]) -> Option<ChsGeometry> {
    let image = boot_sector;
    if image.len() < 512 {
        return None;
    }
    let word = |o: usize| u16::from_le_bytes([image[o], image[o + 1]]);
    let sectors_per_track = word(24);
    let heads = word(26);
    let total16 = word(19);
    let total = if total16 != 0 {
        total16 as u32
    } else {
        u32::from_le_bytes([image[32], image[33], image[34], image[35]])
    };
    if !(1..=63).contains(&sectors_per_track) || !(1..=16).contains(&heads) || total == 0 {
        return None;
    }
    let cylinders = total / (sectors_per_track as u32 * heads as u32);
    if cylinders == 0 || cylinders > u16::MAX as u32 {
        return None;
    }
    let drive_type = match total * 512 {
        368_640 => 1,
        1_228_800 => 2,
        737_280 => 3,
        1_474_560 => 4,
        2_949_120 => 5,
        // Nonstandard sizes: nearest standard drive class by capacity.
        n if n <= 409_600 => 1,
        n if n <= 819_200 => 3,
        n if n <= 1_310_720 => 2,
        _ => 4,
    };
    Some(ChsGeometry {
        cylinders: cylinders as u16,
        heads: heads as u8,
        sectors_per_track: sectors_per_track as u8,
        total_sectors: total,
        drive_type,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectorError {
    NoMedia,
    OutOfRange,
}

/// The inserted medium's CHS shape; `None` while the drive is empty.
pub fn chs_geometry(drive: usize) -> Option<ChsGeometry> {
    slot(drive).state.lock().geom
}

/// One 512-byte sector by LBA, for INT 13h CHS reads (the caller does the
/// CHS→LBA arithmetic against `chs_geometry`).
pub fn read_sector(drive: usize, lba: u32, out: &mut [u8; 512]) -> Result<(), SectorError> {
    let _fs = vfs::serialize_fs(); // backing access from outside a VFS op
    let state = slot(drive).state.lock();
    let file = state.backing.as_ref().ok_or(SectorError::NoMedia)?;
    let start = lba.checked_mul(512).ok_or(SectorError::OutOfRange)?;
    if start.checked_add(512).is_none_or(|end| end > file.size()) {
        return Err(SectorError::OutOfRange);
    }
    if file.read_at(start, out) != 512 {
        return Err(SectorError::OutOfRange);
    }
    Ok(())
}

/// Sector write for INT 13h AH=03h — straight through to the image file,
/// coherent with the FAT layer (same backing handle).
pub fn write_sector(drive: usize, lba: u32, data: &[u8; 512]) -> Result<(), SectorError> {
    let _fs = vfs::serialize_fs(); // backing access from outside a VFS op
    let state = slot(drive).state.lock();
    let file = state.backing.as_ref().ok_or(SectorError::NoMedia)?;
    let start = lba.checked_mul(512).ok_or(SectorError::OutOfRange)?;
    if start.checked_add(512).is_none_or(|end| end > file.size()) {
        return Err(SectorError::OutOfRange);
    }
    if file.write_at(start, data) != 512 {
        return Err(SectorError::OutOfRange);
    }
    Ok(())
}

/// BIOS change line: true once after each insert/eject, then cleared —
/// INT 13h AH=16h report-once semantics.
pub fn take_change_line(drive: usize) -> bool {
    core::mem::replace(&mut slot(drive).state.lock().change_pending, false)
}

// ── The per-drive slot proxy ────────────────────────────────────────────────

struct SlotState {
    generation: u32,
    media: Option<Media>,
    /// Second view of the same image file `media`'s cursor uses — for the
    /// sector layer (INT 13h). The slot owns the close (on eject); this and
    /// the cursor's copy share the one backing-fs handle.
    backing: Option<BackingFile>,
    geom: Option<ChsGeometry>,
    label: Vec<u8>,
    /// BIOS change line: set by insert/eject, cleared when INT 13h AH=16h
    /// reports it.
    change_pending: bool,
    /// Open handles → paths. Reads/writes re-resolve by path; it keeps the
    /// borrow of `media` inside each call (fatfs `File`s borrow the
    /// `FileSystem`).
    opens: BTreeMap<u32, Vec<u8>>,
    next_handle: u32,
}

pub struct FloppySlot {
    state: Mutex<SlotState>,
}

const fn empty_slot() -> FloppySlot {
    FloppySlot {
        state: Mutex::new(SlotState {
            generation: 0,
            media: None,
            backing: None,
            geom: None,
            label: Vec::new(),
            change_pending: false,
            opens: BTreeMap::new(),
            next_handle: 1,
        }),
    }
}

static SLOT_A: FloppySlot = empty_slot();
static SLOT_B: FloppySlot = empty_slot();

fn slot(drive: usize) -> &'static FloppySlot {
    if drive == 0 { &SLOT_A } else { &SLOT_B }
}

fn split_handle(handle: u64) -> (u32, u32) {
    ((handle >> 32) as u32, handle as u32)
}

/// DOS datetime (as rust-fatfs reports it) → seconds since the Unix epoch.
fn unix_from_datetime(dt: &fatfs::DateTime) -> u32 {
    unix_from_ymd_hms(
        dt.date.year, dt.date.month, dt.date.day,
        dt.time.hour, dt.time.min, dt.time.sec,
    )
}

/// Days-from-civil-date, branchless. fatfs decodes stored timestamp fields
/// without validation, so FAT's zeroed "no timestamp" encoding arrives here
/// as month 0 / day 0 and must fall out as 0 via the validity guard.
fn unix_from_ymd_hms(year: u16, month: u16, day: u16, hour: u16, min: u16, sec: u16) -> u32 {
    let (y, m, d) = (year as i64, month as i64, day as i64);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || y < 1980 {
        return 0;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    u32::try_from(secs).unwrap_or(0)
}

fn path_str(path: &[u8]) -> Option<&str> {
    core::str::from_utf8(path).ok()
}

/// `"."`/`".."` chain entries of FAT subdirectories; VFS paths never use them.
fn is_dot_entry(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

impl Filesystem for FloppySlot {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let mut state = self.state.lock();
        let generation = state.generation;
        let media = state.media.as_ref()?;
        let mut file = media.root_dir().open_file(path_str(path)?).ok()?;
        let size = fatfs::Seek::seek(&mut file, fatfs::SeekFrom::End(0)).ok()?;
        let size = u32::try_from(size).ok()?;
        drop(file);
        let handle = state.next_handle;
        state.next_handle = state.next_handle.checked_add(1).unwrap_or(1);
        state.opens.insert(handle, path.to_vec());
        Some(Vnode {
            handle: (generation as u64) << 32 | handle as u64,
            size,
            mode: 0o644,
        })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        let (generation, inner) = split_handle(handle);
        let state = self.state.lock();
        if generation != state.generation {
            return -5;
        }
        let Some(path) = state.opens.get(&inner) else { return -9 };
        let Some(media) = state.media.as_ref() else { return -5 };
        let Some(path) = path_str(path) else { return -5 };
        let Ok(mut file) = media.root_dir().open_file(path) else { return -5 };
        if fatfs::Seek::seek(&mut file, fatfs::SeekFrom::Start(offset as u64)).is_err() {
            return -5;
        }
        let mut done = 0;
        while done < buf.len() {
            match fatfs::Read::read(&mut file, &mut buf[done..]) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(_) => return if done == 0 { -5 } else { done as i32 },
            }
        }
        done as i32
    }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        let state = self.state.lock();
        let media = state.media.as_ref()?;
        let root = media.root_dir();
        let listing = if dir.is_empty() { root } else { root.open_dir(path_str(dir)?).ok()? };
        let mut visible = 0_u64;
        for entry in listing.iter() {
            let Ok(entry) = entry else { break };
            let short = entry.short_file_name_as_bytes();
            if is_dot_entry(short) {
                continue;
            }
            if visible < cookie {
                visible += 1;
                continue;
            }
            if out.len() >= max {
                return Some(visible);
            }
            let name_len = short.len().min(100);
            let mut de = DirEntry {
                name: [0; 100],
                name_len,
                size: entry.len().min(u32::MAX as u64) as u32,
                is_dir: entry.is_dir(),
                is_symlink: false,
                mode: if entry.is_dir() { 0o555 } else { 0o444 },
                mtime: unix_from_datetime(&entry.modified()),
            };
            de.name[..name_len].copy_from_slice(&short[..name_len]);
            out.push(de);
            visible += 1;
        }
        None
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        let state = self.state.lock();
        let Some(media) = state.media.as_ref() else { return false };
        if path.is_empty() {
            return true;
        }
        path_str(path).is_some_and(|p| media.root_dir().open_dir(p).is_ok())
    }

    fn clunk(&self, handle: u64) {
        let (generation, inner) = split_handle(handle);
        let mut state = self.state.lock();
        if generation == state.generation {
            state.opens.remove(&inner);
        }
    }

    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        let (generation, inner) = split_handle(handle);
        let state = self.state.lock();
        if generation != state.generation {
            return -5;
        }
        let Some(path) = state.opens.get(&inner) else { return -9 };
        let Some(media) = state.media.as_ref() else { return -5 };
        let Some(path) = path_str(path) else { return -5 };
        let Ok(mut file) = media.root_dir().open_file(path) else { return -5 };
        if fatfs::Seek::seek(&mut file, fatfs::SeekFrom::Start(offset as u64)).is_err() {
            return -5;
        }
        let mut done = 0;
        while done < data.len() {
            match fatfs::Write::write(&mut file, &data[done..]) {
                Ok(0) => break, // media full / fixed size reached
                Ok(n) => done += n,
                Err(_) => return if done == 0 { -28 } else { done as i32 },
            }
        }
        if fatfs::Write::flush(&mut file).is_err() {
            return -5;
        }
        done as i32
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        let mut state = self.state.lock();
        let generation = state.generation;
        let media = state.media.as_ref()?;
        let mut file = media.root_dir().create_file(path_str(path)?).ok()?;
        file.truncate().ok()?; // DOS AH=3Ch create-or-truncate semantics
        drop(file);
        let handle = state.next_handle;
        state.next_handle = state.next_handle.checked_add(1).unwrap_or(1);
        state.opens.insert(handle, path.to_vec());
        Some(Vnode {
            handle: (generation as u64) << 32 | handle as u64,
            size: 0,
            mode: 0o644,
        })
    }

    fn supports_create(&self) -> bool {
        true
    }

    fn remove(&self, path: &[u8]) -> i32 {
        let state = self.state.lock();
        let Some(media) = state.media.as_ref() else { return -5 };
        let Some(path) = path_str(path) else { return -5 };
        if media.root_dir().remove(path).is_ok() { 0 } else { -2 }
    }

    fn mkdir(&self, path: &[u8]) -> i32 {
        let state = self.state.lock();
        let Some(media) = state.media.as_ref() else { return -5 };
        let Some(path) = path_str(path) else { return -5 };
        if media.root_dir().create_dir(path).is_ok() { 0 } else { -13 }
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    fn rmdir(&self, path: &[u8]) -> i32 {
        // fatfs `remove` handles empty directories; a non-empty one errors.
        self.remove(path)
    }

    fn rename(&self, path: &[u8], new_path: &[u8]) -> i32 {
        let state = self.state.lock();
        let Some(media) = state.media.as_ref() else { return -5 };
        let (Some(src), Some(dst)) = (path_str(path), path_str(new_path)) else { return -5 };
        let root = media.root_dir();
        if root.rename(src, &root, dst).is_ok() { 0 } else { -2 }
    }

    fn supports_directory_mutation(&self) -> bool {
        true
    }
}

// ── Catalogue and media control (OSD surface) ───────────────────────────────

#[derive(Clone)]
struct CatalogEntry {
    name: Vec<u8>,
    path: Vec<u8>,
}

static CATALOG: Mutex<Vec<CatalogEntry>> = Mutex::new(Vec::new());

/// Install the permanent, initially empty slots. Called after the ordinary
/// startup mount tree is complete.
pub fn init() {
    vfs::mount(SLOT_PREFIXES[0], &SLOT_A);
    vfs::mount(SLOT_PREFIXES[1], &SLOT_B);
}

fn catalog_dir() -> Vec<u8> {
    let mut path = crate::kernel::dos::c_root().to_vec();
    path.extend_from_slice(b"FLOPPY");
    path
}

fn supported_name(name: &[u8]) -> bool {
    name.rsplit(|byte| *byte == b'.').next().is_some_and(|ext| {
        ext.eq_ignore_ascii_case(b"IMA")
            || ext.eq_ignore_ascii_case(b"IMG")
            || ext.eq_ignore_ascii_case(b"VFD")
    })
}

/// Rebuild the OSD catalogue from `C:\FLOPPY`.
pub fn refresh_catalog() {
    let dir = catalog_dir();
    let mut found = Vec::new();
    let mut index = 0;
    while let Some(entry) = vfs::readdir(&dir, index) {
        index += 1;
        let name = &entry.name[..entry.name_len];
        if entry.is_dir || !supported_name(name) {
            continue;
        }
        let mut path = dir.clone();
        path.push(b'/');
        path.extend_from_slice(name);
        found.push(CatalogEntry { name: name.to_vec(), path });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    *CATALOG.lock() = found;
}

pub fn catalog_count() -> usize {
    CATALOG.lock().len()
}

pub fn catalog_name(index: usize, out: &mut [u8]) -> usize {
    let catalog = CATALOG.lock();
    let Some(entry) = catalog.get(index) else { return 0 };
    let n = entry.name.len().min(out.len());
    out[..n].copy_from_slice(&entry.name[..n]);
    n
}

pub fn is_inserted(drive: usize) -> bool {
    slot(drive).state.lock().media.is_some()
}

/// Name of the inserted image (for the OSD's "Eject <name>" row). Returns
/// bytes written; 0 while the drive is empty.
pub fn label(drive: usize, out: &mut [u8]) -> usize {
    let state = slot(drive).state.lock();
    let n = state.label.len().min(out.len());
    out[..n].copy_from_slice(&state.label[..n]);
    n
}

pub fn selected(drive: usize, index: usize) -> bool {
    let catalog = CATALOG.lock();
    let Some(entry) = catalog.get(index) else { return false };
    slot(drive).state.lock().label == entry.name
}

pub fn eject(drive: usize) {
    {
        let _fs = vfs::serialize_fs(); // media drop may flush to backing
        let mut state = slot(drive).state.lock();
        state.generation = state.generation.wrapping_add(1);
        state.media = None; // fatfs Drop flushes its fs state to the image
        if let Some(backing) = state.backing.take() {
            backing.close();
        }
        state.geom = None;
        state.label.clear();
        state.opens.clear();
        state.change_pending = true;
    }
    vfs::mounted_media_changed();
    crate::println!("Floppy {}: ejected", DRIVE_LETTERS[drive] as char);
}

/// Insert one catalogue entry into a drive's slot: open the image FILE as
/// the medium (reads and writes go through to it; nothing is copied).
pub fn insert(drive: usize, index: usize) -> Result<(), InsertError> {
    let entry = CATALOG.lock().get(index).cloned().ok_or(InsertError::OutOfBounds)?;
    let backing = vfs::open_backing(&entry.path).ok_or(InsertError::Io)?;
    {
        // Backing I/O (BPB read, fatfs mount, old media's flush-on-drop)
        // outside a VFS op: hold the serialization guard, release it before
        // mounted_media_changed re-enters the VFS.
        let _fs = vfs::serialize_fs();
        let mut boot = [0u8; 512];
        let geom = if backing.read_at(0, &mut boot) == 512 { parse_chs(&boot) } else { None };
        let cursor = ImageCursor { file: backing, pos: 0 };
        let media = match fatfs::FileSystem::new(cursor, fatfs::FsOptions::new()) {
            Ok(media) => media,
            Err(_) => {
                backing.close();
                return Err(InsertError::BadFilesystem);
            }
        };
        let mut state = slot(drive).state.lock();
        state.generation = state.generation.wrapping_add(1);
        state.media = Some(media); // old media drops (flushes), then...
        if let Some(old) = state.backing.replace(backing) {
            old.close(); // ...its backing closes
        }
        state.geom = geom;
        state.label = entry.name.clone();
        state.opens.clear();
        state.change_pending = true;
    }
    vfs::mounted_media_changed();
    crate::println!(
        "Floppy {}: inserted {}",
        DRIVE_LETTERS[drive] as char,
        String::from_utf8_lossy(&entry.name)
    );
    Ok(())
}

/// Cluster geometry for INT 21h AH=36h: (sectors/cluster, bytes/sector,
/// total clusters, free clusters). `None` while the drive is empty. FAT
/// floppy media is 512 bytes/sector without exception; fatfs keeps the raw
/// BPB private.
pub fn geometry(drive: usize) -> Option<(u16, u16, u16, u16)> {
    let _fs = vfs::serialize_fs(); // stats() may read FAT sectors from backing
    let state = slot(drive).state.lock();
    let media = state.media.as_ref()?;
    let sectors_per_cluster = (media.cluster_size() / 512).max(1);
    let stats = media.stats().ok()?;
    Some((
        u16::try_from(sectors_per_cluster).unwrap_or(1),
        512,
        u16::try_from(stats.total_clusters()).unwrap_or(u16::MAX),
        u16::try_from(stats.free_clusters()).unwrap_or(u16::MAX),
    ))
}

#[cfg(test)]
mod tests {
    use super::{supported_name, unix_from_ymd_hms};

    #[test]
    fn catalogue_accepts_floppy_image_extensions_only() {
        assert!(supported_name(b"DOS622.IMA"));
        assert!(supported_name(b"games.img"));
        assert!(supported_name(b"BOOT.VFD"));
        assert!(!supported_name(b"README.TXT"));
        assert!(!supported_name(b"CD.ISO"));
    }

    #[test]
    fn bpb_geometry_parses_standard_and_rejects_junk() {
        let mut bpb = [0u8; 512];
        bpb[19..21].copy_from_slice(&2880u16.to_le_bytes()); // total sectors
        bpb[24..26].copy_from_slice(&18u16.to_le_bytes()); // sectors/track
        bpb[26..28].copy_from_slice(&2u16.to_le_bytes()); // heads
        let g = super::parse_chs(&bpb).unwrap();
        assert_eq!(
            (g.cylinders, g.heads, g.sectors_per_track, g.drive_type),
            (80, 2, 18, 4)
        );

        bpb[24..26].copy_from_slice(&0u16.to_le_bytes()); // spt 0 = no geometry
        assert!(super::parse_chs(&bpb).is_none());
        assert!(super::parse_chs(&[0u8; 512]).is_none());
    }

    #[test]
    fn dos_datetime_converts_to_unix_epoch() {
        // date -u -d "1994-06-15 12:30:00" +%s
        assert_eq!(unix_from_ymd_hms(1994, 6, 15, 12, 30, 0), 771683400);
        assert_eq!(unix_from_ymd_hms(1980, 1, 1, 0, 0, 0), 315532800);
        // FAT's zeroed no-timestamp encoding decodes (unvalidated) to
        // year 1980, month 0, day 0 — must not read as a real date.
        assert_eq!(unix_from_ymd_hms(1980, 0, 0, 0, 0, 0), 0);
    }
}
