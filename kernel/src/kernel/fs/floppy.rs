//! Two hot-swappable floppy slots (DOS A: and B:) and their `C:\FLOPPY`
//! image catalogue.
//!
//! Same shape as the CD-ROM slot: each drive is mounted once (`floppya/`,
//! `floppyb/`); inserting media replaces only the FAT filesystem held behind
//! the proxy, so VFS mount indices stay stable, and a generation counter
//! invalidates handles from before a swap. Media is a whole image in RAM —
//! at floppy sizes (≤2.88M) that is cheap on any machine that also affords
//! an image catalogue; real FDC hardware would plug in below this proxy as
//! a different `RandomAccess`-style backing, not a different filesystem.
//!
//! Read-only for now: the slot denies writes at the VFS boundary, so DOS
//! sees a write-protected disk. The FAT layer is rust-fatfs, which already
//! knows how to write — lifting the protection later is a policy change
//! plus a flush-back of the RAM image to the catalogue file.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::kernel::vfs::{self, DirEntry, Filesystem, Vnode};

pub const DRIVES: usize = 2;
const SLOT_PREFIXES: [&[u8]; DRIVES] = [b"floppya/", b"floppyb/"];
const DRIVE_LETTERS: [u8; DRIVES] = [b'A', b'B'];
/// 2.88M ED media is 2,949,120 bytes; anything past 4M is not a floppy image.
const MAX_IMAGE_BYTES: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    OutOfBounds,
    TooBig,
    Io,
    /// The image did not parse as a FAT volume.
    BadFilesystem,
}

// ── RAM image behind fatfs's byte-stream io traits ──────────────────────────

/// `std::io::Cursor` semantics over the in-RAM image: seeks anywhere ≥ 0,
/// reads past the end return 0 bytes. Writes land in the Vec (rust-fatfs may
/// touch the dirty flag even on a read-mounted volume); they are invisible
/// outside this slot and vanish on eject.
struct ImageCursor {
    data: Vec<u8>,
    pos: u64,
}

impl fatfs::IoBase for ImageCursor {
    type Error = ();
}

impl fatfs::Read for ImageCursor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        let pos = usize::try_from(self.pos).map_err(|_| ())?;
        if pos >= self.data.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.data.len() - pos);
        buf[..n].copy_from_slice(&self.data[pos..pos + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl fatfs::Write for ImageCursor {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ()> {
        let pos = usize::try_from(self.pos).map_err(|_| ())?;
        let end = pos.checked_add(buf.len()).ok_or(())?;
        if end > self.data.len() {
            if end > MAX_IMAGE_BYTES as usize {
                return Err(());
            }
            self.data.resize(end, 0);
        }
        self.data[pos..end].copy_from_slice(buf);
        self.pos = end as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl fatfs::Seek for ImageCursor {
    fn seek(&mut self, pos: fatfs::SeekFrom) -> Result<u64, ()> {
        let new = match pos {
            fatfs::SeekFrom::Start(n) => Some(n),
            fatfs::SeekFrom::End(n) => (self.data.len() as u64).checked_add_signed(n),
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

// ── The per-drive slot proxy ────────────────────────────────────────────────

struct SlotState {
    generation: u32,
    media: Option<Media>,
    label: Vec<u8>,
    /// Open handles → paths. Reads re-resolve by path; at RAM-image speeds
    /// the double walk is free and it keeps the borrow of `media` inside
    /// each call (fatfs `File`s borrow the `FileSystem`).
    opens: BTreeMap<u32, Vec<u8>>,
    next_handle: u32,
}

pub struct FloppySlot {
    drive: usize,
    state: Mutex<SlotState>,
}

const fn empty_slot(drive: usize) -> FloppySlot {
    FloppySlot {
        drive,
        state: Mutex::new(SlotState {
            generation: 0,
            media: None,
            label: Vec::new(),
            opens: BTreeMap::new(),
            next_handle: 1,
        }),
    }
}

static SLOT_A: FloppySlot = empty_slot(0);
static SLOT_B: FloppySlot = empty_slot(1);

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
            mode: 0o444,
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

    /// Write-protected media: `create` keeps the default `None` with
    /// `supports_create` false, which the VFS treats as read-only backing.
    fn write(&self, _handle: u64, _offset: u32, _data: &[u8]) -> i32 {
        -1
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

pub fn selected(drive: usize, index: usize) -> bool {
    let catalog = CATALOG.lock();
    let Some(entry) = catalog.get(index) else { return false };
    slot(drive).state.lock().label == entry.name
}

pub fn eject(drive: usize) {
    {
        let mut state = slot(drive).state.lock();
        state.generation = state.generation.wrapping_add(1);
        state.media = None;
        state.label.clear();
        state.opens.clear();
    }
    vfs::mounted_media_changed();
    crate::println!("Floppy {}: ejected", DRIVE_LETTERS[drive] as char);
}

/// Load one catalogue entry and insert it into a drive's slot.
pub fn insert(drive: usize, index: usize) -> Result<(), InsertError> {
    let entry = CATALOG.lock().get(index).cloned().ok_or(InsertError::OutOfBounds)?;
    let image = super::read_image_file(&entry.path, MAX_IMAGE_BYTES).map_err(|e| match e {
        super::ImageReadError::TooBig => InsertError::TooBig,
        super::ImageReadError::Io => InsertError::Io,
    })?;
    let cursor = ImageCursor { data: image, pos: 0 };
    let media = fatfs::FileSystem::new(cursor, fatfs::FsOptions::new())
        .map_err(|_| InsertError::BadFilesystem)?;
    {
        let mut state = slot(drive).state.lock();
        state.generation = state.generation.wrapping_add(1);
        state.media = Some(media);
        state.label = entry.name.clone();
        state.opens.clear();
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
/// total clusters). `None` while the drive is empty. FAT floppy media is
/// 512 bytes/sector without exception; fatfs keeps the raw BPB private.
pub fn geometry(drive: usize) -> Option<(u16, u16, u16)> {
    let state = slot(drive).state.lock();
    let media = state.media.as_ref()?;
    let sectors_per_cluster = (media.cluster_size() / 512).max(1);
    let total = media.stats().ok()?.total_clusters();
    Some((
        u16::try_from(sectors_per_cluster).unwrap_or(1),
        512,
        u16::try_from(total).unwrap_or(u16::MAX),
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
    fn dos_datetime_converts_to_unix_epoch() {
        // date -u -d "1994-06-15 12:30:00" +%s
        assert_eq!(unix_from_ymd_hms(1994, 6, 15, 12, 30, 0), 771683400);
        assert_eq!(unix_from_ymd_hms(1980, 1, 1, 0, 0, 0), 315532800);
        // FAT's zeroed no-timestamp encoding decodes (unvalidated) to
        // year 1980, month 0, day 0 — must not read as a real date.
        assert_eq!(unix_from_ymd_hms(1980, 0, 0, 0, 0, 0), 0);
    }
}
