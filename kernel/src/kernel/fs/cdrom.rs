//! One hot-swappable CD-ROM slot and its `C:\CD` image catalogue.
//!
//! The slot itself is mounted once at `cdrom/`; inserting media replaces only
//! the filesystem held behind this proxy, so VFS mount indices remain stable.
//! Images are discovered through VFS, making the same catalogue work from the
//! proprietary disk on hosted, emulated, and physical machines.
//!
//! Media is the catalogue image FILE, read through a [`vfs::BackingFile`] —
//! not a RAM copy, so a full 700MB disc costs no memory and needs no size
//! cap. Caching, if ever needed, is the VFS's job at that seam.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::iso9660::{CueSheet, DiscFormat, Iso9660Fs, MediaError, RandomAccess};
use crate::kernel::vfs::{self, BackingFile, DirEntry, Filesystem, Vnode};

const SLOT_PREFIX: &[u8] = b"cdrom/";
/// Cue SHEETS (small text files) are still slurped for parsing.
const MAX_CUE_BYTES: u32 = 1024 * 1024;

/// Runtime drive-speed model selected in the OSD. Index zero means no
/// throttling; the remaining entries model the original 150 KiB/s CD-ROM
/// multiples. Keep 2x as the default for compatibility with the installer
/// timing that motivated the model.
const SPEED_BYTES_PER_SECOND: [u64; 4] = [0, 150 * 1024, 300 * 1024, 600 * 1024];
const SPEED_LABELS: [&[u8]; 4] = [b"None", b"1x", b"2x", b"4x"];
const DEFAULT_SPEED: u32 = 2;
static SPEED: AtomicU32 = AtomicU32::new(DEFAULT_SPEED);

fn speed_index() -> usize {
    (SPEED.load(Ordering::Relaxed) as usize).min(SPEED_BYTES_PER_SECOND.len() - 1)
}

/// Time a successful transfer should occupy. `None` means an unthrottled
/// virtual drive, so callers complete the read immediately.
pub fn transfer_ns(bytes: usize) -> Option<u64> {
    let bytes_per_second = SPEED_BYTES_PER_SECOND[speed_index()];
    if bytes_per_second == 0 {
        return None;
    }
    let numerator = (bytes as u128) * 1_000_000_000u128;
    Some(
        numerator
            .div_ceil(bytes_per_second as u128)
            .min(u128::from(u64::MAX)) as u64,
    )
}

pub fn speed_label() -> &'static [u8] {
    SPEED_LABELS[speed_index()]
}

pub fn cycle_speed(forward: bool) {
    let count = SPEED_BYTES_PER_SECOND.len();
    let current = speed_index();
    let next = if forward {
        (current + 1) % count
    } else {
        (current + count - 1) % count
    };
    SPEED.store(next as u32, Ordering::Relaxed);
}

/// The image file as the disc: positional reads straight to the backing fs.
/// The slot closes the handle on eject; `Iso9660Fs` only ever reads.
struct FileImage(BackingFile);

impl RandomAccess for FileImage {
    fn len(&self) -> u64 {
        self.0.size() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, MediaError> {
        let offset = u32::try_from(offset).map_err(|_| MediaError::OutOfBounds)?;
        if offset > self.0.size() {
            return Err(MediaError::OutOfBounds);
        }
        let want = buf.len().min((self.0.size() - offset) as usize);
        let n = self.0.read_at(offset, &mut buf[..want]);
        if n < 0 {
            return Err(MediaError::Io);
        }
        Ok(n as usize)
    }
}

struct SlotState {
    generation: u32,
    media: Option<Box<Iso9660Fs>>,
    /// The slot owns the backing handle's lifecycle (closed on eject/swap);
    /// `media`'s `FileImage` holds a working copy of the same handle.
    backing: Option<BackingFile>,
    label: Vec<u8>,
}

struct CdSlot {
    state: Mutex<SlotState>,
}

static CD_SLOT: CdSlot = CdSlot {
    state: Mutex::new(SlotState {
        generation: 0,
        media: None,
        backing: None,
        label: Vec::new(),
    }),
};

fn split_handle(handle: u64) -> (u32, u64) {
    ((handle >> 32) as u32, handle & u32::MAX as u64)
}

impl Filesystem for CdSlot {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let state = self.state.lock();
        let mut vnode = state.media.as_ref()?.open(path)?;
        if vnode.handle > u32::MAX as u64 {
            return None;
        }
        vnode.handle |= (state.generation as u64) << 32;
        Some(vnode)
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32 {
        let (generation, inner) = split_handle(handle);
        let state = self.state.lock();
        if generation != state.generation {
            return -5;
        }
        state
            .media
            .as_ref()
            .map_or(-5, |media| media.read(inner, offset, buf, size))
    }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        self.state
            .lock()
            .media
            .as_ref()?
            .readdir(dir, cookie, out, max)
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        self.state
            .lock()
            .media
            .as_ref()
            .is_some_and(|media| media.dir_exists(path))
    }

    fn clunk(&self, handle: u64) {
        let (generation, inner) = split_handle(handle);
        let state = self.state.lock();
        if generation == state.generation
            && let Some(media) = state.media.as_ref()
        {
            media.clunk(inner);
        }
    }

    fn write(&self, _handle: u64, _offset: u32, _data: &[u8]) -> i32 {
        -1
    }
}

#[derive(Clone)]
struct CatalogEntry {
    name: Vec<u8>,
    path: Vec<u8>,
}

static CATALOG: Mutex<Vec<CatalogEntry>> = Mutex::new(Vec::new());

/// Install the permanent, initially empty slot. Called after the ordinary
/// startup mount tree is complete.
pub fn init() {
    vfs::mount(SLOT_PREFIX, &CD_SLOT);
}

fn catalog_dir() -> Vec<u8> {
    let mut path = crate::kernel::dos::c_root().to_vec();
    path.extend_from_slice(b"CD");
    path
}

fn supported_name(name: &[u8]) -> bool {
    name.rsplit(|byte| *byte == b'.')
        .next()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(b"ISO") || ext.eq_ignore_ascii_case(b"CUE"))
}

/// Rebuild the OSD catalogue from `C:\CD`.
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
        found.push(CatalogEntry {
            name: name.to_vec(),
            path,
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    *CATALOG.lock() = found;
}

pub fn catalog_count() -> usize {
    CATALOG.lock().len()
}

pub fn catalog_name(index: usize, out: &mut [u8]) -> usize {
    let catalog = CATALOG.lock();
    let Some(entry) = catalog.get(index) else {
        return 0;
    };
    let n = entry.name.len().min(out.len());
    out[..n].copy_from_slice(&entry.name[..n]);
    n
}

pub fn is_inserted() -> bool {
    CD_SLOT.state.lock().media.is_some()
}

/// Name of the inserted image (for the OSD's "Eject <name>" row). Returns
/// bytes written; 0 while the slot is empty.
pub fn label(out: &mut [u8]) -> usize {
    let slot = CD_SLOT.state.lock();
    let n = slot.label.len().min(out.len());
    out[..n].copy_from_slice(&slot.label[..n]);
    n
}

pub fn selected(index: usize) -> bool {
    let catalog = CATALOG.lock();
    let Some(entry) = catalog.get(index) else {
        return false;
    };
    CD_SLOT.state.lock().label == entry.name
}

pub fn eject() {
    {
        let _fs = vfs::serialize_fs(); // backing close outside a VFS op
        let mut slot = CD_SLOT.state.lock();
        slot.generation = slot.generation.wrapping_add(1);
        slot.media = None;
        if let Some(backing) = slot.backing.take() {
            backing.close();
        }
        slot.label.clear();
    }
    vfs::mounted_media_changed();
    crate::println!("CD-ROM: ejected");
}

fn read_cue_file(path: &[u8]) -> Result<Vec<u8>, MediaError> {
    super::read_image_file(path, MAX_CUE_BYTES).map_err(|e| match e {
        super::ImageReadError::TooBig => MediaError::InvalidImage,
        super::ImageReadError::Io => MediaError::Io,
    })
}

fn sibling_path(path: &[u8], filename: &[u8]) -> Vec<u8> {
    let parent = path
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(0, |i| i + 1);
    let mut result = path[..parent].to_vec();
    result.extend_from_slice(filename);
    result
}

/// Insert one catalogue entry into the fixed slot: the image FILE becomes
/// the disc (a .CUE's small sheet is parsed from RAM; its .BIN is the disc).
pub fn insert(index: usize) -> Result<(), MediaError> {
    let entry = CATALOG
        .lock()
        .get(index)
        .cloned()
        .ok_or(MediaError::OutOfBounds)?;
    let is_cue = entry
        .name
        .rsplit(|byte| *byte == b'.')
        .next()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(b"CUE"));

    // Resolve everything through the VFS first (cue slurp, backing open) —
    // these are ordinary VFS operations and must NOT run under the guard.
    let cue = if is_cue {
        Some(read_cue_file(&entry.path)?)
    } else {
        None
    };
    let disc_path = match &cue {
        Some(cue) => {
            let sheet = CueSheet::parse(cue)?;
            sibling_path(&entry.path, &sheet.bin_file)
        }
        None => entry.path.clone(),
    };
    let backing = vfs::open_backing(&disc_path).ok_or(MediaError::Io)?;

    {
        // Backing I/O (descriptor parse) and the swap (old handle close)
        // happen outside a VFS op: serialization guard until after the
        // swap, released before mounted_media_changed re-enters the VFS.
        let _fs = vfs::serialize_fs();
        let format = match &cue {
            Some(cue) => DiscFormat::Cue(cue),
            None => DiscFormat::Iso,
        };
        let filesystem = match Iso9660Fs::open(Box::new(FileImage(backing)), format) {
            Ok(fs) => fs,
            Err(e) => {
                backing.close();
                return Err(e);
            }
        };
        let mut slot = CD_SLOT.state.lock();
        slot.generation = slot.generation.wrapping_add(1);
        slot.media = Some(Box::new(filesystem));
        if let Some(old) = slot.backing.replace(backing) {
            old.close();
        }
        slot.label = entry.name.clone();
    }
    vfs::mounted_media_changed();
    crate::println!(
        "CD-ROM: inserted {} as D:",
        String::from_utf8_lossy(&entry.name)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SPEED, supported_name, transfer_ns};
    use core::sync::atomic::Ordering;

    #[test]
    fn catalogue_accepts_iso_and_cue_only() {
        assert!(supported_name(b"DESCENT.ISO"));
        assert!(supported_name(b"game.cue"));
        assert!(!supported_name(b"track.bin"));
        assert!(!supported_name(b"README.TXT"));
    }

    #[test]
    fn drive_speed_models_cdrom_multiples_and_none() {
        let saved = SPEED.load(Ordering::Relaxed);
        SPEED.store(0, Ordering::Relaxed);
        assert_eq!(transfer_ns(300 * 1024), None);
        SPEED.store(1, Ordering::Relaxed);
        assert_eq!(transfer_ns(300 * 1024), Some(2_000_000_000));
        SPEED.store(2, Ordering::Relaxed);
        assert_eq!(transfer_ns(300 * 1024), Some(1_000_000_000));
        SPEED.store(3, Ordering::Relaxed);
        assert_eq!(transfer_ns(300 * 1024), Some(500_000_000));
        SPEED.store(saved, Ordering::Relaxed);
    }
}
