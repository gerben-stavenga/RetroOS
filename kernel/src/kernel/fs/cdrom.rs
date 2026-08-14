//! One hot-swappable CD-ROM slot and its `C:\CD` image catalogue.
//!
//! The slot itself is mounted once at `cdrom/`; inserting media replaces only
//! the filesystem held behind this proxy, so VFS mount indices remain stable.
//! Images are discovered through VFS, making the same catalogue work from the
//! proprietary disk on hosted, emulated, and physical machines.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use super::iso9660::{CueSheet, DiscFormat, Iso9660Fs, MediaError, RandomAccess};
use crate::kernel::vfs::{self, DirEntry, Filesystem, Vnode};

const SLOT_PREFIX: &[u8] = b"cdrom/";
const MAX_IMAGE_BYTES: u32 = 128 * 1024 * 1024;

struct MemoryImage(Vec<u8>);

impl RandomAccess for MemoryImage {
    fn len(&self) -> u64 { self.0.len() as u64 }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, MediaError> {
        let offset = usize::try_from(offset).map_err(|_| MediaError::OutOfBounds)?;
        if offset > self.0.len() {
            return Err(MediaError::OutOfBounds);
        }
        let n = buf.len().min(self.0.len() - offset);
        buf[..n].copy_from_slice(&self.0[offset..offset + n]);
        Ok(n)
    }
}

struct SlotState {
    generation: u32,
    media: Option<Box<Iso9660Fs>>,
    label: Vec<u8>,
}

struct CdSlot {
    state: Mutex<SlotState>,
}

static CD_SLOT: CdSlot = CdSlot {
    state: Mutex::new(SlotState { generation: 0, media: None, label: Vec::new() }),
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
        state.media.as_ref().map_or(-5, |media| media.read(inner, offset, buf, size))
    }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        self.state.lock().media.as_ref()?.readdir(dir, cookie, out, max)
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        self.state.lock().media.as_ref().is_some_and(|media| media.dir_exists(path))
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

    fn write(&self, _handle: u64, _offset: u32, _data: &[u8]) -> i32 { -1 }
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
    name.rsplit(|byte| *byte == b'.').next().is_some_and(|ext|
        ext.eq_ignore_ascii_case(b"ISO") || ext.eq_ignore_ascii_case(b"CUE"))
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

pub fn is_inserted() -> bool {
    CD_SLOT.state.lock().media.is_some()
}

pub fn selected(index: usize) -> bool {
    let catalog = CATALOG.lock();
    let Some(entry) = catalog.get(index) else { return false };
    CD_SLOT.state.lock().label == entry.name
}

pub fn eject() {
    {
        let mut slot = CD_SLOT.state.lock();
        slot.generation = slot.generation.wrapping_add(1);
        slot.media = None;
        slot.label.clear();
    }
    vfs::mounted_media_changed();
    crate::println!("CD-ROM: ejected");
}

fn read_vfs_file(path: &[u8]) -> Result<Vec<u8>, MediaError> {
    let handle = vfs::open_to_handle(path);
    if handle < 0 {
        return Err(MediaError::Io);
    }
    let size = vfs::file_size_by_handle(handle);
    if size > MAX_IMAGE_BYTES {
        vfs::close_vfs_handle(handle);
        return Err(MediaError::InvalidImage);
    }
    let mut data = Vec::new();
    if data.try_reserve_exact(size as usize).is_err() {
        vfs::close_vfs_handle(handle);
        return Err(MediaError::Io);
    }
    data.resize(size as usize, 0);
    let mut offset = 0;
    while offset < data.len() {
        let n = vfs::read_by_handle(handle, &mut data[offset..]);
        if n <= 0 {
            vfs::close_vfs_handle(handle);
            return Err(MediaError::Io);
        }
        offset += n as usize;
    }
    vfs::close_vfs_handle(handle);
    Ok(data)
}

fn sibling_path(path: &[u8], filename: &[u8]) -> Vec<u8> {
    let parent = path.iter().rposition(|byte| *byte == b'/').map_or(0, |i| i + 1);
    let mut result = path[..parent].to_vec();
    result.extend_from_slice(filename);
    result
}

/// Load one catalogue entry and insert it into the fixed slot.
pub fn insert(index: usize) -> Result<(), MediaError> {
    let entry = CATALOG.lock().get(index).cloned().ok_or(MediaError::OutOfBounds)?;
    let is_cue = entry.name.rsplit(|byte| *byte == b'.').next()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(b"CUE"));

    let filesystem = if is_cue {
        let cue = read_vfs_file(&entry.path)?;
        let sheet = CueSheet::parse(&cue)?;
        let bin_path = sibling_path(&entry.path, &sheet.bin_file);
        let bin = read_vfs_file(&bin_path)?;
        Iso9660Fs::open(Box::new(MemoryImage(bin)), DiscFormat::Cue(&cue))?
    } else {
        let iso = read_vfs_file(&entry.path)?;
        Iso9660Fs::open(Box::new(MemoryImage(iso)), DiscFormat::Iso)?
    };

    {
        let mut slot = CD_SLOT.state.lock();
        slot.generation = slot.generation.wrapping_add(1);
        slot.media = Some(Box::new(filesystem));
        slot.label = entry.name.clone();
    }
    vfs::mounted_media_changed();
    crate::println!("CD-ROM: inserted {} as D:", String::from_utf8_lossy(&entry.name));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::supported_name;

    #[test]
    fn catalogue_accepts_iso_and_cue_only() {
        assert!(supported_name(b"DESCENT.ISO"));
        assert!(supported_name(b"game.cue"));
        assert!(!supported_name(b"track.bin"));
        assert!(!supported_name(b"README.TXT"));
    }
}
