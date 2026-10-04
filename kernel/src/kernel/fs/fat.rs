//! Shared read/write FAT12/16/32 VFS adapter for image files and disk volumes.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::kernel::vfs::{DirEntry, Filesystem, ShortName, Vnode};
use crate::kernel::block::Volume;

/// A resident copy above this size isn't worth pinning outside the shared
/// disk cache — 386/4 MB machines only ever format volumes small enough to
/// stay well under it anyway.
const FAT_CACHE_CAP: u64 = 2 * 1024 * 1024;

/// Byte-stream I/O over one bounded partition (or a raw GRUB module).
/// Unaligned FAT metadata writes preserve the rest of their sector.
pub struct VolumeIo {
    volume: Volume,
    position: u64,
    writable: bool,
    /// (start byte, length) of the FAT table region(s) — every copy, back to
    /// back — once computed from the BPB. `None` until the first read/write
    /// tries to resolve it; `Some(None)` if there's nothing worth caching
    /// (oversized table, non-512-byte sectors, or a non-FAT boot sector).
    fat_range: Option<Option<(u64, u64)>>,
    /// The FAT table region held resident once first touched. Every cluster
    /// hop that would otherwise round-trip through the shared block cache —
    /// competing with the data region for the same limited page budget, and
    /// alternating with it on every single cluster — reads straight from
    /// here instead. Writes go through `self.volume` as always and are
    /// mirrored here to stay coherent.
    fat_cache: Option<Vec<u8>>,
}

impl VolumeIo {
    pub fn new(volume: Volume, writable: bool) -> Self {
        Self { volume, position: 0, writable, fat_range: None, fat_cache: None }
    }

    fn len(&self) -> u64 { self.volume.sectors.saturating_mul(512) }

    /// Locate the FAT table region(s) from the BPB, once. `num_fats` copies
    /// sit back to back right after the reserved sectors — this covers all
    /// of them, so a write that lands in the mirror stays coherent too.
    fn fat_range(&mut self) -> Option<(u64, u64)> {
        if self.fat_range.is_none() {
            let mut boot = [0; 512];
            let computed = if self.volume.read(0, &mut boot) != 1 { None } else {
                (|| {
                    if u16::from_le_bytes([boot[11], boot[12]]) != 512 { return None; }
                    let reserved = u16::from_le_bytes([boot[14], boot[15]]) as u64;
                    let num_fats = boot[16] as u64;
                    let fat16 = u16::from_le_bytes([boot[22], boot[23]]) as u64;
                    let fat32 = u32::from_le_bytes(boot[36..40].try_into().unwrap()) as u64;
                    let fat_size = if fat16 != 0 { fat16 } else { fat32 };
                    if num_fats == 0 || fat_size == 0 { return None; }
                    let start = reserved.checked_mul(512)?;
                    let len = num_fats.checked_mul(fat_size)?.checked_mul(512)?;
                    (len != 0 && len <= FAT_CACHE_CAP && start.checked_add(len)? <= self.len())
                        .then_some((start, len))
                })()
            };
            self.fat_range = Some(computed);
        }
        self.fat_range.unwrap()
    }

    /// Whether `[pos, pos+count)` lies entirely inside the cached FAT region,
    /// loading that region on first touch.
    fn fat_hit(&mut self, pos: u64, count: usize) -> Option<(usize, usize)> {
        let (start, len) = self.fat_range()?;
        if pos < start || pos + count as u64 > start + len { return None; }
        if self.fat_cache.is_none() {
            let mut buf = alloc::vec![0u8; len as usize];
            if self.volume.read(start / 512, &mut buf) as u64 != len / 512 { return None; }
            self.fat_cache = Some(buf);
        }
        Some(((pos - start) as usize, count))
    }
}

impl fatfs::IoBase for VolumeIo { type Error = (); }

impl fatfs::Read for VolumeIo {
    fn read(&mut self, out: &mut [u8]) -> Result<usize, ()> {
        let count = self.len().saturating_sub(self.position).min(out.len() as u64) as usize;
        if count == 0 { return Ok(0); }
        if let Some((off, n)) = self.fat_hit(self.position, count) {
            out[..n].copy_from_slice(&self.fat_cache.as_ref().unwrap()[off..off + n]);
            self.position += n as u64;
            return Ok(n);
        }
        let within = (self.position % 512) as usize;
        let n = if within == 0 && count >= 512 {
            let n = count / 512 * 512;
            if self.volume.read(self.position / 512, &mut out[..n]) as usize != n / 512 {
                return Err(());
            }
            n
        } else {
            let mut sector = [0; 512];
            if self.volume.read(self.position / 512, &mut sector) != 1 { return Err(()); }
            let n = count.min(512 - within);
            out[..n].copy_from_slice(&sector[within..within + n]);
            n
        };
        self.position += n as u64;
        Ok(n)
    }
}

impl fatfs::Write for VolumeIo {
    fn write(&mut self, data: &[u8]) -> Result<usize, ()> {
        if data.is_empty() { return Ok(0); }
        if !self.writable || self.position.checked_add(data.len() as u64).is_none_or(|end| end > self.len()) {
            return Err(());
        }
        let within = (self.position % 512) as usize;
        let n = if within == 0 && data.len() >= 512 {
            let n = data.len() / 512 * 512;
            if self.volume.write(self.position / 512, &data[..n]) as usize != n / 512 {
                return Err(());
            }
            n
        } else {
            let mut sector = [0; 512];
            if self.volume.read(self.position / 512, &mut sector) != 1 { return Err(()); }
            let n = data.len().min(512 - within);
            sector[within..within + n].copy_from_slice(&data[..n]);
            if self.volume.write(self.position / 512, &sector) != 1 { return Err(()); }
            n
        };
        // Keep the resident copy coherent — it's served straight to fatfs on
        // the next read, bypassing the shared disk cache entirely. A write
        // straddling the region's edge (never seen from fatfs in practice —
        // FAT-table and file-data writes are separate calls — but not ruled
        // out by anything here) drops the cache instead of going stale.
        if let Some((start, len)) = self.fat_range()
            && self.fat_cache.is_some()
        {
            let end = self.position + n as u64;
            if self.position >= start && end <= start + len {
                let off = (self.position - start) as usize;
                self.fat_cache.as_mut().unwrap()[off..off + n].copy_from_slice(&data[..n]);
            } else if self.position < start + len && end > start {
                self.fat_cache = None;
            }
        }
        self.position += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), ()> {
        if self.writable { self.volume.flush().map_err(|_| ())?; }
        Ok(())
    }
}

impl fatfs::Seek for VolumeIo {
    fn seek(&mut self, from: fatfs::SeekFrom) -> Result<u64, ()> {
        self.position = match from {
            fatfs::SeekFrom::Start(n) => Some(n),
            fatfs::SeekFrom::Current(n) => self.position.checked_add_signed(n),
            fatfs::SeekFrom::End(n) => self.len().checked_add_signed(n),
        }.ok_or(())?;
        Ok(self.position)
    }
}

/// Probe by parsing the filesystem, never by trusting an MBR type or GUID.
/// Probe I/O is read-only, including the library's unmount-on-drop path.
pub fn is_fat(volume: &Volume) -> bool {
    let mut boot = [0; 512];
    if volume.read(0, &mut boot) != 1 { return false; }
    let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]) as u64;
    let total16 = u16::from_le_bytes([boot[19], boot[20]]);
    let sectors = if total16 != 0 { total16 as u64 } else {
        u32::from_le_bytes(boot[32..36].try_into().unwrap()) as u64
    };
    if sectors == 0 || sectors * bytes_per_sector > volume.sectors.saturating_mul(512) {
        return false;
    }
    FatFs::new(VolumeIo::new(*volume, false)).is_ok()
}

/// `fatfs::File::seek` cannot resume from wherever it last was — a fresh
/// `open_file` + `seek(offset)` always walks the FAT chain link by link from
/// the FIRST cluster up to `offset`'s cluster (see fatfs's own `File::seek`:
/// the only fast paths are "same offset" and "same cluster as before").
/// Re-opening by path and reseeking on every DOS read call therefore costs
/// O(path depth + offset / cluster_size) EVERY TIME, even though the block
/// cache makes each individual sector fetch cheap — a game issuing many
/// small sequential reads against one growing offset pays for the whole
/// cluster chain again and again, quadratically. Keeping the `File` object
/// alive across calls lets fatfs's existing fast paths do their job: seeking
/// to the position a previous read already left it at is then a no-op.
type CachedFile<T> = fatfs::File<'static, T, fatfs::DefaultTimeProvider, fatfs::LossyOemCpConverter>;

/// `File` borrows `&FileSystem`, which contains `RefCell`s for its own
/// internal caching — so `File` is `!Send` on its own (a `&T` is `Send` only
/// if `T: Sync`, and `RefCell` isn't). That's the right default for a bare
/// `File`, but this one only ever moves or gets touched from behind
/// `FatState`'s own `Mutex`, which already serializes every access to both
/// `media` and this handle — so no two threads can ever reach the same
/// `File` (or the `FileSystem` it borrows) concurrently. Asserting `Send`
/// here just tells the compiler what the `Mutex` already guarantees.
struct SendFile<T: fatfs::ReadWriteSeek + 'static>(CachedFile<T>);
unsafe impl<T: fatfs::ReadWriteSeek + 'static> Send for SendFile<T> {}

struct FatState<T: fatfs::ReadWriteSeek + 'static> {
    media: Option<fatfs::FileSystem<T>>,
    opens: BTreeMap<u32, Vec<u8>>,
    // SAFETY (the 'static above): every `FatFs<T>` this backs is Box::leak'd
    // at mount time (see fs/disk.rs, startup.rs) and never moved for the life
    // of the kernel. The `media` field these files borrow from remains stable
    // until shutdown clears every cached handle before taking it. Access
    // is still funneled through `self.state`'s Mutex like everything else.
    handles: BTreeMap<u32, SendFile<T>>,
    next_handle: u32,
}

impl<T: fatfs::ReadWriteSeek + 'static> FatState<T> {
    fn media(&self) -> &fatfs::FileSystem<T> {
        self.media.as_ref().expect("FAT filesystem is unmounted")
    }
}

pub struct FatFs<T: fatfs::ReadWriteSeek + 'static> {
    state: Mutex<FatState<T>>,
    writable: bool,
}

impl<T: fatfs::ReadWriteSeek + 'static> FatFs<T> {
    pub fn new(io: T) -> Result<Self, fatfs::Error<T::Error>> {
        Self::new_with_policy(io, true)
    }

    pub fn new_with_policy(io: T, writable: bool) -> Result<Self, fatfs::Error<T::Error>> {
        let media = fatfs::FileSystem::new(io, fatfs::FsOptions::new())?;
        Ok(Self { state: Mutex::new(FatState {
            media: Some(media), opens: BTreeMap::new(), handles: BTreeMap::new(), next_handle: 1,
        }), writable })
    }

    pub fn geometry(&self) -> Option<(u16, u16, u16, u16)> {
        let state = self.state.lock();
        let stats = state.media().stats().ok()?;
        Some((
            u16::try_from((state.media().cluster_size() / 512).max(1)).unwrap_or(1),
            512,
            u16::try_from(stats.total_clusters()).unwrap_or(u16::MAX),
            u16::try_from(stats.free_clusters()).unwrap_or(u16::MAX),
        ))
    }
}

/// DOS datetime (as rust-fatfs reports it) → seconds since the Unix epoch.
fn unix_from_datetime(dt: &fatfs::DateTime) -> u32 {
    unix_from_ymd_hms(
        dt.date.year,
        dt.date.month,
        dt.date.day,
        dt.time.hour,
        dt.time.min,
        dt.time.sec,
    )
}

/// Days-from-civil-date, branchless. fatfs decodes stored timestamp fields
/// without validation, so FAT's zeroed "no timestamp" encoding arrives here
/// as month 0 / day 0 and must fall out as 0 via the validity guard.
pub(super) fn unix_from_ymd_hms(year: u16, month: u16, day: u16, hour: u16, min: u16, sec: u16) -> u32 {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::cell::{Cell, RefCell};
    use crate::kernel::block::Disk;
    use fatfs::{Read, Seek, SeekFrom, Write};

    pub struct MemoryDisk {
        data: RefCell<Vec<u8>>,
        writes: Cell<usize>,
        flushes: Cell<usize>,
    }

    impl Disk for MemoryDisk {
        fn read(&self, lba: u64, out: &mut [u8]) -> u32 {
            let offset = lba as usize * 512;
            let data = self.data.borrow();
            let Some(input) = data.get(offset..offset + out.len()) else { return 0 };
            out.copy_from_slice(input);
            out.len().div_ceil(512) as u32
        }
        fn write(&self, lba: u64, input: &[u8]) -> u32 {
            let offset = lba as usize * 512;
            let mut data = self.data.borrow_mut();
            let Some(out) = data.get_mut(offset..offset + input.len()) else { return 0 };
            out.copy_from_slice(input);
            self.writes.set(self.writes.get() + 1);
            input.len().div_ceil(512) as u32
        }
        fn flush(&self) -> Result<(), crate::kernel::block::FlushError> {
            self.flushes.set(self.flushes.get() + 1);
            Ok(())
        }
        fn sectors(&self) -> u64 { self.data.borrow().len() as u64 / 512 }
        fn name(&self) -> &str { "fat-test" }
    }

    fn disk(sectors: usize) -> &'static MemoryDisk {
        Box::leak(Box::new(MemoryDisk {
            data: RefCell::new(alloc::vec![0; sectors * 512]),
            writes: Cell::new(0), flushes: Cell::new(0),
        }))
    }

    pub fn formatted(kind: fatfs::FatType, sectors: usize) -> (&'static MemoryDisk, Volume) {
        let disk = disk(sectors);
        let volume = Volume::whole(disk);
        fatfs::format_volume(&mut VolumeIo::new(volume, true), fatfs::FormatVolumeOptions::new().fat_type(kind)).unwrap();
        (disk, volume)
    }

    #[test]
    fn volume_cursor_preserves_neighbors_bounds_and_flush() {
        let disk = disk(6);
        disk.data.borrow_mut().fill(0xa5);
        let volume = crate::kernel::block::cache::volume(Volume::new(disk, 2, 2));
        let mut io = VolumeIo::new(volume, true);
        io.seek(SeekFrom::Start(509)).unwrap();
        io.write_all(b"across boundary").unwrap();
        io.flush().unwrap();
        assert_eq!(disk.flushes.get(), 1);
        io.seek(SeekFrom::Start(509)).unwrap();
        let mut out = [0; 15];
        io.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"across boundary");
        let data = disk.data.borrow();
        assert!(data[..2 * 512 + 509].iter().all(|&byte| byte == 0xa5));
        assert!(data[2 * 512 + 524..].iter().all(|&byte| byte == 0xa5));
        drop(data);
        io.seek(SeekFrom::End(-1)).unwrap();
        assert!(io.write(b"xx").is_err());
        io.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(io.read(&mut out).unwrap(), 0);
        assert!(io.seek(SeekFrom::Start(0)).is_ok());
        assert!(io.seek(SeekFrom::Current(-1)).is_err());
        let mut readonly = VolumeIo::new(volume, false);
        assert!(readonly.write(b"x").is_err());
    }

    #[test]
    fn fat_table_stays_resident_and_coherent_across_writes() {
        let (_, volume) = formatted(fatfs::FatType::Fat16, 32768);
        let cached = crate::kernel::block::cache::volume(volume);
        let mut io = VolumeIo::new(cached, true);
        let (start, len) = io.fat_range().expect("FAT16 table fits the resident cap");
        assert!(len > 0);

        io.seek(SeekFrom::Start(start)).unwrap();
        let mut first = [0; 4];
        io.read_exact(&mut first).unwrap();
        assert!(io.fat_cache.is_some(), "first touch loads the resident copy");

        io.seek(SeekFrom::Start(start + 4)).unwrap();
        io.write_all(b"\xAA\xBB\xCC\xDD").unwrap();
        // The resident copy is updated in place, not dropped and reloaded.
        assert_eq!(&io.fat_cache.as_ref().unwrap()[4..8], b"\xAA\xBB\xCC\xDD");

        io.seek(SeekFrom::Start(start + 4)).unwrap();
        let mut readback = [0; 4];
        io.read_exact(&mut readback).unwrap();
        assert_eq!(&readback, b"\xAA\xBB\xCC\xDD");

        // A second, independent VolumeIo over the same volume sees the write
        // too — it's not a private, disk-diverging copy.
        let mut other = VolumeIo::new(cached, false);
        other.seek(SeekFrom::Start(start + 4)).unwrap();
        let mut from_disk = [0; 4];
        other.read_exact(&mut from_disk).unwrap();
        assert_eq!(&from_disk, b"\xAA\xBB\xCC\xDD");
    }

    #[test]
    fn fat12_fat16_fat32_read_write_and_remount() {
        for (kind, sectors) in [(fatfs::FatType::Fat12, 2880), (fatfs::FatType::Fat16, 32768), (fatfs::FatType::Fat32, 131072)] {
            let (disk, volume) = formatted(kind, sectors);
            let before = disk.writes.get();
            assert!(is_fat(&volume));
            assert_eq!(disk.writes.get(), before, "probing must never write");
            assert!(!is_fat(&Volume::new(disk, 0, 1)), "reject truncated media");
            let fs = FatFs::new(VolumeIo::new(volume, true)).unwrap();
            let root_file = fs.create(b"ROOT.TXT").expect("create in FAT root");
            assert_eq!(fs.write(root_file.handle, 0, b"root contents"), 13);
            assert_eq!(fs.clunk(root_file.handle), 0);
            assert!(fs.dos_attributes(b"ROOT.TXT").is_some());
            assert!(fs.set_mtime(b"ROOT.TXT", 1_700_000_000));
            assert_eq!(fs.mtime(b"ROOT.TXT"), Some(1_700_000_000));
            assert_eq!(fs.mkdir(b"Directory"), 0);
            let node = fs.create(b"Directory/My long document.txt").unwrap();
            let data: Vec<u8> = (0..9000).map(|n| n as u8).collect();
            assert_eq!(fs.write(node.handle, 0, &data), 9000);
            assert_eq!(fs.clunk(node.handle), 0);
            let mut entries = Vec::new();
            fs.readdir(b"Directory", 0, &mut entries, 8);
            assert_eq!(entries.len(), 1);
            let entry = &entries[0];
            assert_eq!(&entry.name[..entry.name_len], b"My long document.txt");
            assert!(entry.short_name.is_some());
            assert!(fs.rename(b"Directory/My long document.txt", b"Directory/renamed.txt") == 0);
            assert_eq!(fs.unmount(), 0);
            drop(fs);
            let fs = FatFs::new(VolumeIo::new(volume, true)).unwrap();
            let root_file = fs.open(b"ROOT.TXT").unwrap();
            let mut root_data = [0; 13];
            assert_eq!(fs.read(root_file.handle, 0, &mut root_data, root_file.size), 13);
            assert_eq!(&root_data, b"root contents");
            fs.clunk(root_file.handle);
            let node = fs.open(b"Directory/renamed.txt").unwrap();
            let mut out = alloc::vec![0; data.len()];
            assert_eq!(fs.read(node.handle, 0, &mut out, node.size), 9000);
            assert_eq!(out, data);
            fs.clunk(node.handle);
            let truncated = fs.create(b"Directory/renamed.txt").unwrap();
            assert_eq!(truncated.size, 0);
            fs.clunk(truncated.handle);
            assert_eq!(fs.remove(b"Directory/renamed.txt"), 0);
            assert_eq!(fs.rmdir(b"Directory"), 0);
        }
        assert!(!is_fat(&Volume::whole(disk(4))));
    }

    #[test]
    fn fat_root_scores_above_an_efi_partition_without_writing_during_selection() {
        use crate::kernel::fs::disk::FilesystemVolume;
        let (disk, volume) = formatted(fatfs::FatType::Fat12, 2880);
        let detected = FilesystemVolume::probe(volume).unwrap();
        let mut boot = crate::BootConfig::empty();
        boot.set_c_root(b"home/retroos/");
        assert_eq!(detected.root_score(&boot), 0);
        let fs = detected.open(true).unwrap();
        assert_eq!(fs.mkdir(b"home"), 0);
        assert_eq!(fs.mkdir(b"home/retroos"), 0);
        drop(fs);
        let before = disk.writes.get();
        assert_eq!(detected.root_score(&boot), 2);
        boot.set_c_root(b"HOME/RETROOS/");
        assert_eq!(detected.root_score(&boot), 0);
        assert_eq!(disk.writes.get(), before);
    }
}

impl<T: fatfs::ReadWriteSeek + 'static> Filesystem for FatFs<T> {
    fn format_name(&self) -> &'static str { "FAT" }

    fn unmount(&self) -> i32 {
        if !self.writable { return 0; }
        let mut state = self.state.lock();
        state.handles.clear();
        state.opens.clear();
        let Some(media) = state.media.take() else { return 0 };
        let unmounted = media.unmount().is_ok();
        if unmounted { 0 } else { -5 }
    }

    fn dos_attributes(&self, path: &[u8]) -> Option<u8> {
        let state = self.state.lock();
        let text = path_str(path)?;
        let (parent, name) = text.rsplit_once('/').unwrap_or(("", text));
        let dir = if parent.is_empty() { state.media().root_dir() }
                  else { state.media().root_dir().open_dir(parent).ok()? };
        for entry in dir.iter() {
            let entry = entry.ok()?;
            if entry.file_name() == name { return Some(entry.attributes().bits()); }
        }
        None
    }
    fn mtime(&self, path: &[u8]) -> Option<u32> {
        let state = self.state.lock();
        let text = path_str(path)?;
        let (parent, name) = text.rsplit_once('/').unwrap_or(("", text));
        let dir = if parent.is_empty() { state.media().root_dir() }
                  else { state.media().root_dir().open_dir(parent).ok()? };
        for entry in dir.iter() {
            let entry = entry.ok()?;
            if entry.file_name() == name { return Some(unix_from_datetime(&entry.modified())); }
        }
        None
    }

    fn set_mtime(&self, path: &[u8], unix: u32) -> bool {
        // Gregorian civil date from Unix days, independent of DOS lookup policy.
        let z = i64::from(unix / 86400) + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = mp + if mp < 10 { 3 } else { -9 };
        let year = era * 400 + yoe + i64::from(month <= 2);
        if !(1980..=2107).contains(&year) { return false; }
        let state = self.state.lock();
        let Some(path) = path_str(path) else { return false };
        let Ok(mut file) = state.media().root_dir().open_file(path) else { return false };
        file.set_modified(fatfs::DateTime::new(
            fatfs::Date::new(year as u16, month as u16, day as u16),
            fatfs::Time::new((unix % 86400 / 3600) as u16, (unix % 3600 / 60) as u16, (unix % 60) as u16, 0),
        ));
        fatfs::Write::flush(&mut file).is_ok()
    }

    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let mut state = self.state.lock();
        let mut file = state.media().root_dir().open_file(path_str(path)?).ok()?;
        let size = fatfs::Seek::seek(&mut file, fatfs::SeekFrom::End(0)).ok()?;
        let size = u32::try_from(size).ok()?;
        fatfs::Seek::seek(&mut file, fatfs::SeekFrom::Start(0)).ok()?;
        // SAFETY: see the `handles` field comment on `FatState` — `media`
        // outlives every handle this file borrows from. Shutdown drops all
        // cached handles before taking the media for unmount. Transmuting
        // here also ends `file`'s borrow of `state.media` for the compiler.
        let file: CachedFile<T> = unsafe {
            core::mem::transmute::<
                fatfs::File<'_, T, fatfs::DefaultTimeProvider, fatfs::LossyOemCpConverter>,
                CachedFile<T>,
            >(file)
        };
        let handle = state.next_handle;
        state.next_handle = state.next_handle.checked_add(1).unwrap_or(1);
        state.opens.insert(handle, path.to_vec());
        state.handles.insert(handle, SendFile(file));
        Some(Vnode {
            handle: handle as u64,
            size,
            mode: 0o644,
        })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        let inner = u32::try_from(handle).unwrap_or(0);
        let mut state = self.state.lock();
        // The cached, still-open File carries fatfs's own cluster-position
        // fast path (see the `handles` field comment): reseeking to wherever
        // the previous read already left it is then free. A cold miss here
        // (handle created before this cache existed, or already evicted)
        // falls back to the always-correct, always-slower open-by-path path.
        if let Some(file) = state.handles.get_mut(&inner) {
            if fatfs::Seek::seek(&mut file.0, fatfs::SeekFrom::Start(offset as u64)).is_err() {
                return -5;
            }
            let mut done = 0;
            while done < buf.len() {
                match fatfs::Read::read(&mut state.handles.get_mut(&inner).unwrap().0, &mut buf[done..]) {
                    Ok(0) => break,
                    Ok(n) => done += n,
                    Err(_) => return if done == 0 { -5 } else { done as i32 },
                }
            }
            return done as i32;
        }
        let Some(path) = state.opens.get(&inner) else {
            return -9;
        };
        let media = state.media();
        let Some(path) = path_str(path) else {
            return -5;
        };
        let Ok(mut file) = media.root_dir().open_file(path) else {
            return -5;
        };
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
        let media = state.media();
        let root = media.root_dir();
        let listing = if dir.is_empty() {
            root
        } else {
            root.open_dir(path_str(dir)?).ok()?
        };
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
            let name = entry.file_name();
            let name_len = name.len();
            let mut de = DirEntry {
                name: alloc::vec![0; name_len],
                name_len,
                short_name: ShortName::new(short),
                size: entry.len().min(u32::MAX as u64) as u32,
                is_dir: entry.is_dir(),
                is_symlink: false,
                mode: if entry.is_dir() { 0o777 } else if entry.attributes().contains(fatfs::FileAttributes::READ_ONLY) { 0o444 } else { 0o666 },
                dos_attributes: Some(entry.attributes().bits()),
                mtime: unix_from_datetime(&entry.modified()),
                node: 0,
                mount_idx: 0,
            };
            de.name[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
            out.push(de);
            visible += 1;
        }
        None
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        let state = self.state.lock();
        let media = state.media();
        if path.is_empty() {
            return true;
        }
        path_str(path).is_some_and(|p| media.root_dir().open_dir(p).is_ok())
    }

    fn clunk(&self, handle: u64) -> i32 {
        let inner = u32::try_from(handle).unwrap_or(0);
        let mut state = self.state.lock();
        state.opens.remove(&inner);
        state.handles.remove(&inner);
        0
    }

    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        let inner = u32::try_from(handle).unwrap_or(0);
        let mut state = self.state.lock();
        // This writes through its own fresh File, independent of any cached
        // read handle in `state.handles` — drop that cache entry so the next
        // read reopens and sees the write, instead of the stale size/cluster
        // position the cached File captured at its own last use.
        state.handles.remove(&inner);
        let Some(path) = state.opens.get(&inner) else {
            return -9;
        };
        let media = state.media();
        let Some(path) = path_str(path) else {
            return -5;
        };
        let Ok(mut file) = media.root_dir().open_file(path) else {
            return -5;
        };
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
        let media = state.media();
        let path_text = path_str(path)?;
        let (parent, name) = path_text.rsplit_once('/').unwrap_or(("", path_text));
        let dir = if parent.is_empty() { media.root_dir() }
                  else { media.root_dir().open_dir(parent).ok()? };
        // VFS has already resolved exact names. FAT cannot store colliding
        // case variants or short aliases, but a collision must not silently
        // turn a request for a new name into truncating another file.
        if dir.open_file(name).is_ok()
            && !dir.iter().any(|entry| entry.is_ok_and(|entry| entry.file_name() == name))
        {
            return None;
        }
        let mut file = dir.create_file(name).ok()?;
        file.truncate().ok()?; // DOS AH=3Ch create-or-truncate semantics
        drop(file);
        drop(dir);
        let handle = state.next_handle;
        state.next_handle = state.next_handle.checked_add(1).unwrap_or(1);
        state.opens.insert(handle, path.to_vec());
        Some(Vnode {
            handle: handle as u64,
            size: 0,
            mode: 0o644,
        })
    }

    fn supports_create(&self) -> bool {
        true
    }

    fn remove(&self, path: &[u8]) -> i32 {
        let state = self.state.lock();
        let media = state.media();
        let Some(path) = path_str(path) else {
            return -5;
        };
        if media.root_dir().remove(path).is_ok() {
            0
        } else {
            -2
        }
    }

    fn mkdir(&self, path: &[u8]) -> i32 {
        let state = self.state.lock();
        let media = state.media();
        let Some(path) = path_str(path) else {
            return -5;
        };
        // The library's create_dir succeeds for an existing case variant.
        // Such a storage collision is EEXIST, not a newly created VFS name.
        if media.root_dir().open_dir(path).is_ok() { return -17; }
        if media.root_dir().create_dir(path).is_ok() {
            0
        } else {
            -13
        }
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
        let media = state.media();
        let (Some(src), Some(dst)) = (path_str(path), path_str(new_path)) else {
            return -5;
        };
        let root = media.root_dir();
        if root.rename(src, &root, dst).is_ok() {
            0
        } else {
            -2
        }
    }

    fn supports_directory_mutation(&self) -> bool {
        true
    }
}
