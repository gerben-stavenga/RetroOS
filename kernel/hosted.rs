//! Hosted platform services: the media thread and host-directory VFS.
use kernel::kernel::vfs::{ContentVersion, DirEntry, Filesystem, FsStats, Meta, Stat, Vnode};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt}};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

/// Start the process-lifetime media worker after platform setup, before startup
/// registers its services. Linux maintains the shared process mappings.
pub fn start_media_worker() {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        std::thread::Builder::new().name("retroos-media".into()).spawn(|| {
            // This is the sole consumer; Linux needs no mapping refresh.
            kernel::kernel::media::worker(|| {})
        }).expect("start media worker");
        while !kernel::kernel::media::enabled() {
            std::thread::yield_now();
        }
    });
}

pub struct HostFs {
    root: PathBuf,
    files: Mutex<(u64, BTreeMap<u64, HostFile>)>,
}

struct HostFile { file: File, identity: u64 }

fn identity(meta: &fs::Metadata) -> u64 { (meta.dev().rotate_left(32) ^ meta.ino()).max(1) }
fn owner(meta: &fs::Metadata) -> Meta { Meta { uid: meta.uid(), gid: meta.gid(), mode: meta.mode() } }

fn errno(error: io::Error) -> i32 { -error.raw_os_error().unwrap_or(5) }
fn status(result: io::Result<()>) -> i32 { result.map_or_else(errno, |_| 0) }
fn stat(meta: &fs::Metadata) -> Stat {
    Stat { mtime: u32::try_from(meta.mtime()).ok(), size: meta.len().min(u32::MAX as u64) as u32,
        mode: meta.mode() as u16, is_dir: meta.is_dir(), is_symlink: meta.is_symlink(), ino: identity(meta) }
}

impl HostFs {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() { return Err(io::Error::from_raw_os_error(20)); }
        Ok(Self { root, files: Mutex::new((0, BTreeMap::new())) })
    }

    // VFS owns guest symlink interpretation. Never let a host symlink select
    // an object outside this mount when opening a path on the host.
    fn path(&self, path: &[u8], follow: bool) -> io::Result<PathBuf> {
        let path = Path::new(OsStr::from_bytes(path));
        if path.components().any(|c| !matches!(c, Component::Normal(_) | Component::CurDir)) {
            return Err(io::Error::from_raw_os_error(13));
        }
        let relative: PathBuf = path.components().filter(|c| matches!(c, Component::Normal(_))).collect();
        let path = relative.as_path();
        let joined = self.root.join(path);
        let resolved = if follow { joined.canonicalize()? } else if path.as_os_str().is_empty() {
            self.root.clone()
        } else {
            joined.parent().unwrap().canonicalize()?.join(joined.file_name().unwrap())
        };
        if !resolved.starts_with(&self.root) { return Err(io::Error::from_raw_os_error(13)); }
        Ok(resolved)
    }

    fn keep(&self, file: File) -> io::Result<Vnode> {
        let meta = file.metadata()?;
        if !meta.is_file() { return Err(io::Error::from_raw_os_error(21)); }
        if meta.len() > u32::MAX as u64 { return Err(io::Error::from_raw_os_error(27)); }
        let mut files = self.files.lock().unwrap();
        files.0 += 1;
        let handle = files.0;
        files.1.insert(handle, HostFile { file, identity: identity(&meta) });
        Ok(Vnode { handle, size: meta.len() as u32, mode: meta.mode() as u16 })
    }

    fn with_file<T>(&self, handle: u64, f: impl FnOnce(&File) -> io::Result<T>) -> io::Result<T> {
        let files = self.files.lock().unwrap();
        f(&files.1.get(&handle).ok_or_else(|| io::Error::from_raw_os_error(9))?.file)
    }
}

impl Filesystem for HostFs {
    fn format_name(&self) -> &'static str { "host" }
    fn statfs(&self) -> Result<FsStats, i32> {
        use std::os::fd::AsRawFd;
        let dir = File::open(&self.root).map_err(errno)?;
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // fstatfs initializes the structure on success; the fd stays owned here.
        if unsafe { libc::fstatfs(dir.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err(errno(io::Error::last_os_error()));
        }
        let info = unsafe { info.assume_init() };
        Ok(FsStats { kind: info.f_type as u64, block_size: info.f_bsize as u64,
            blocks: info.f_blocks, free_blocks: info.f_bfree, available_blocks: info.f_bavail,
            files: info.f_files, free_files: info.f_ffree, name_max: info.f_namelen as u64,
            ..FsStats::default() })
    }
    fn dynamic_directory(&self, _: &[u8]) -> bool { true }
    fn content_version(&self, handle: u64) -> Result<Option<ContentVersion>, i32> {
        self.with_file(handle, |file| {
            let m = file.metadata()?;
            Ok(Some(ContentVersion { revision: [m.mtime() as u64, m.ctime() as u64,
                (m.mtime_nsec() as u64) << 32 | m.ctime_nsec() as u64],
                size: Some(m.len().min(u32::MAX as u64) as u32) }))
        }).map_err(errno)
    }
    fn file_identity(&self, handle: u64) -> Option<u64> {
        self.files.lock().unwrap().1.get(&handle).map(|f| f.identity)
    }
    fn stat_node(&self, node: u64) -> Option<(Stat, Meta)> {
        let files = self.files.lock().unwrap();
        let m = files.1.values().find(|f| f.identity == node)?.file.metadata().ok()?;
        Some((stat(&m), owner(&m)))
    }
    fn meta_node(&self, node: u64) -> Option<Meta> { self.stat_node(node).map(|(_, m)| m) }
    fn link_count_node(&self, node: u64) -> Option<u32> {
        let files = self.files.lock().unwrap();
        Some(files.1.values().find(|f| f.identity == node)?.file.metadata().ok()?.nlink() as u32)
    }
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let path = self.path(path, true).ok()?;
        let file = OpenOptions::new().read(true).write(true).open(&path)
            .or_else(|_| File::open(&path)).ok()?;
        self.keep(file).ok()
    }
    fn stat(&self, path: &[u8], follow: bool) -> Option<Stat> {
        let path = self.path(path, follow).ok()?;
        fs::symlink_metadata(path).ok().map(|m| stat(&m))
    }
    fn meta(&self, path: &[u8]) -> Option<Meta> {
        let m = fs::symlink_metadata(self.path(path, false).ok()?).ok()?;
        Some(owner(&m))
    }
    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        self.with_file(handle, |file| file.read_at(buf, offset as u64))
            .map_or_else(errno, |n| n as i32)
    }
    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        self.with_file(handle, |file| file.write_at(data, offset as u64))
            .map_or_else(errno, |n| n as i32)
    }
    fn clunk(&self, handle: u64) -> i32 {
        if self.files.lock().unwrap().1.remove(&handle).is_some() { 0 } else { -9 }
    }
    fn dir_exists(&self, path: &[u8]) -> bool { self.path(path, true).is_ok_and(|p| p.is_dir()) }
    fn readdir(&self, path: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        let mut entries: Vec<_> = fs::read_dir(self.path(path, true).ok()?).ok()?
            .collect::<io::Result<_>>().ok()?;
        entries.sort_by_key(|e| e.file_name());
        let start = usize::try_from(cookie).ok()?;
        let end = start.saturating_add(max).min(entries.len());
        for e in entries.get(start..end)? {
            let name = e.file_name().as_bytes().to_vec();
            let m = fs::symlink_metadata(e.path()).ok()?;
            out.push(DirEntry::new(name, stat(&m)));
        }
        (end < entries.len()).then_some(end as u64)
    }
    fn readlink(&self, path: &[u8], out: &mut [u8]) -> Option<usize> {
        let target = fs::read_link(self.path(path, false).ok()?).ok()?;
        let bytes = target.as_os_str().as_bytes();
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
        Some(n)
    }
    fn supports_create(&self) -> bool { true }
    fn create(&self, path: &[u8]) -> Option<Vnode> { self.create_mode(path, 0o666) }
    fn create_mode(&self, path: &[u8], mode: u32) -> Option<Vnode> {
        let path = self.path(path, false).ok()?;
        // Existing symlinks are resolved by VFS, not by host creation.
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_symlink()) { return None; }
        self.keep(OpenOptions::new().read(true).write(true).create(true).truncate(true)
            .mode(mode).open(path).ok()?).ok()
    }
    fn resize(&self, handle: u64, size: u32) -> i32 {
        status(self.with_file(handle, |f| f.set_len(size as u64)))
    }
    fn supports_mkdir(&self) -> bool { true }
    fn supports_directory_mutation(&self) -> bool { true }
    fn mkdir(&self, path: &[u8]) -> i32 { status(self.path(path, false).and_then(fs::create_dir)) }
    fn mkdir_mode(&self, path: &[u8], mode: u32) -> i32 {
        use std::os::unix::fs::DirBuilderExt;
        status(self.path(path, false).and_then(|p| fs::DirBuilder::new().mode(mode).create(p)))
    }
    fn rmdir(&self, path: &[u8]) -> i32 { status(self.path(path, false).and_then(fs::remove_dir)) }
    fn remove(&self, path: &[u8]) -> i32 { status(self.path(path, false).and_then(fs::remove_file)) }
    fn rename(&self, from: &[u8], to: &[u8]) -> i32 {
        status((|| fs::rename(self.path(from, false)?, self.path(to, false)?))())
    }
    fn symlink(&self, target: &[u8], path: &[u8]) -> i32 {
        status(self.path(path, false).and_then(|p| std::os::unix::fs::symlink(OsStr::from_bytes(target), p)))
    }
    fn hard_link(&self, from: &[u8], to: &[u8]) -> i32 {
        status((|| fs::hard_link(self.path(from, false)?, self.path(to, false)?))())
    }
    fn link_count(&self, path: &[u8]) -> u32 {
        self.path(path, false).and_then(fs::symlink_metadata).map_or(0, |m| m.nlink() as u32)
    }
    fn flush(&self, path: &[u8]) -> i32 {
        status(self.path(path, true).and_then(File::open).and_then(|f| f.sync_all()))
    }
    fn sync(&self) -> i32 {
        status(self.files.lock().unwrap().1.values().try_for_each(|f| f.file.sync_all()))
    }
    fn mtime(&self, path: &[u8]) -> Option<u32> { self.stat(path, true)?.mtime }
    fn set_mtime(&self, path: &[u8], mtime: u32) -> bool { self.set_times(path, None, Some(mtime)) == 0 }
    fn set_times(&self, path: &[u8], accessed: Option<u32>, modified: Option<u32>) -> i32 {
        let mut times = fs::FileTimes::new();
        let time = |n| std::time::UNIX_EPOCH + std::time::Duration::from_secs(n as u64);
        if let Some(n) = accessed { times = times.set_accessed(time(n)); }
        if let Some(n) = modified { times = times.set_modified(time(n)); }
        status(self.path(path, true).and_then(File::open).and_then(|f| f.set_times(times)))
    }
    fn set_meta(&self, path: &[u8], uid: u32, gid: u32, mode: u32) -> bool {
        self.path(path, true).and_then(|p| {
            std::os::unix::fs::chown(&p, Some(uid), Some(gid))?;
            fs::set_permissions(p, fs::Permissions::from_mode(mode))
        }).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_jobs_run_on_the_host_worker() {
        start_media_worker();
        start_media_worker();
        let caller = std::thread::current().id();
        // Sole producer; the job reads thread-local std state without allocation.
        let worker = kernel::kernel::media::graphics(|| {
            let thread = std::thread::current();
            (thread.id(), thread.name() == Some("retroos-media"))
        });
        assert_ne!(worker.0, caller);
        assert!(worker.1);
    }

    #[test]
    fn host_files_are_live_and_open_handles_survive_rename_and_unlink() {
        let root = std::env::temp_dir().join(format!("retroos-hostfs-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let host = HostFs::new(&root).unwrap();
        assert!(host.dir_exists(b"."));
        assert!(host.statfs().unwrap().blocks > 0);
        let node = host.create(b"file").unwrap();
        assert_eq!(host.write(node.handle, 0, b"guest bytes"), 11);
        assert_eq!(fs::read(root.join("file")).unwrap(), b"guest bytes");
        let before = host.content_version(node.handle).unwrap();
        fs::write(root.join("file"), b"host changed bytes").unwrap();
        assert_ne!(host.content_version(node.handle).unwrap(), before);
        let mut buf = [0; 32];
        assert_eq!(host.read(node.handle, 5, &mut buf[..7], 18), 7);
        assert_eq!(&buf[..7], b"changed");
        assert_eq!(host.resize(node.handle, 4), 0);
        assert_eq!(host.flush(b"file"), 0);
        assert_eq!(fs::read(root.join("file")).unwrap(), b"host");
        assert_eq!(host.rename(b"file", b"renamed"), 0);
        assert_eq!(host.hard_link(b"renamed", b"alias"), 0);
        assert_eq!(host.link_count(b"alias"), 2);
        assert_eq!(host.file_identity(host.open(b"alias").unwrap().handle), host.file_identity(node.handle));
        assert_eq!(host.remove(b"renamed"), 0);
        assert_eq!(host.remove(b"alias"), 0);
        assert_eq!(host.read(node.handle, 0, &mut buf, 32), 4);
        let id = host.file_identity(node.handle).unwrap();
        assert_eq!(host.stat_node(id).unwrap().0.size, 4);
        assert_eq!(host.link_count_node(id), Some(0));
        assert_eq!(host.clunk(node.handle), 0);
        assert_eq!(host.read(node.handle, 0, &mut buf, 32), -9);
        assert_eq!(host.mkdir(b"dir"), 0);
        assert_eq!(host.symlink(b"/dir", b"link"), 0);
        assert!(host.stat(b"link", false).unwrap().is_symlink);
        assert_eq!(host.readlink(b"link", &mut buf), Some(4));
        assert_eq!(&buf[..4], b"/dir");
        let mut entries = Vec::new();
        let cookie = host.readdir(b"", 0, &mut entries, 1).unwrap();
        assert_eq!(host.readdir(b"", cookie, &mut entries, 1), None);
        assert_eq!(entries.iter().map(|e| e.name.as_slice()).collect::<Vec<_>>(), [b"dir".as_slice(), b"link"]);
        fs::write(root.join("new"), b"new").unwrap();
        entries.clear();
        host.readdir(b"", 0, &mut entries, 10);
        assert_eq!(entries.len(), 3);
        assert!(host.open(b"../outside").is_none());
        assert!(host.create(b"../outside").is_none());
        assert_eq!(host.symlink(b"/etc/passwd", b"outside"), 0);
        assert!(host.open(b"outside").is_none());
        assert!(host.create(b"outside").is_none());
        assert_eq!(host.rmdir(b"dir"), 0);
        fs::remove_dir_all(root).unwrap();
    }
}
