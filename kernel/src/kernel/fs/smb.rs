//! Common SMB filesystem. Remote permissions are enforced by the server.
use crate::kernel::{
    net, portio,
    vfs::{self, DirEntry, Filesystem, Stat, Vnode},
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    vec,
    vec::Vec,
};
use smb2_core::{
    Error, Result,
    auth::ntlm::NtlmCredentials,
    client::{Client, Transport},
    msg::create::{CreateDisposition, CreateResponse},
    types::FileId,
};

const READ: u32 = 0x0012_0089;
const WRITE: u32 = 0x0012_019f;
const DELETE: u32 = 0x0011_0080;
const DIRECTORY: u32 = 1;
const NOT_DIRECTORY: u32 = 0x40;
const DEADLINE_NS: u64 = 3_000_000_000;

struct Socket {
    handle: i32,
    deadline: u64,
}
impl Drop for Socket {
    fn drop(&mut self) {
        if self.handle >= 0 {
            net::close(self.handle);
            self.handle = -1;
        }
    }
}
impl Socket {
    fn connect(endpoint: net::Endpoint) -> Result<Self> {
        let handle = net::socket(net::SocketKind::Tcp, !net::native_backend())
            .map_err(|_| Error::Transport)?;
        let mut socket = Self {
            handle,
            deadline: portio::now_ns().saturating_add(DEADLINE_NS),
        };
        loop {
            match net::connect(handle, endpoint) {
                Ok(_) => return Ok(socket),
                Err(net::Error::WouldBlock) => socket.progress()?,
                Err(_) => return Err(Error::Transport),
            }
        }
    }
    fn progress(&mut self) -> Result<()> {
        if portio::now_ns() >= self.deadline {
            return Err(Error::Timeout);
        }
        net::poll();
        core::hint::spin_loop();
        Ok(())
    }
}
impl Transport for Socket {
    fn begin_request(&mut self) {
        self.deadline = portio::now_ns().saturating_add(DEADLINE_NS);
    }
    fn disconnect(&mut self) {
        if self.handle >= 0 {
            net::close(self.handle);
            self.handle = -1;
        }
    }
    fn send_all(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            if portio::now_ns() >= self.deadline {
                return Err(Error::Timeout);
            }
            match net::sendto(self.handle, bytes, None) {
                Ok(n) if n > 0 => bytes = &bytes[n as usize..],
                Err(net::Error::WouldBlock) => self.progress()?,
                _ => return Err(Error::Transport),
            }
        }
        Ok(())
    }
    fn receive_exact(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        while !bytes.is_empty() {
            if portio::now_ns() >= self.deadline {
                return Err(Error::Timeout);
            }
            match net::recvfrom(self.handle, bytes, false, &mut None) {
                Ok(n) if n > 0 => bytes = &mut bytes[n as usize..],
                Err(net::Error::WouldBlock) => self.progress()?,
                _ => return Err(Error::Transport),
            }
        }
        Ok(())
    }
}

fn random(bytes: &mut [u8]) -> Result<()> {
    crate::kernel::random::fill(bytes).map_err(|_| Error::Unavailable)
}
fn filetime() -> u64 {
    (u64::from(crate::kernel::clock::rtc_unix_timestamp().unwrap_or(0)) + 11_644_473_600)
        * 10_000_000
}
fn errno(error: Error) -> i32 {
    match error {
        Error::Timeout => -110,
        Error::Authentication | Error::Signature => -13,
        Error::Unavailable => -95,
        Error::Status(s) => match s {
            0xc000000f | 0xc0000034 | 0xc000003a => -2,
            0xc0000022 | 0xc000006d | 0xc000006a => -13,
            0xc0000035 => -17,
            0xc0000043 => -16,
            0xc0000101 => -39,
            0xc0000103 => -20,
            0xc00000ba => -21,
            0xc000007f => -28,
            _ => -5,
        },
        _ => -5,
    }
}
fn path(bytes: &[u8]) -> Option<&str> {
    let path = core::str::from_utf8(bytes).ok()?;
    if bytes.len() > 1024
        || bytes.contains(&0)
        || bytes.contains(&b'\\')
        || path.split('/').any(|p| p == ".." || p == ".")
    {
        return None;
    }
    Some(path.trim_end_matches('/'))
}
fn stat(info: &CreateResponse) -> Stat {
    Stat {
        size: info.end_of_file.min(u64::from(u32::MAX)) as u32,
        mode: 0o777,
        is_dir: info.file_attributes & 16 != 0,
        is_symlink: false,
        ino: 0,
    }
}
struct Open {
    file: FileId,
    path: Vec<u8>,
    writable: bool,
}
struct Directory {
    file: FileId,
    path: Vec<u8>,
    pending: VecDeque<smb2_core::msg::directory_info::DirectoryInfoEntry>,
    first: bool,
}
struct State {
    client: Client<Socket>,
    handles: BTreeMap<u64, Open>,
    directories: BTreeMap<u64, Directory>,
    next: u64,
}
pub struct SmbFs(spin::Mutex<State>);
impl State {
    fn insert(&mut self, info: CreateResponse, path: &[u8], writable: bool) -> Option<Vnode> {
        if self.handles.len() >= 128 {
            let _ = self.client.close(info.file_id);
            return None;
        }
        let id = self.next;
        self.next = self.next.checked_add(1)?;
        let size = info.end_of_file.min(u64::from(u32::MAX)) as u32;
        self.handles.insert(
            id,
            Open {
                file: info.file_id,
                path: path.to_vec(),
                writable,
            },
        );
        Some(Vnode {
            handle: id,
            size,
            mode: 0o666,
        })
    }
    fn lookup(&mut self, path: &str) -> Result<CreateResponse> {
        self.client.open(path, READ, CreateDisposition::FileOpen, 0)
    }
    fn mutate(&mut self, path: &str, directory: bool, rename: Option<&str>) -> Result<()> {
        let info = self.client.open(
            path,
            DELETE,
            CreateDisposition::FileOpen,
            if directory { DIRECTORY } else { 0 },
        )?;
        let result = if let Some(name) = rename {
            let name: Vec<u8> = name
                .replace('/', "\\")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let mut data = vec![0; 20];
            data[0] = 1;
            data[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
            data.extend_from_slice(&name);
            self.client.set_info(info.file_id, 10, data)
        } else {
            self.client.set_info(info.file_id, 13, vec![1])
        };
        let close = self.client.close(info.file_id);
        result.and(close)
    }
}
impl Filesystem for SmbFs {
    fn format_name(&self) -> &'static str {
        "smb2"
    }
    fn open(&self, raw: &[u8]) -> Option<Vnode> {
        let p = path(raw)?;
        let mut s = self.0.lock();
        let info = s
            .client
            .open(p, READ, CreateDisposition::FileOpen, NOT_DIRECTORY)
            .ok()?;
        s.insert(info, raw, false)
    }
    fn stat(&self, raw: &[u8], _: bool) -> Option<Stat> {
        let p = path(raw)?;
        let mut s = self.0.lock();
        let info = s.lookup(p).ok()?;
        let result = stat(&info);
        let _ = s.client.close(info.file_id);
        Some(result)
    }
    fn dir_exists(&self, raw: &[u8]) -> bool {
        self.stat(raw, true).is_some_and(|s| s.is_dir)
    }
    fn create(&self, raw: &[u8]) -> Option<Vnode> {
        let p = path(raw)?;
        let mut s = self.0.lock();
        let info = s
            .client
            .open(p, WRITE, CreateDisposition::FileOverwriteIf, NOT_DIRECTORY)
            .ok()?;
        s.insert(info, raw, true)
    }
    fn supports_create(&self) -> bool {
        true
    }
    fn supports_mkdir(&self) -> bool {
        true
    }
    fn supports_directory_mutation(&self) -> bool {
        true
    }
    fn read(&self, id: u64, offset: u32, out: &mut [u8], size: u32) -> i32 {
        let mut s = self.0.lock();
        let Some(file) = s.handles.get(&id).map(|h| h.file) else {
            return -9;
        };
        match s
            .client
            .read(file, u64::from(offset), out.len().min(size as usize))
        {
            Ok(data) => {
                out[..data.len()].copy_from_slice(&data);
                data.len() as i32
            }
            Err(e) => errno(e),
        }
    }
    fn write(&self, id: u64, offset: u32, bytes: &[u8]) -> i32 {
        let mut s = self.0.lock();
        let Some(handle) = s.handles.get(&id) else {
            return -9;
        };
        // VFS open is mode-independent. Upgrade a read handle lazily, leaving
        // read-only shares readable and letting the server enforce writes.
        if !handle.writable {
            let p = handle.path.clone();
            let old = handle.file;
            let Some(p) = path(&p) else { return -22 };
            let info = match s
                .client
                .open(p, WRITE, CreateDisposition::FileOpen, NOT_DIRECTORY)
            {
                Ok(i) => i,
                Err(e) => return errno(e),
            };
            let _ = s.client.close(old);
            let handle = s.handles.get_mut(&id).unwrap();
            handle.file = info.file_id;
            handle.writable = true;
        }
        let file = s.handles.get(&id).unwrap().file;
        if bytes.is_empty() {
            return 0;
        }
        s.client
            .write(file, u64::from(offset), bytes)
            .map_or_else(errno, |n| n as i32)
    }
    fn resize(&self, id: u64, size: u32) -> i32 {
        // Upgrade through the same path used by writes.
        if let e @ ..=-1 = self.write(id, 0, &[]) {
            return e;
        }
        let mut s = self.0.lock();
        let Some(file) = s.handles.get(&id).map(|h| h.file) else {
            return -9;
        };
        s.client
            .set_info(file, 20, u64::from(size).to_le_bytes().to_vec())
            .map_or_else(errno, |_| 0)
    }
    fn clunk(&self, id: u64) -> i32 {
        let mut s = self.0.lock();
        let Some(handle) = s.handles.remove(&id) else {
            return -9;
        };
        let result = if handle.writable {
            s.client.flush(handle.file)
        } else {
            Ok(())
        };
        let close = s.client.close(handle.file);
        result.and(close).map_or_else(errno, |_| 0)
    }
    fn readdir(&self, raw: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        if max == 0 {
            return None;
        }
        let p = path(raw)?;
        let mut s = self.0.lock();
        let id = if cookie == vfs::READDIR_START {
            if s.directories.len() >= 32 {
                let id = *s.directories.keys().next()?;
                let old = s.directories.remove(&id)?;
                let _ = s.client.close(old.file);
            }
            let info = s
                .client
                .open(p, READ, CreateDisposition::FileOpen, DIRECTORY)
                .ok()?;
            let id = s.next;
            s.next = s.next.checked_add(1)?;
            s.directories.insert(
                id,
                Directory {
                    file: info.file_id,
                    path: raw.to_vec(),
                    pending: VecDeque::new(),
                    first: true,
                },
            );
            id
        } else {
            cookie
        };
        let mut dir = s.directories.remove(&id)?;
        if dir.path != raw {
            let _ = s.client.close(dir.file);
            return None;
        }
        let target = out.len().saturating_add(max);
        loop {
            if dir.pending.is_empty() {
                let entries = match s.client.directory(dir.file, dir.first) {
                    Ok(e) => e,
                    Err(_) => {
                        let _ = s.client.close(dir.file);
                        return None;
                    }
                };
                dir.first = false;
                if entries.is_empty() {
                    let _ = s.client.close(dir.file);
                    return None;
                }
                dir.pending.extend(entries);
            }
            while out.len() < target {
                let Some(e) = dir.pending.pop_front() else {
                    break;
                };
                if e.file_name == "." || e.file_name == ".." {
                    continue;
                }
                let name = e.file_name.into_bytes();
                let name_len = name.len();
                out.push(DirEntry {
                    name,
                    name_len,
                    short_name: None,
                    size: e.end_of_file.min(u64::from(u32::MAX)) as u32,
                    is_dir: e.file_attributes & 16 != 0,
                    is_symlink: false,
                    mode: 0o777,
                    dos_attributes: Some(e.file_attributes as u8),
                    mount_idx: 0,
                    mtime: e
                        .last_write_time
                        .0
                        .saturating_sub(116_444_736_000_000_000)
                        .checked_div(10_000_000)
                        .unwrap_or(0)
                        .min(u64::from(u32::MAX)) as u32,
                    node: 0,
                });
            }
            if out.len() == target {
                let next = s.next;
                s.next = s.next.checked_add(1)?;
                s.directories.insert(next, dir);
                return Some(next);
            }
        }
    }
    fn mkdir(&self, raw: &[u8]) -> i32 {
        let Some(p) = path(raw) else { return -22 };
        let mut s = self.0.lock();
        match s
            .client
            .open(p, WRITE, CreateDisposition::FileCreate, DIRECTORY)
        {
            Ok(info) => s.client.close(info.file_id).map_or_else(errno, |_| 0),
            Err(e) => errno(e),
        }
    }
    fn remove(&self, raw: &[u8]) -> i32 {
        let Some(p) = path(raw) else { return -22 };
        self.0
            .lock()
            .mutate(p, false, None)
            .map_or_else(errno, |_| 0)
    }
    fn rmdir(&self, raw: &[u8]) -> i32 {
        let Some(p) = path(raw) else { return -22 };
        self.0
            .lock()
            .mutate(p, true, None)
            .map_or_else(errno, |_| 0)
    }
    fn rename(&self, raw: &[u8], new: &[u8]) -> i32 {
        let (Some(p), Some(n)) = (path(raw), path(new)) else {
            return -22;
        };
        self.0
            .lock()
            .mutate(p, false, Some(n))
            .map_or_else(errno, |_| 0)
    }
    fn unmount(&self) -> i32 {
        let flushed = self.sync();
        let mut s = self.0.lock();
        let handles = core::mem::take(&mut s.handles);
        for (_, h) in handles {
            let _ = s.client.close(h.file);
        }
        let directories = core::mem::take(&mut s.directories);
        for (_, d) in directories {
            let _ = s.client.close(d.file);
        }
        let result = s.client.disconnect().map_or_else(errno, |_| 0);
        if flushed < 0 { flushed } else { result }
    }
    fn sync(&self) -> i32 {
        let mut s = self.0.lock();
        let files: Vec<_> = s
            .handles
            .values()
            .filter(|h| h.writable)
            .map(|h| h.file)
            .collect();
        for file in files {
            if let Err(e) = s.client.flush(file) {
                return errno(e);
            }
        }
        0
    }
}

/// Reserve failed mount points so a failed network mount cannot expose a
/// writable directory from the filesystem underneath it.
struct Offline;
static OFFLINE: Offline = Offline;
impl Filesystem for Offline {
    fn format_name(&self) -> &'static str {
        "smb2-offline"
    }
    fn open(&self, _: &[u8]) -> Option<Vnode> {
        None
    }
    fn read(&self, _: u64, _: u32, _: &mut [u8], _: u32) -> i32 {
        -107
    }
    fn write(&self, _: u64, _: u32, _: &[u8]) -> i32 {
        -107
    }
    fn dir_exists(&self, p: &[u8]) -> bool {
        p.is_empty()
    }
    fn readdir(&self, _: &[u8], _: u64, _: &mut Vec<DirEntry>, _: usize) -> Option<u64> {
        None
    }
}

pub fn mount_configured() {
    let root = crate::kernel::dos::c_root();
    let path = [root, b"RETROOS/RETROOS.INI"].concat();
    let Ok(bytes) = crate::kernel::exec::load_file_resolved(&path) else {
        return;
    };
    let Ok(config) = crate::kernel::mount_config::Config::parse_user(&bytes) else {
        return;
    };
    for (index, mount) in config.smb.into_iter().enumerate() {
        let prefix: &'static [u8] = Box::leak(if mount.path == "/" {
            Vec::new().into_boxed_slice()
        } else {
            alloc::format!("{}/", mount.path.trim_matches('/')).into_bytes().into_boxed_slice()
        });
        if let Some(drive) = mount.drive {
            if crate::kernel::dos::extra_drive_prefix(drive).is_some()
                || drive == b'H' && vfs::is_mounted(b"host/")
            {
                crate::compact_println!("SMB: mount {} failed (drive already in use)", mount.path.as_str());
                continue;
            }
            crate::kernel::dos::configure_drive(drive, prefix);
        }
        vfs::mount(prefix, &OFFLINE);
        let result = (|| {
            let mut entropy = [0; 4];
            random(&mut entropy)?;
            let endpoint = net::Endpoint {
                address: mount.server,
                port: mount.port,
            };
            let socket = Socket::connect(endpoint)?;
            let server = alloc::format!(
                "{}.{}.{}.{}",
                mount.server[0],
                mount.server[1],
                mount.server[2],
                mount.server[3]
            );
            let client = Client::connect(
                socket,
                &server,
                &mount.share,
                NtlmCredentials {
                    username: mount.username,
                    password: mount.password,
                    domain: mount.domain,
                },
                random,
                filetime,
            )?;
            Ok(SelfMount { client })
        })();
        match result {
            Ok(session) => {
                let fs = Box::leak(Box::new(SmbFs(spin::Mutex::new(State {
                    client: session.client,
                    handles: BTreeMap::new(),
                    directories: BTreeMap::new(),
                    next: 1,
                }))));
                let subdir = mount.subdir.trim_matches('/').as_bytes();
                if !subdir.is_empty() && !fs.dir_exists(subdir) {
                    lib::compact_panic!("SMB: configured subdirectory unavailable");
                }
                let private: &'static [u8] = Box::leak(alloc::format!("smbfs/{}/", index).into_bytes().into_boxed_slice());
                if mount.access == crate::kernel::mount_config::Access::Ro {
                    vfs::mount_readonly(private, fs);
                } else { vfs::mount(private, fs); }
                vfs::hide_mount(private);
                let mut source = private.to_vec();
                if !subdir.is_empty() { source.extend_from_slice(subdir); source.push(b'/'); }
                if prefix.is_empty() {
                    // The network root owns /bin, replacing the bootstrap
                    // bundle's shell and command aliases.
                    vfs::bind(b"bin/", Box::leak([source.as_slice(), b"bin/"].concat().into_boxed_slice()));
                }
                if prefix == root {
                    // Mount credentials live only in the boot copy. Once C:
                    // is online its normal user settings must stay persistent.
                    let ini = [source.as_slice(), b"RETROOS/RETROOS.INI"].concat();
                    vfs::bind(Box::leak([prefix, b"RETROOS/RETROOS.INI"].concat().into_boxed_slice()), Box::leak(ini.into_boxed_slice()));
                    if fs.dir_exists(&[subdir, if subdir.is_empty() { b"RETROOS/FIRMWARE" } else { b"/RETROOS/FIRMWARE" }].concat()) {
                        vfs::bind(Box::leak([prefix, b"RETROOS/FIRMWARE/"].concat().into_boxed_slice()), Box::leak([source.as_slice(), b"RETROOS/FIRMWARE/"].concat().into_boxed_slice()));
                    }
                }
                vfs::bind(prefix, Box::leak(source.into_boxed_slice()));
                crate::compact_println!(
                    "SMB: mounted {} (authenticated, signed SMB2)",
                    mount.path.as_str()
                );
            }
            Err(e) => {
                crate::compact_println!("SMB: mount {} failed ({})", mount.path.as_str(), errno(e));
                if prefix.is_empty() || prefix == root {
                    lib::compact_panic!("SMB: required root or C: filesystem unavailable");
                }
            }
        }
    }
}
struct SelfMount {
    client: Client<Socket>,
}
