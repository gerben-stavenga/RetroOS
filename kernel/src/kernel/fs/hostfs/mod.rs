//! Host filesystem backends.
//!
//! The serial HostFS client and the hosted native backend implement the same
//! VFS `Filesystem` interface. Serial hardware lives in the reusable
//! `drivers::uart16550` module; HostFS framing lives in `frame`; session and
//! request policy lives in `client`.

mod client;
mod frame;
mod injected;

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};
use alloc::vec::Vec;
use client::{close, ensure_ready, request, RequestWriter, ResponseReader, CMD_CREATE, CMD_MKDIR,
    CMD_OPEN, CMD_READ, CMD_READDIR, CMD_STAT, CMD_WRITE, HOSTFS_IO_ERROR, MAX_READ_CHUNK,
    MAX_WRITE_CHUNK};
use frame::MAX_BODY;

pub use client::{configure, init, uart_present};
pub use injected::{host_backend_installed, install_host_backend, HostBackendHooks, InjectedHostFs,
    INJECTED_HOSTFS};

/// Whether HostFS currently has an established backend/session.
pub fn is_ready() -> bool {
    host_backend_installed() || client::is_ready()
}

pub struct HostFs;

impl HostFs {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for HostFs {
    fn default() -> Self {
        Self::new()
    }
}

impl Filesystem for HostFs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        if !ensure_ready() || path.len() > u16::MAX as usize { return None; }
        let mut payload = RequestWriter::new();
        if !payload.push_path(path) { return None; }
        let mut response = [0u8; MAX_BODY];
        let n = request(CMD_OPEN, payload.as_slice(), &mut response)?;
        let mut response = ResponseReader::new(&response[..n], 12)?;
        let status = response.read_i32()?;
        let handle = response.read_u32()?;
        let size = response.read_u32()?;
        debug_assert_eq!(response.remaining(), 0);
        if status < 0 { return None; }
        Some(Vnode { handle: handle as u64, size, mode: 0o644 })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        if !ensure_ready() { return HOSTFS_IO_ERROR; }
        let mut total = 0usize;
        while total < buf.len() {
            let want = (buf.len() - total).min(MAX_READ_CHUNK);
            let mut payload = RequestWriter::new();
            if !payload.push_u32(handle as u32)
                || !payload.push_u32(offset.saturating_add(total as u32))
                || !payload.push_u32(want as u32)
            {
                return HOSTFS_IO_ERROR;
            }
            let mut response = [0u8; MAX_BODY];
            let Some(n) = request(CMD_READ, payload.as_slice(), &mut response) else {
                return HOSTFS_IO_ERROR;
            };
            if n < 8 { return HOSTFS_IO_ERROR; }
            let status = i32::from_le_bytes(response[..4].try_into().unwrap());
            let data_len = u32::from_le_bytes(response[4..8].try_into().unwrap()) as usize;
            if status < 0 { return status; }
            if data_len > want || n != 8 + data_len { return HOSTFS_IO_ERROR; }
            buf[total..total + data_len].copy_from_slice(&response[8..8 + data_len]);
            total += data_len;
            if data_len < want { break; }
        }
        total as i32
    }

    /// The wire protocol is still one request per entry (`CMD_READDIR` takes a
    /// u32 index), so the cookie here is simply that index. Batching is done
    /// on this side: the VFS gets whole chunks, even though each one costs a
    /// round trip. Widening the protocol to a real batch reply would cut the
    /// round trips, but hostfs is the hosted backend and not the hot path.
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        if !ensure_ready() { return None; }
        let mut index = cookie;
        while out.len() < max {
            if !ensure_ready() || dir.len() > u16::MAX as usize { return None; }
            let mut payload = RequestWriter::new();
            if !payload.push_path(dir) || !payload.push_u32(index as u32) { return None; }
            let mut response = [0u8; MAX_BODY];
            let response_len = request(CMD_READDIR, payload.as_slice(), &mut response)?;
            if response_len < 5 { return None; }
            let status = i32::from_le_bytes(response[..4].try_into().unwrap());
            if status < 0 { return None; }
            let name_len = response[4] as usize;
            if response_len != 5 + name_len + 9 || name_len > 100 { return None; }
            let mut name = [0u8; 100];
            let n = name_len;
            name[..n].copy_from_slice(&response[5..5 + n]);
            let tail = 5 + n;
            let size = u32::from_le_bytes(response[tail..tail + 4].try_into().unwrap());
            let is_dir = response[tail + 4] != 0;
            let mtime = u32::from_le_bytes(response[tail + 5..tail + 9].try_into().unwrap());

            out.push(DirEntry {
                name,
                name_len: n,
                size,
                is_dir,
                is_symlink: false,
                mode: if is_dir { 0o755 } else { 0o644 },
                mtime,
                node: 0,
                mount_idx: 0,
            });
            index += 1;
        }
        Some(index)
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        if !ensure_ready() || path.len() > u16::MAX as usize { return false; }
        let mut payload = RequestWriter::new();
        if !payload.push_path(path) { return false; }
        let mut response = [0u8; MAX_BODY];
        let Some(n) = request(CMD_STAT, payload.as_slice(), &mut response) else { return false; };
        let mut response = match ResponseReader::new(&response[..n], 9) { Some(value) => value, None => return false };
        let status = match response.read_i32() { Some(value) => value, None => return false };
        if response.read_u32().is_none() { return false; }
        let is_dir = match response.read_u8() { Some(value) => value, None => return false };
        status == 0 && is_dir != 0
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        if !ensure_ready() || path.len() > u16::MAX as usize { return None; }
        let mut payload = RequestWriter::new();
        if !payload.push_path(path) { return None; }
        let mut response = [0u8; MAX_BODY];
        let n = request(CMD_CREATE, payload.as_slice(), &mut response)?;
        let mut response = ResponseReader::new(&response[..n], 8)?;
        let status = response.read_i32()?;
        let handle = response.read_u32()?;
        debug_assert_eq!(response.remaining(), 0);
        if status < 0 { return None; }
        Some(Vnode { handle: handle as u64, size: 0, mode: 0o644 })
    }

    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        if !ensure_ready() { return HOSTFS_IO_ERROR; }
        let mut total = 0usize;
        while total < data.len() {
            let count = (data.len() - total).min(MAX_WRITE_CHUNK);
            let mut payload = RequestWriter::new();
            if !payload.push_u32(handle as u32)
                || !payload.push_u32(offset.saturating_add(total as u32))
                || !payload.push_u32(count as u32)
                || !payload.push_bytes(&data[total..total + count])
            {
                return HOSTFS_IO_ERROR;
            }
            let mut response = [0u8; MAX_BODY];
            let Some(n) = request(CMD_WRITE, payload.as_slice(), &mut response) else {
                return HOSTFS_IO_ERROR;
            };
            let Some(mut response) = ResponseReader::new(&response[..n], 8) else {
                return HOSTFS_IO_ERROR;
            };
            let Some(status) = response.read_i32() else { return HOSTFS_IO_ERROR; };
            let Some(written) = response.read_u32().map(|value| value as usize) else {
                return HOSTFS_IO_ERROR;
            };
            if status < 0 { return status; }
            if written != count { return HOSTFS_IO_ERROR; }
            total += written;
        }
        total as i32
    }

    /// Tclunk: tell the host to free the server-side fid. Fire-and-forget (the
    /// server sends no reply). The VFS currently shares fids through its path
    /// cache, so there is no safe per-close clunk point yet.
    fn clunk(&self, handle: u64) {
        if !ensure_ready() { return; }
        let _ = close(handle);
    }

    fn mkdir(&self, path: &[u8]) -> i32 {
        if !ensure_ready() || path.len() > u16::MAX as usize { return HOSTFS_IO_ERROR; }
        let mut payload = Vec::with_capacity(2 + path.len());
        payload.extend_from_slice(&(path.len() as u16).to_le_bytes());
        payload.extend_from_slice(path);
        let mut response = [0u8; MAX_BODY];
        let Some(n) = request(CMD_MKDIR, &payload, &mut response) else {
            return HOSTFS_IO_ERROR;
        };
        if n != 4 { return HOSTFS_IO_ERROR; }
        i32::from_le_bytes(response[..4].try_into().unwrap())
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    /// HostFS is a writable backend even when its peer is temporarily down.
    /// Keep failed creates as I/O errors rather than letting VFS substitute
    /// its RAM overlay and report a false success to DOS.
    fn supports_create(&self) -> bool {
        true
    }
}
