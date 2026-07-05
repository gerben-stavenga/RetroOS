//! Native host filesystem server for the interpreter — the in-process side of
//! the kernel's `hostfs` serial protocol, backed by `std::fs`. This replaces the
//! `hostfs.py` server (and the QEMU serial bridge): the UART feeds command bytes
//! here, and the response bytes go straight back, so `/host` mounts a real host
//! directory with no external process.
//!
//! Wire format mirrors `kernel/src/kernel/hostfs.rs` (the client). All integers
//! are little-endian. The client always sends a complete command, then reads the
//! reply, so each command is executed synchronously when its last byte arrives.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const CMD_OPEN: u8 = 0x01;
const CMD_READ: u8 = 0x02;
const CMD_CLOSE: u8 = 0x03;
const CMD_STAT: u8 = 0x04;
const CMD_READDIR: u8 = 0x05;
const CMD_CREATE: u8 = 0x06;
const CMD_WRITE: u8 = 0x07;

pub struct HostFs {
    root: PathBuf,
    handles: HashMap<u32, PathBuf>,
    next_handle: u32,
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn le16(b: &[u8]) -> usize {
    u16::from_le_bytes([b[0], b[1]]) as usize
}

impl HostFs {
    pub fn new(root: &str) -> HostFs {
        HostFs { root: PathBuf::from(root), handles: HashMap::new(), next_handle: 1 }
    }

    /// Resolve a guest VFS subpath (POSIX, no mount prefix) under the host root.
    fn resolve(&self, path: &[u8]) -> PathBuf {
        let s = String::from_utf8_lossy(path);
        self.root.join(s.trim_start_matches('/'))
    }

    fn assign(&mut self, p: PathBuf) -> u32 {
        let h = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(h, p);
        h
    }

    /// Try to parse and execute one command from the front of `buf`. Returns
    /// `(bytes_consumed, reply)` once a full command is present, else `None`.
    pub fn try_command(&mut self, buf: &[u8]) -> Option<(usize, Vec<u8>)> {
        let cmd = *buf.first()?;
        match cmd {
            CMD_OPEN | CMD_STAT | CMD_CREATE => {
                if buf.len() < 3 {
                    return None;
                }
                let plen = le16(&buf[1..3]);
                if buf.len() < 3 + plen {
                    return None;
                }
                let path = &buf[3..3 + plen];
                let reply = match cmd {
                    CMD_OPEN => self.open(path),
                    CMD_STAT => self.stat(path),
                    _ => self.create(path),
                };
                Some((3 + plen, reply))
            }
            CMD_READDIR => {
                if buf.len() < 3 {
                    return None;
                }
                let plen = le16(&buf[1..3]);
                if buf.len() < 3 + plen + 4 {
                    return None;
                }
                let dir = &buf[3..3 + plen];
                let index = le32(&buf[3 + plen..3 + plen + 4]);
                Some((3 + plen + 4, self.readdir(dir, index)))
            }
            CMD_READ => {
                if buf.len() < 13 {
                    return None;
                }
                Some((13, self.read(le32(&buf[1..5]), le32(&buf[5..9]), le32(&buf[9..13]))))
            }
            CMD_WRITE => {
                if buf.len() < 13 {
                    return None;
                }
                let dlen = le32(&buf[9..13]) as usize;
                if buf.len() < 13 + dlen {
                    return None;
                }
                Some((13 + dlen, self.write(le32(&buf[1..5]), le32(&buf[5..9]), &buf[13..13 + dlen])))
            }
            CMD_CLOSE => Some((5.min(buf.len()).max(1), Vec::new())), // client never sends; no reply
            _ => Some((1, Vec::new())),                              // unknown: skip one byte
        }
    }

    // ── Commands (reply layout matches the kernel client's reads) ──────────

    fn open(&mut self, path: &[u8]) -> Vec<u8> {
        let p = self.resolve(path);
        let mut r = Reply::new();
        match fs::metadata(&p) {
            Ok(m) if m.is_file() => {
                let h = self.assign(p);
                r.i32(0).u32(h).u32(m.len().min(u32::MAX as u64) as u32);
            }
            _ => { r.i32(-1).u32(0).u32(0); }
        }
        r.0
    }

    fn create(&mut self, path: &[u8]) -> Vec<u8> {
        let p = self.resolve(path);
        let mut r = Reply::new();
        match fs::File::create(&p) {
            Ok(_) => { let h = self.assign(p); r.i32(0).u32(h); }
            Err(_) => { r.i32(-1).u32(0); }
        }
        r.0
    }

    fn read(&mut self, handle: u32, offset: u32, len: u32) -> Vec<u8> {
        let mut r = Reply::new();
        let data = self.handles.get(&handle).and_then(|p| {
            let mut f = fs::File::open(p).ok()?;
            f.seek(SeekFrom::Start(offset as u64)).ok()?;
            let mut buf = vec![0u8; len as usize];
            let n = f.read(&mut buf).ok()?;
            buf.truncate(n);
            Some(buf)
        });
        match data {
            Some(d) => { r.i32(0).u32(d.len() as u32).bytes(&d); }
            None => { r.i32(-5).u32(0); }
        }
        r.0
    }

    fn write(&mut self, handle: u32, offset: u32, data: &[u8]) -> Vec<u8> {
        let mut r = Reply::new();
        let ok = self.handles.get(&handle).and_then(|p| {
            let mut f = fs::OpenOptions::new().write(true).open(p).ok()?;
            f.seek(SeekFrom::Start(offset as u64)).ok()?;
            f.write_all(data).ok()?;
            Some(())
        });
        match ok {
            Some(()) => { r.i32(0).u32(data.len() as u32); }
            None => { r.i32(-5).u32(0); }
        }
        r.0
    }

    fn stat(&mut self, path: &[u8]) -> Vec<u8> {
        let p = self.resolve(path);
        let mut r = Reply::new();
        match fs::metadata(&p) {
            Ok(m) => { r.i32(0).u32(m.len().min(u32::MAX as u64) as u32).u8(m.is_dir() as u8); }
            Err(_) => { r.i32(-1).u32(0).u8(0); }
        }
        r.0
    }

    fn readdir(&mut self, dir: &[u8], index: u32) -> Vec<u8> {
        let p = self.resolve(dir);
        let mut r = Reply::new();
        match nth_entry(&p, index as usize) {
            Some((name, size, is_dir)) => {
                let n = name.len().min(100);
                r.i32(0).u8(n as u8).bytes(&name[..n]).u32(size).u8(is_dir as u8);
            }
            None => { r.i32(-1); } // end of directory (client reads only the status)
        }
        r.0
    }
}

/// Return the `index`-th directory entry as `(name_bytes, size, is_dir)`.
fn nth_entry(dir: &Path, index: usize) -> Option<(Vec<u8>, u32, bool)> {
    let entry = fs::read_dir(dir).ok()?.flatten().nth(index)?;
    // Follow symlinks: a symlink-to-dir must report as a directory so DOS/DN can
    // enter it (`/home/retroos` is full of them — GAMES entries, BORLANDC, TC…).
    // `DirEntry::metadata` does NOT traverse links; `fs::metadata` does. Fall
    // back to the link's own metadata for a dangling target so a broken symlink
    // still shows (as a file) instead of truncating the whole listing.
    let meta = fs::metadata(entry.path()).or_else(|_| entry.metadata()).ok()?;
    let name = entry.file_name().into_encoded_bytes();
    Some((name, meta.len().min(u32::MAX as u64) as u32, meta.is_dir()))
}

/// Little-endian reply builder.
struct Reply(Vec<u8>);
impl Reply {
    fn new() -> Reply { Reply(Vec::new()) }
    fn i32(&mut self, v: i32) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
    fn u32(&mut self, v: u32) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
    fn u8(&mut self, v: u8) -> &mut Self { self.0.push(v); self }
    fn bytes(&mut self, b: &[u8]) -> &mut Self { self.0.extend_from_slice(b); self }
}
