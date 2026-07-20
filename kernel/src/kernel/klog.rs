//! In-memory kernel log ring.
//!
//! Every byte handed to the platform debug sink (`println!` + `dbg_println!`,
//! see `lib::vga::stream`) is also appended here, split into lines. On real
//! metal the sink writes port 0xE9, which is unconnected on actual hardware;
//! hosted writes to stderr/a log file. This buffer keeps the most recent
//! `MAX_LINES` lines so a booted system with no serial/debug port can surface
//! kernel + dbg_println output after the fact: COMMAND.COM's `LOG` builtin
//! reads it back line-by-line via INT 31h AH=07h and prints it.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};

const MAX_LINES: usize = 2000;
const KLOG_HANDLE: u64 = 1;
const KLOG_NAMES: [&[u8]; 2] = [b"klog", b"klog.txt"];
const MAX_LINE_LEN: usize = 512;

struct KLog {
    lines: VecDeque<Vec<u8>>,
    cur: Vec<u8>,
}

static mut LOG: Option<KLog> = None;
/// Frozen line count for the in-progress `LOG` dump (set when a read starts at
/// index 0). While a dump runs, `push_byte` is paused — otherwise the dump's
/// own console output (the DOS write mirror feeds this same sink) would append
/// new lines, grow the count without bound, and shift indices past the cap.
static mut DUMP_LEN: usize = 0;
static mut DUMPING: bool = false;

pub struct KLogFs;

pub static KLOG_FS: KLogFs = KLogFs;

/// Allocate the buffer. Call once after the heap is up, before `set_debug_sink`.
pub fn init() {
    unsafe {
        LOG = Some(KLog {
            lines: VecDeque::with_capacity(MAX_LINES + 1),
            cur: Vec::with_capacity(128),
        });
    }
}

/// Append one console byte. Called from the platform debug sink for every
/// logged byte; a no-op until `init()` has run, and paused during a `LOG` dump
/// (see `DUMPING`). A completed line (`\n`) is pushed and the oldest dropped
/// past `MAX_LINES`; `\r` is ignored.
pub fn push_byte(b: u8) {
    unsafe {
        if DUMPING {
            return;
        }
        let log = match (*core::ptr::addr_of_mut!(LOG)).as_mut() {
            Some(l) => l,
            None => return,
        };
        if b == b'\n' {
            let line = core::mem::replace(&mut log.cur, Vec::with_capacity(128));
            log.lines.push_back(line);
            while log.lines.len() > MAX_LINES {
                log.lines.pop_front();
            }
        } else if b != b'\r' && log.cur.len() < MAX_LINE_LEN {
            log.cur.push(b);
        }
    }
}

/// Copy line `idx` (0 = oldest retained) into `out`, returning its byte length.
/// `None` once `idx` reaches the snapshot taken at `idx == 0` — the caller's
/// stop signal. A read at `idx == 0` snapshots the current length and pauses
/// appends (so the dump sees a stable, non-shifting view despite its own output
/// echoing back into this sink); the end-of-dump read re-enables appends.
pub fn line(idx: usize, out: &mut [u8]) -> Option<usize> {
    unsafe {
        let log = (*core::ptr::addr_of!(LOG)).as_ref()?;
        if idx == 0 {
            DUMP_LEN = log.lines.len();
            DUMPING = true;
        }
        if idx >= DUMP_LEN {
            DUMPING = false;
            return None;
        }
        let bytes = log.lines.get(idx)?.as_slice();
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
        Some(n)
    }
}

fn log_byte_len(log: &KLog) -> u32 {
    let mut len = 0usize;
    for line in &log.lines {
        len = len.saturating_add(line.len().saturating_add(1));
    }
    if !log.cur.is_empty() {
        len = len.saturating_add(log.cur.len());
    }
    len.min(u32::MAX as usize) as u32
}

fn byte_len() -> u32 {
    unsafe {
        let log = match (*core::ptr::addr_of!(LOG)).as_ref() {
            Some(l) => l,
            None => return 0,
        };
        log_byte_len(log)
    }
}

fn copy_piece(piece: &[u8], file_pos: &mut u32, offset: u32, out: &mut [u8], written: &mut usize) {
    if out.len() == *written {
        return;
    }
    let piece_len = piece.len().min(u32::MAX as usize) as u32;
    let piece_start = *file_pos;
    let piece_end = piece_start.saturating_add(piece_len);
    if offset < piece_end {
        let piece_off = offset.saturating_sub(piece_start) as usize;
        let n = piece[piece_off..].len().min(out.len() - *written);
        out[*written..*written + n].copy_from_slice(&piece[piece_off..piece_off + n]);
        *written += n;
    }
    *file_pos = piece_end;
}

fn read_bytes(offset: u32, out: &mut [u8]) -> i32 {
    unsafe {
        let log = match (*core::ptr::addr_of!(LOG)).as_ref() {
            Some(l) => l,
            None => return 0,
        };
        let mut file_pos = 0u32;
        let mut written = 0usize;
        for line in &log.lines {
            copy_piece(line.as_slice(), &mut file_pos, offset, out, &mut written);
            copy_piece(b"\n", &mut file_pos, offset, out, &mut written);
            if written == out.len() {
                return written as i32;
            }
        }
        if !log.cur.is_empty() {
            copy_piece(log.cur.as_slice(), &mut file_pos, offset, out, &mut written);
        }
        written as i32
    }
}

fn is_klog_path(path: &[u8]) -> bool {
    KLOG_NAMES.contains(&path)
}

impl Filesystem for KLogFs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        if is_klog_path(path) {
            Some(Vnode {
                handle: KLOG_HANDLE,
                size: byte_len(),
                mode: 0o444,
            })
        } else {
            None
        }
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32 {
        if handle != KLOG_HANDLE {
            return -2;
        }
        if offset >= size {
            return 0;
        }
        let n = buf.len().min((size - offset) as usize);
        read_bytes(offset, &mut buf[..n])
    }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        if !dir.is_empty() {
            return None;
        }
        // A fixed handful of synthetic names, so the cookie is just the index.
        for (i, name) in KLOG_NAMES.iter().enumerate().skip(cookie as usize) {
            if out.len() >= max {
                return Some(i as u64);
            }
            let len = name.len().min(100);
            let mut de = DirEntry {
                name: [0; 100],
                name_len: len,
                size: byte_len(),
                is_dir: false,
                mode: 0o444,
                mtime: 0,
            };
            de.name[..len].copy_from_slice(&name[..len]);
            out.push(de);
        }
        None
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        path.is_empty()
    }

    fn write(&self, _handle: u64, _offset: u32, _data: &[u8]) -> i32 {
        -1
    }
}
