//! In-memory kernel log ring.
//!
//! Every byte handed to the platform debug sink (`println!` + `dbg_println!`,
//! see `lib::vga::stream`) is also appended here, split into lines. On real
//! metal the sink writes port 0xE9, which is unconnected on actual hardware —
//! so the log would otherwise be lost. This buffer keeps the most recent
//! `MAX_LINES` lines so a booted system with no serial/debug port can surface
//! kernel + dbg_println output after the fact: COMMAND.COM's `LOG` builtin
//! reads it back line-by-line via INT 31h AH=07h and prints it.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::string::String;

const MAX_LINES: usize = 2000;
// Only the metal debug sink appends to the ring (`push_byte`); the hosted
// backend logs straight to stdout, so the appender and its state are metal-only.
#[cfg(target_arch = "x86")]
const MAX_LINE_LEN: usize = 512;

struct KLog {
    lines: VecDeque<String>,
    #[cfg(target_arch = "x86")]
    cur: String,
}

static mut LOG: Option<KLog> = None;
/// Frozen line count for the in-progress `LOG` dump (set when a read starts at
/// index 0). While a dump runs, `push_byte` is paused — otherwise the dump's
/// own console output (the DOS write mirror feeds this same sink) would append
/// new lines, grow the count without bound, and shift indices past the cap.
static mut DUMP_LEN: usize = 0;
static mut DUMPING: bool = false;

/// Allocate the buffer. Call once after the heap is up, before `set_debug_sink`.
pub fn init() {
    unsafe {
        LOG = Some(KLog {
            lines: VecDeque::with_capacity(MAX_LINES + 1),
            #[cfg(target_arch = "x86")]
            cur: String::with_capacity(128),
        });
    }
}

/// Append one console byte. Called from the platform debug sink for every
/// logged byte; a no-op until `init()` has run, and paused during a `LOG` dump
/// (see `DUMPING`). A completed line (`\n`) is pushed and the oldest dropped
/// past `MAX_LINES`; `\r` is ignored.
#[cfg(target_arch = "x86")]
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
            let line = core::mem::replace(&mut log.cur, String::with_capacity(128));
            log.lines.push_back(line);
            while log.lines.len() > MAX_LINES {
                log.lines.pop_front();
            }
        } else if b != b'\r' && log.cur.len() < MAX_LINE_LEN {
            log.cur.push(b as char);
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
        let bytes = log.lines.get(idx)?.as_bytes();
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
        Some(n)
    }
}
