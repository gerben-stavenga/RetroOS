//! Kernel pipes — refcounted buffered byte streams for inter-process I/O
//!
//! Used by Linux pipe()/pipe2() syscalls and internally for console stdin.
//! Each pipe has independent reader and writer refcounts. When all writers
//! close, readers get EOF. When all readers close, writers get EPIPE.
//!
//! Pipes are inherently shared across threads (a write-end in one, a read-end
//! in another), so the pool is genuine shared state — not something a per-thread
//! `&mut` handle can express. It lives behind a `spin::Mutex` so access is
//! borrow-checked and correct under multiple cores (the lock is only ever taken
//! from kernel/event-loop context — ISRs merely queue — so a plain spinlock
//! suffices, no IRQ masking needed).

use alloc::collections::VecDeque;
use spin::Mutex;

const MAX_PIPES: usize = 64;

/// A kernel pipe with refcounted endpoints
struct KernelPipe {
    buffer: VecDeque<u16>,
    pending_eof: bool,
    nonblocking: [bool; 2],
    readers: u16,
    writers: u16,
}

impl KernelPipe {
    const fn empty() -> Self {
        Self {
            buffer: VecDeque::new(),
            pending_eof: false,
            nonblocking: [false; 2],
            readers: 0,
            writers: 0,
        }
    }

    fn is_free(&self) -> bool {
        self.readers == 0 && self.writers == 0
    }
}

static PIPES: Mutex<[KernelPipe; MAX_PIPES]> = {
    const EMPTY: KernelPipe = KernelPipe::empty();
    Mutex::new([EMPTY; MAX_PIPES])
};

/// Allocate a new pipe. Returns pipe index, or None if table full.
/// Starts with readers=1, writers=1.
pub fn alloc() -> Option<u8> {
    let mut pipes = PIPES.lock();
    for i in 0..MAX_PIPES {
        if pipes[i].is_free() {
            pipes[i] = KernelPipe {
                buffer: VecDeque::new(),
                pending_eof: false,
                nonblocking: [false; 2],
                readers: 1,
                writers: 1,
            };
            return Some(i as u8);
        }
    }
    None
}

/// Status flags belong to each shared pipe endpoint, including after dup/fork.
pub fn nonblocking(idx: u8, writer: bool) -> bool {
    PIPES.lock()[idx as usize].nonblocking[usize::from(writer)]
}
pub fn set_nonblocking(idx: u8, writer: bool, enabled: bool) {
    PIPES.lock()[idx as usize].nonblocking[usize::from(writer)] = enabled;
}

/// Read up to `buf.len()` bytes from pipe. Returns bytes read.
/// Returns 0 if empty and no writers (EOF).
pub fn read(idx: u8, buf: &mut [u8]) -> usize {
    read_event(idx, buf).unwrap_or(0)
}

/// Queue the full write without discarding earlier bytes. Foreground children
/// can finish before their reader runs, so storage grows with queued output.
/// Returns bytes written, -1 for no readers, or a negative allocation errno.
pub fn write(idx: u8, data: &[u8]) -> i32 {
    if data.is_empty() { return 0; }
    let Ok(count) = i32::try_from(data.len()) else { return -22; };
    let mut pipes = PIPES.lock();
    let p = &mut pipes[idx as usize];
    if p.readers == 0 {
        return -1; // EPIPE
    }
    if p.buffer.try_reserve(data.len()).is_err() { return -12; }
    p.buffer.extend(data.iter().copied().map(u16::from));
    count
}

/// Remove the last written byte (for backspace line editing). Returns true if removed.
#[allow(dead_code)]
pub fn pop_back(idx: u8) -> bool {
    PIPES.lock()[idx as usize].buffer.pop_back().is_some()
}

/// Check if pipe has data available for reading.
pub fn has_data(idx: u8) -> bool {
    let pipes = PIPES.lock();
    let p = &pipes[idx as usize];
    p.pending_eof || !p.buffer.is_empty()
}

/// Unread bytes, stopping before a terminal EOF event without consuming it.
pub fn available_bytes(idx: u8) -> usize {
    let pipes = PIPES.lock();
    let pipe = &pipes[idx as usize];
    if pipe.pending_eof { 0 } else { pipe.buffer.iter().copied().take_while(|&byte| byte != 256).count() }
}

/// Check if pipe has any writers remaining.
pub fn has_writers(idx: u8) -> bool {
    PIPES.lock()[idx as usize].writers > 0
}

/// Increment reader refcount (for fork/dup).
pub fn add_reader(idx: u8) {
    PIPES.lock()[idx as usize].readers += 1;
}

/// Increment writer refcount (for fork/dup).
pub fn add_writer(idx: u8) {
    PIPES.lock()[idx as usize].writers += 1;
}

/// Decrement reader refcount. Pipe is freed when both hit 0.
pub fn close_reader(idx: u8) {
    let mut pipes = PIPES.lock();
    let p = &mut pipes[idx as usize];
    if p.readers > 0 {
        p.readers -= 1;
    }
    if p.readers == 0 {
        p.buffer = VecDeque::new();
        p.pending_eof = false;
    }
}

/// Decrement writer refcount. Pipe is freed when both hit 0.
pub fn close_writer(idx: u8) {
    let mut pipes = PIPES.lock();
    let p = &mut pipes[idx as usize];
    if p.writers > 0 {
        p.writers -= 1;
    }
}

/// A canonical terminal EOF is a single completed zero-byte read, not a closed pipe.
pub fn write_eof(idx: u8) {
    let mut pipes = PIPES.lock();
    let pipe = &mut pipes[idx as usize];
    if pipe.buffer.try_reserve(1).is_ok() { pipe.buffer.push_back(256); }
}

/// None means blocked; Some(0) means EOF (or a zero-length read).
pub fn read_event(idx: u8, buf: &mut [u8]) -> Option<usize> {
    let mut pipes = PIPES.lock();
    let p = &mut pipes[idx as usize];
    if buf.is_empty() {
        return Some(0);
    }
    if p.pending_eof {
        p.pending_eof = false;
        return Some(0);
    }
    let mut n = 0;
    while n < buf.len() {
        match p.buffer.pop_front() {
            Some(256) => {
                p.pending_eof = n != 0;
                return Some(n);
            }
            Some(byte) => {
                buf[n] = byte as u8;
                n += 1;
            }
            None => break,
        }
    }
    if n != 0 || p.writers == 0 {
        Some(n)
    } else {
        None
    }
}

/// Discard queued terminal input for TCSETSF.
pub fn discard(idx: u8) {
    let mut pipes = PIPES.lock();
    let p = &mut pipes[idx as usize];
    p.buffer.clear();
    p.pending_eof = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_eof_is_ordered_and_does_not_close_the_writer() {
        let pipe = alloc().unwrap();
        let mut bytes = [0; 8];
        assert_eq!(read_event(pipe, &mut bytes), None);
        write(pipe, b"hi");
        write_eof(pipe);
        write(pipe, b"later");
        assert_eq!(read_event(pipe, &mut bytes), Some(2));
        assert_eq!(&bytes[..2], b"hi");
        assert!(has_data(pipe));
        assert_eq!(read_event(pipe, &mut bytes), Some(0));
        assert_eq!(read_event(pipe, &mut bytes), Some(5));
        assert_eq!(&bytes[..5], b"later");
        assert_eq!(read_event(pipe, &mut bytes), None);
        write_eof(pipe);
        discard(pipe);
        assert!(!has_data(pipe));
        assert_eq!(read_event(pipe, &mut bytes), None);
        close_writer(pipe);
        assert_eq!(read_event(pipe, &mut bytes), Some(0));
        close_reader(pipe);
    }
}
