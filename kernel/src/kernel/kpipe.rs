//! Kernel pipes — refcounted byte ring buffers for inter-process I/O
//!
//! Used by Linux pipe()/pipe2() syscalls and internally for console stdin.
//! Each pipe has independent reader and writer refcounts. When all writers
//! close, readers get EOF. When all readers close, writers get EPIPE.

use crate::pipe::Pipe;

const MAX_PIPES: usize = 64;
const PIPE_BUF_SIZE: usize = 1024;

/// A kernel pipe with refcounted endpoints
struct KernelPipe {
    buffer: Pipe<u8, PIPE_BUF_SIZE>,
    readers: u16,
    writers: u16,
}

impl KernelPipe {
    const fn empty() -> Self {
        Self {
            buffer: Pipe::new(0),
            readers: 0,
            writers: 0,
        }
    }

    fn is_free(&self) -> bool {
        self.readers == 0 && self.writers == 0
    }
}

static mut PIPES: [KernelPipe; MAX_PIPES] = {
    const EMPTY: KernelPipe = KernelPipe::empty();
    [EMPTY; MAX_PIPES]
};

/// Allocate a new pipe. Returns pipe index, or None if table full.
/// Starts with readers=1, writers=1.
pub fn alloc() -> Option<u8> {
    unsafe {
        for i in 0..MAX_PIPES {
            if PIPES[i].is_free() {
                PIPES[i] = KernelPipe {
                    buffer: Pipe::new(0),
                    readers: 1,
                    writers: 1,
                };
                return Some(i as u8);
            }
        }
    }
    None
}

/// Read up to `buf.len()` bytes from pipe. Returns bytes read.
/// Returns 0 if empty and no writers (EOF).
pub fn read(idx: u8, buf: &mut [u8]) -> usize {
    unsafe {
        let p = &mut PIPES[idx as usize];
        p.buffer.read(buf)
    }
}

/// Write bytes to pipe. Returns bytes written, or -1 if no readers (EPIPE).
pub fn write(idx: u8, data: &[u8]) -> i32 {
    unsafe {
        let p = &mut PIPES[idx as usize];
        if p.readers == 0 {
            return -1; // EPIPE
        }
        for &b in data {
            p.buffer.push(b);
        }
        data.len() as i32
    }
}

/// Remove the last written byte (for backspace line editing). Returns true if removed.
pub fn pop_back(idx: u8) -> bool {
    unsafe { PIPES[idx as usize].buffer.pop_back() }
}

/// Check if pipe has data available for reading.
pub fn has_data(idx: u8) -> bool {
    unsafe { !PIPES[idx as usize].buffer.is_empty() }
}

/// Check if pipe has any writers remaining.
pub fn has_writers(idx: u8) -> bool {
    unsafe { PIPES[idx as usize].writers > 0 }
}

/// Increment reader refcount (for fork/dup).
pub fn add_reader(idx: u8) {
    unsafe { PIPES[idx as usize].readers += 1; }
}

/// Increment writer refcount (for fork/dup).
pub fn add_writer(idx: u8) {
    unsafe { PIPES[idx as usize].writers += 1; }
}

/// Decrement reader refcount. Pipe is freed when both hit 0.
pub fn close_reader(idx: u8) {
    unsafe {
        let p = &mut PIPES[idx as usize];
        if p.readers > 0 {
            p.readers -= 1;
        }
    }
}

/// Decrement writer refcount. Pipe is freed when both hit 0.
pub fn close_writer(idx: u8) {
    unsafe {
        let p = &mut PIPES[idx as usize];
        if p.writers > 0 {
            p.writers -= 1;
        }
    }
}
