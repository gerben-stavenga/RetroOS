//! Fixed-size ring buffer (pipe), ported from C++ PipeN.
//!
//! Generic over element type T. Used for IRQ events, keyboard scancodes, etc.

pub struct Pipe<T: Copy, const N: usize> {
    buf: [T; N],
    read_pos: usize,
    write_pos: usize,
}

impl<T: Copy, const N: usize> Pipe<T, N> {
    pub const fn new(init: T) -> Self {
        Self { buf: [init; N], read_pos: 0, write_pos: 0 }
    }

    /// Push an element, dropping the oldest if full.
    pub fn push(&mut self, val: T) {
        if self.write_pos == self.read_pos + N {
            self.read_pos += 1;
        }
        self.buf[self.write_pos % N] = val;
        self.write_pos += 1;
    }

    /// Pop an element, or None if empty.
    pub fn pop(&mut self) -> Option<T> {
        if self.read_pos == self.write_pos {
            return None;
        }
        let val = self.buf[self.read_pos % N];
        self.read_pos += 1;
        Some(val)
    }

    pub fn is_empty(&self) -> bool {
        self.read_pos == self.write_pos
    }

    /// Drain all entries, calling f for each.
    pub fn drain(&mut self, mut f: impl FnMut(T)) {
        while self.read_pos < self.write_pos {
            f(self.buf[self.read_pos % N]);
            self.read_pos += 1;
        }
    }

    /// Remove the last pushed element (if any). Returns true if removed.
    pub fn pop_back(&mut self) -> bool {
        if self.write_pos > self.read_pos {
            self.write_pos -= 1;
            true
        } else {
            false
        }
    }

    /// Discard all entries.
    pub fn clear(&mut self) {
        self.read_pos = self.write_pos;
    }

    /// Read up to buf.len() elements into a slice. Returns count.
    pub fn read(&mut self, buf: &mut [T]) -> usize {
        let mut i = 0;
        while i < buf.len() && self.read_pos < self.write_pos {
            buf[i] = self.buf[self.read_pos % N];
            self.read_pos += 1;
            i += 1;
        }
        i
    }
}
