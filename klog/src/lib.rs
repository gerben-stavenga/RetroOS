#![no_std]

//! Allocation-free debug-log ring shared by boot code and the kernel.
//!
//! The console layer feeds bytes here from its common stream. The kernel owns
//! and attaches the large backing array, then supplies the DOS/VFS adapters
//! that expose the retained bytes later.

pub const DEFAULT_CAPACITY: usize = 128 * 1024;
const MAX_LINE_LEN: usize = 512;

struct KLog {
    bytes: usize,
    capacity: usize,
    head: usize,
    len: usize,
    cur_len: usize,
    dumping: bool,
    dump_head: usize,
    dump_bytes: usize,
    dump_pos: usize,
    dump_next_line: usize,
}

impl KLog {
    const fn new() -> Self {
        Self {
            bytes: 0,
            capacity: 0,
            head: 0,
            len: 0,
            cur_len: 0,
            dumping: false,
            dump_head: 0,
            dump_bytes: 0,
            dump_pos: 0,
            dump_next_line: 0,
        }
    }

    fn byte_at(&self, start: usize, offset: usize) -> u8 {
        unsafe {
            *((self.bytes + (start + offset) % self.capacity) as *const u8)
        }
    }

    fn set_byte(&mut self, offset: usize, byte: u8) {
        unsafe {
            *((self.bytes + offset) as *mut u8) = byte;
        }
    }

    fn drop_oldest_line(&mut self) {
        while self.len != 0 {
            let b = self.byte_at(self.head, 0);
            self.head = (self.head + 1) % self.capacity;
            self.len -= 1;
            if b == b'\n' {
                return;
            }
        }
        self.cur_len = 0;
    }

    fn append(&mut self, b: u8) {
        if self.len == self.capacity {
            self.drop_oldest_line();
        }
        let tail = (self.head + self.len) % self.capacity;
        self.set_byte(tail, b);
        self.len += 1;
    }

    fn start_dump(&mut self) {
        self.dumping = true;
        self.dump_head = self.head;
        self.dump_bytes = self.len;
        self.dump_pos = 0;
        self.dump_next_line = 0;
    }

    fn scan_dump_line(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut n = 0;
        while self.dump_pos < self.dump_bytes {
            let b = self.byte_at(self.dump_head, self.dump_pos);
            self.dump_pos += 1;
            if b == b'\n' {
                self.dump_next_line += 1;
                return Some(n);
            }
            if n < out.len() {
                out[n] = b;
                n += 1;
            }
        }
        None
    }
}

static mut LOG: KLog = KLog::new();

/// Attach caller-owned static storage and reset the log. Keeping the large
/// array in the kernel entry avoids charging small `lib` users such as the
/// BIOS bootloader for a log they never expose.
pub fn init(storage: &'static mut [u8]) {
    unsafe {
        let log = &mut *core::ptr::addr_of_mut!(LOG);
        *log = KLog::new();
        log.bytes = storage.as_mut_ptr() as usize;
        log.capacity = storage.len();
    }
}

/// Append one byte from the common debug stream. During a line-oriented dump,
/// appends pause so the dump's own console echo cannot grow the snapshot.
pub fn push_byte(b: u8) {
    unsafe {
        let log = &mut *core::ptr::addr_of_mut!(LOG);
        if log.capacity == 0 || log.dumping {
            return;
        }
        match b {
            b'\r' => {}
            b'\n' => {
                log.append(b);
                log.cur_len = 0;
            }
            _ if log.cur_len < MAX_LINE_LEN => {
                log.append(b);
                log.cur_len += 1;
            }
            _ => {}
        }
    }
}

/// Copy completed line `idx` (zero is oldest) into `out`. Calls made in order
/// scan the snapshot once; an out-of-order index restarts from its beginning.
pub fn line(idx: usize, out: &mut [u8]) -> Option<usize> {
    unsafe {
        let log = &mut *core::ptr::addr_of_mut!(LOG);
        if log.capacity == 0 {
            return None;
        }
        if idx == 0 {
            log.start_dump();
        }
        if !log.dumping {
            return None;
        }
        if idx != log.dump_next_line {
            log.dump_pos = 0;
            log.dump_next_line = 0;
            let mut discard = [];
            while log.dump_next_line < idx {
                if log.scan_dump_line(&mut discard).is_none() {
                    log.dumping = false;
                    return None;
                }
            }
        }
        let result = log.scan_dump_line(out);
        if result.is_none() {
            log.dumping = false;
        }
        result
    }
}

/// Current number of retained bytes, including an unterminated final line.
pub fn byte_len() -> u32 {
    unsafe { (*core::ptr::addr_of!(LOG)).len as u32 }
}

/// Read the ring as a flat byte stream at `offset`.
pub fn read(offset: u32, out: &mut [u8]) -> usize {
    unsafe {
        let log = &*core::ptr::addr_of!(LOG);
        if log.capacity == 0 {
            return 0;
        }
        let start = (offset as usize).min(log.len);
        let n = out.len().min(log.len - start);
        for (i, byte) in out[..n].iter_mut().enumerate() {
            *byte = log.byte_at(log.head, start + i);
        }
        n
    }
}
