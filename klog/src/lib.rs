#![no_std]

//! Allocation-free debug-log ring shared by boot code and the kernel.
//!
//! The console layer feeds bytes here from its common stream. The kernel owns
//! and attaches the backing buffer, then supplies the DOS/VFS adapters
//! that expose the retained bytes later.

pub const DEFAULT_CAPACITY: usize = 128 * 1024;
const MAX_LINE_LEN: usize = 512;

struct KLog {
    bytes: usize,
    capacity: usize,
    head: usize,
    len: usize,
    /// Number of bytes appended since initialization, including evicted bytes.
    total: usize,
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
            total: 0,
            cur_len: 0,
            dumping: false,
            dump_head: 0,
            dump_bytes: 0,
            dump_pos: 0,
            dump_next_line: 0,
        }
    }

    fn byte_at(&self, start: usize, offset: usize) -> u8 {
        unsafe { *((self.bytes + (start + offset) % self.capacity) as *const u8) }
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
        self.total = self.total.saturating_add(1);
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
static LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
struct Guard;
impl Guard {
    fn lock() -> Self {
        use core::sync::atomic::Ordering;
        while LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, core::sync::atomic::Ordering::Release);
    }
}

/// Attach lifetime-long storage, preserving the early log when growing it.
/// Callers allocate before entering this function; no allocation occurs locked.
pub fn init(storage: &'static mut [u8]) {
    let _guard = Guard::lock();
    unsafe {
        let log = &mut *core::ptr::addr_of_mut!(LOG);
        while log.len > storage.len() {
            log.drop_oldest_line();
        }
        for (i, byte) in storage[..log.len].iter_mut().enumerate() {
            *byte = log.byte_at(log.head, i);
        }
        log.bytes = storage.as_mut_ptr() as usize;
        log.capacity = storage.len();
        log.head = 0;
        log.dumping = false;
    }
}

/// Append one byte from the common debug stream. During a line-oriented dump,
/// appends pause so the dump's own console echo cannot grow the snapshot.
pub fn push_byte(b: u8) {
    push_bytes(core::slice::from_ref(&b));
}

/// Append one complete record atomically with respect to readers and writers.
pub fn push_bytes(bytes: &[u8]) {
    let _guard = Guard::lock();
    unsafe {
        let log = &mut *core::ptr::addr_of_mut!(LOG);
        if log.capacity == 0 || log.dumping {
            return;
        }
        for &b in bytes {
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
}

/// Copy completed line `idx` (zero is oldest) into `out`. Calls made in order
/// scan the snapshot once; an out-of-order index restarts from its beginning.
pub fn line(idx: usize, out: &mut [u8]) -> Option<usize> {
    let _guard = Guard::lock();
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
    let _guard = Guard::lock();
    unsafe { (*core::ptr::addr_of!(LOG)).len as u32 }
}

/// Monotonic position of the next byte in the stream. Unlike `byte_len`, this
/// continues advancing when old ring lines are evicted.
pub fn total_bytes() -> usize {
    let _guard = Guard::lock();
    unsafe { (*core::ptr::addr_of!(LOG)).total }
}

/// Read bytes appended since an absolute stream position. If the ring has
/// already evicted that position, return its oldest retained position instead.
/// The caller can then append the returned bytes to a durable log file.
pub fn read_since(offset: usize, out: &mut [u8]) -> (usize, usize) {
    let _guard = Guard::lock();
    unsafe {
        let log = &*core::ptr::addr_of!(LOG);
        if log.capacity == 0 {
            return (offset, 0);
        }
        let oldest = log.total - log.len;
        let start = offset.max(oldest).min(log.total);
        let n = out.len().min(log.total - start);
        for (i, byte) in out[..n].iter_mut().enumerate() {
            *byte = log.byte_at(log.head, start - oldest + i);
        }
        (start, n)
    }
}

/// Read the ring as a flat byte stream at `offset`.
pub fn read(offset: u32, out: &mut [u8]) -> usize {
    let _guard = Guard::lock();
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
