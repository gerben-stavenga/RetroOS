//! Host filesystem — talks to hostfs.py via COM1 serial port.
//!
//! Implements the VFS Filesystem trait by sending commands over the serial
//! port, which QEMU bridges to a Unix socket where the host-side Python
//! script serves real file operations.

use crate::arch::{inb, outb};
use crate::kernel::vfs::{Filesystem, Vnode, DirEntry};

const COM1: u16 = 0x3F8;

/// Whether hostfs has been initialized (COM1 configured).
static mut INITIALIZED: bool = false;

/// Initialize COM1 for hostfs communication.
/// Returns true if a serial port is present and peer is connected.
pub fn init() -> bool {
    // Check UART exists: writing scratch register should read back
    outb(COM1 + 7, 0xAA);
    if inb(COM1 + 7) != 0xAA {
        return false;
    }
    outb(COM1 + 1, 0x00); // Disable interrupts
    outb(COM1 + 3, 0x80); // Enable DLAB
    outb(COM1 + 0, 0x01); // Divisor lo = 1 (115200 baud)
    outb(COM1 + 1, 0x00); // Divisor hi
    outb(COM1 + 3, 0x03); // 8N1, DLAB off
    outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
    outb(COM1 + 4, 0x0B); // DTR + RTS + OUT2
    // Check if peer is connected (CTS + DSR in modem status register)
    let msr = inb(COM1 + 6);
    if msr & 0x30 == 0 {
        return false; // No peer
    }
    unsafe { INITIALIZED = true; }
    true
}

fn is_ready() -> bool {
    unsafe { INITIALIZED }
}

fn send_byte(b: u8) {
    // Wait for transmit holding register empty
    while inb(COM1 + 5) & 0x20 == 0 {}
    outb(COM1, b);
}

fn recv_byte() -> u8 {
    // Wait for data ready
    while inb(COM1 + 5) & 0x01 == 0 {}
    inb(COM1)
}

fn send_bytes(data: &[u8]) {
    // Batch into 16-byte FIFO bursts: when LSR.THRE fires the FIFO is
    // empty, so we can write up to 16 bytes before having to wait again.
    // This cuts ~16x off the LSR-poll overhead versus per-byte send.
    let mut i = 0;
    while i < data.len() {
        while inb(COM1 + 5) & 0x20 == 0 {}
        let chunk = (data.len() - i).min(16);
        for _ in 0..chunk {
            outb(COM1, data[i]);
            i += 1;
        }
    }
}

fn recv_bytes(buf: &mut [u8]) {
    // Drain the RX FIFO while LSR.DR is set, only reblocking on the
    // initial-byte wait. Cuts the LSR-poll overhead vs. checking before
    // every single byte.
    let mut i = 0;
    while i < buf.len() {
        while inb(COM1 + 5) & 0x01 == 0 {}
        while i < buf.len() && (inb(COM1 + 5) & 0x01) != 0 {
            buf[i] = inb(COM1);
            i += 1;
        }
    }
}

fn send_u16(v: u16) {
    send_bytes(&v.to_le_bytes());
}

fn send_u32(v: u32) {
    send_bytes(&v.to_le_bytes());
}

fn recv_i32() -> i32 {
    let mut buf = [0u8; 4];
    recv_bytes(&mut buf);
    i32::from_le_bytes(buf)
}

fn recv_u32() -> u32 {
    let mut buf = [0u8; 4];
    recv_bytes(&mut buf);
    u32::from_le_bytes(buf)
}

fn recv_u8() -> u8 {
    recv_byte()
}

const CMD_OPEN: u8 = 0x01;
const CMD_READ: u8 = 0x02;
#[allow(dead_code)]
const CMD_CLOSE: u8 = 0x03;
const CMD_STAT: u8 = 0x04;
const CMD_READDIR: u8 = 0x05;
const CMD_CREATE: u8 = 0x06;
const CMD_WRITE: u8 = 0x07;

pub struct HostFs;

impl HostFs {
    pub const fn new() -> Self {
        Self
    }
}

impl Filesystem for HostFs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        if !is_ready() { return None; }
        send_byte(CMD_OPEN);
        send_u16(path.len() as u16);
        send_bytes(path);

        let status = recv_i32();
        let handle = recv_u32();
        let size = recv_u32();
        if status < 0 { return None; }

        Some(Vnode { handle: handle as u64, size })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        if !is_ready() { return -5; }
        send_byte(CMD_READ);
        send_u32(handle as u32);
        send_u32(offset);
        send_u32(buf.len() as u32);

        let status = recv_i32();
        let data_len = recv_u32();
        if status < 0 { return status; }

        let to_read = (data_len as usize).min(buf.len());
        recv_bytes(&mut buf[..to_read]);
        // Drain any extra bytes (shouldn't happen)
        for _ in to_read..data_len as usize {
            recv_byte();
        }
        to_read as i32
    }

    fn readdir(&self, dir: &[u8], index: usize) -> Option<DirEntry> {
        if !is_ready() { return None; }
        send_byte(CMD_READDIR);
        send_u16(dir.len() as u16);
        send_bytes(dir);
        send_u32(index as u32);

        let status = recv_i32();
        if status < 0 { return None; }

        let name_len = recv_u8() as usize;
        let mut name = [0u8; 100];
        let n = name_len.min(100);
        recv_bytes(&mut name[..n]);
        // Drain excess
        for _ in n..name_len {
            recv_byte();
        }
        let size = recv_u32();
        let is_dir = recv_u8() != 0;

        Some(DirEntry { name, name_len: n, size, is_dir })
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        if !is_ready() { return false; }
        send_byte(CMD_STAT);
        send_u16(path.len() as u16);
        send_bytes(path);

        let status = recv_i32();
        let _size = recv_u32();
        let is_dir = recv_u8();
        status == 0 && is_dir != 0
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        if !is_ready() { return None; }
        send_byte(CMD_CREATE);
        send_u16(path.len() as u16);
        send_bytes(path);

        let status = recv_i32();
        let handle = recv_u32();
        if status < 0 { return None; }
        Some(Vnode { handle: handle as u64, size: 0 })
    }

    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        if !is_ready() { return -5; }
        send_byte(CMD_WRITE);
        send_u32(handle as u32);
        send_u32(offset);
        send_u32(data.len() as u32);
        send_bytes(data);

        let status = recv_i32();
        let written = recv_u32();
        if status < 0 { return status; }
        written as i32
    }
}

/// Close a hostfs handle (called when VFS file entry is freed).
/// Note: the VFS doesn't currently call close on the Filesystem trait,
/// so hostfs handles leak. This is acceptable for now.
#[allow(dead_code)]
pub fn close_handle(handle: u32) {
    if !is_ready() { return; }
    send_byte(CMD_CLOSE);
    send_u32(handle);
    let _status = recv_i32();
}
