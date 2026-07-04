//! Injected raw port I/O for kernel-side drivers (ATA, hostfs COM1, CMOS,
//! PCI config) that run DEEP below any `machine: &mut A` parameter — the VFS
//! read path reaches the disk from call sites that never see the arch handle.
//!
//! The canonical port surface is `Arch::inb/outb/...`; these hooks are the
//! same backend functions, installed once by the ENTRY crate before
//! `startup` (composition-root dependency injection, no `cfg`). Reads
//! before installation return the ISA "no device" pattern; writes drop.

/// The installed hook table.
#[derive(Clone, Copy)]
pub struct PortIo {
    pub inb: fn(u16) -> u8,
    pub inw: fn(u16) -> u16,
    pub inl: fn(u16) -> u32,
    pub outb: fn(u16, u8),
    pub outw: fn(u16, u16),
    pub outl: fn(u16, u32),
}

const NONE: PortIo = PortIo {
    inb: |_| 0xFF,
    inw: |_| 0xFFFF,
    inl: |_| 0xFFFF_FFFF,
    outb: |_, _| {},
    outw: |_, _| {},
    outl: |_, _| {},
};

static mut HOOKS: PortIo = NONE;

/// Install the backend's port accessors. Single-threaded boot context (the
/// entry calls this before `startup`), so the plain static is safe by the
/// same argument as the rest of the boot statics.
pub fn install_portio(hooks: PortIo) {
    unsafe { HOOKS = hooks };
}

#[inline]
fn hooks() -> PortIo {
    unsafe { HOOKS }
}

#[inline]
pub fn inb(port: u16) -> u8 {
    (hooks().inb)(port)
}
#[inline]
pub fn inw(port: u16) -> u16 {
    (hooks().inw)(port)
}
#[inline]
pub fn inl(port: u16) -> u32 {
    (hooks().inl)(port)
}
#[inline]
pub fn outb(port: u16, val: u8) {
    (hooks().outb)(port, val)
}
#[inline]
pub fn outw(port: u16, val: u16) {
    (hooks().outw)(port, val)
}
#[inline]
pub fn outl(port: u16, val: u32) {
    (hooks().outl)(port, val)
}
