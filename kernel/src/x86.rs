//! x86 CPU control and I/O routines

use core::arch::asm;

/// Read CR0 register
#[inline]
pub fn read_cr0() -> u32 {
    let value: u32;
    unsafe {
        asm!("mov {}, cr0", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Write CR0 register
#[inline]
pub unsafe fn write_cr0(value: u32) {
    unsafe { asm!("mov cr0, {}", in(reg) value, options(nostack)); }
}

/// Read CR2 register (page fault linear address)
#[inline]
pub fn read_cr2() -> u32 {
    let value: u32;
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Read CR3 register (page directory base)
#[inline]
pub fn read_cr3() -> u32 {
    let value: u32;
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Write CR3 register (page directory base)
#[inline]
pub unsafe fn write_cr3(value: u32) {
    unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack)); }
}

/// Flush TLB by reloading CR3
#[inline]
pub fn flush_tlb() {
    unsafe {
        write_cr3(read_cr3());
    }
}

/// Invalidate TLB entry for specific address
#[inline]
pub fn invlpg(addr: usize) {
    unsafe {
        asm!("invlpg [{}]", in(reg) addr, options(nostack));
    }
}

/// Read CR4 register
#[inline]
pub fn read_cr4() -> u32 {
    let value: u32;
    unsafe {
        asm!("mov {}, cr4", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Write CR4 register
#[inline]
pub unsafe fn write_cr4(value: u32) {
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nostack)); }
}

/// Execute CPUID instruction
#[inline]
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        asm!(
            "cpuid",
            inout("eax") leaf => eax,
            lateout("ebx") ebx,
            lateout("ecx") ecx,
            lateout("edx") edx,
            options(nomem, nostack),
        );
    }
    (eax, ebx, ecx, edx)
}

/// CR4 flags
pub mod cr4 {
    pub const VME: u32 = 1 << 0;   // Virtual 8086 Mode Extensions
    pub const PVI: u32 = 1 << 1;   // Protected-mode Virtual Interrupts
    pub const TSD: u32 = 1 << 2;   // Time Stamp Disable
    pub const DE: u32 = 1 << 3;    // Debugging Extensions
    pub const PSE: u32 = 1 << 4;   // Page Size Extension
    pub const PAE: u32 = 1 << 5;   // Physical Address Extension
    pub const MCE: u32 = 1 << 6;   // Machine Check Exception
    pub const PGE: u32 = 1 << 7;   // Page Global Enabled
    pub const PCE: u32 = 1 << 8;   // Performance-Monitoring Counter Enable
    pub const OSFXSR: u32 = 1 << 9;  // OS support for FXSAVE/FXRSTOR
    pub const OSXMMEXCPT: u32 = 1 << 10; // OS support for unmasked SIMD exceptions
}

/// Read byte from I/O port
#[inline]
pub fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Read word (16-bit) from I/O port
#[inline]
pub fn inw(port: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Write to I/O port
#[inline]
pub fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Load Global Descriptor Table
#[inline]
pub unsafe fn lgdt(gdt_ptr: &GdtPtr) {
    unsafe { asm!("lgdt [{}]", in(reg) gdt_ptr, options(nostack)); }
}

/// Load Interrupt Descriptor Table
#[inline]
pub unsafe fn lidt(idt_ptr: &IdtPtr) {
    unsafe { asm!("lidt [{}]", in(reg) idt_ptr, options(nostack)); }
}

/// Load Task Register
#[inline]
pub unsafe fn ltr(selector: u16) {
    unsafe { asm!("ltr {:x}", in(reg) selector, options(nostack)); }
}

/// Enable interrupts
#[inline]
pub fn sti() {
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Disable interrupts
#[inline]
pub fn cli() {
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

/// Halt CPU until next interrupt
#[inline]
pub fn hlt() {
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }
}

/// GDT pointer structure
#[repr(C, packed)]
pub struct GdtPtr {
    pub limit: u16,
    pub base: u32,
}

/// IDT pointer structure
#[repr(C, packed)]
pub struct IdtPtr {
    pub limit: u16,
    pub base: u32,
}

/// CR0 flags
pub mod cr0 {
    pub const PE: u32 = 1 << 0;  // Protected Mode Enable
    pub const MP: u32 = 1 << 1;  // Monitor Co-Processor
    pub const EM: u32 = 1 << 2;  // Emulation
    pub const TS: u32 = 1 << 3;  // Task Switched
    pub const ET: u32 = 1 << 4;  // Extension Type
    pub const NE: u32 = 1 << 5;  // Numeric Error
    pub const WP: u32 = 1 << 16; // Write Protect
    pub const AM: u32 = 1 << 18; // Alignment Mask
    pub const NW: u32 = 1 << 29; // Not Write-through
    pub const CD: u32 = 1 << 30; // Cache Disable
    pub const PG: u32 = 1 << 31; // Paging
}

/// EFER MSR (Extended Feature Enable Register)
pub const EFER_MSR: u32 = 0xC0000080;

/// EFER flags
pub mod efer {
    pub const SCE: u64 = 1 << 0;   // System Call Extensions
    pub const LME: u64 = 1 << 8;   // Long Mode Enable
    pub const LMA: u64 = 1 << 10;  // Long Mode Active (read-only)
    pub const NXE: u64 = 1 << 11;  // No-Execute Enable
}

/// Read Model Specific Register
#[inline]
pub fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Write Model Specific Register
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack),
        );
    }
}

/// Reload all data segment registers
#[inline]
pub unsafe fn reload_segments(data_selector: u16, code_selector: u16) {
    unsafe {
        asm!(
            "mov ds, {0:x}",
            "mov es, {0:x}",
            "mov fs, {0:x}",
            "mov gs, {0:x}",
            "mov ss, {0:x}",
            // Far jump to reload CS
            "push {1:e}",
            "lea {2}, [2f]",
            "push {2}",
            "retf",
            "2:",
            in(reg) data_selector,
            in(reg) code_selector as u32,
            lateout(reg) _,
            options(nostack),
        );
    }
}
