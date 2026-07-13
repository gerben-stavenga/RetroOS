//! x86 CPU control and I/O routines

use core::arch::asm;

/// FPU/SSE state save area.
/// 512 bytes, 16-byte aligned (required by FXSAVE; FSAVE only uses 108
/// bytes but fits fine).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxState(pub [u8; 512]);

impl Default for FxState {
    fn default() -> Self { Self::zeroed() }
}

/// Check if FXSAVE/FXRSTOR is available (CR4.OSFXSR set during boot).
#[inline]
fn has_fxsr() -> bool { read_cr4() & cr4::OSFXSR != 0 }

impl FxState {
    pub const fn zeroed() -> Self { Self([0; 512]) }

    /// Save the live FPU/SSE state into this area.
    #[inline]
    pub fn save(&mut self) {
        unsafe {
            if has_fxsr() {
                asm!("fxsave [{}]", in(reg) self as *mut _ as *mut u8, options(nostack));
            } else {
                asm!("fsave [{}]", in(reg) self as *mut _ as *mut u8, options(nostack));
            }
        }
    }

    /// Restore the FPU/SSE state from this area.
    #[inline]
    pub fn restore(&self) {
        unsafe {
            if has_fxsr() {
                asm!("fxrstor [{}]", in(reg) self as *const _ as *const u8, options(nostack));
            } else {
                asm!("frstor [{}]", in(reg) self as *const _ as *const u8, options(nostack));
            }
        }
    }
}

/// Clean FPU template captured at boot after `fninit` — used to seed new
/// threads so they don't inherit stale FPU state from whoever ran before.
static mut CLEAN_FX: FxState = FxState::zeroed();

/// Capture the current (just-initialized) FPU state as the template for new
/// threads. Call once, immediately after `fninit`, during host bring-up.
pub fn capture_clean_fx_template() {
    let p = &raw mut CLEAN_FX;
    unsafe { (*p).save(); }
}

/// Return a copy of the clean FPU template for initializing a new thread's
/// save area.
pub fn clean_fx_template() -> FxState {
    unsafe { CLEAN_FX }
}

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
///
/// # Safety
///
/// The caller must ensure `value` is a valid CR0 configuration for the current
/// CPU mode; an invalid control-register write can fault or corrupt execution.
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
///
/// # Safety
///
/// The caller must ensure `value` points at a valid, properly built page
/// directory; loading a bad CR3 makes all subsequent memory accesses fault.
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

/// Write back and invalidate all cache lines (`WBINVD`). Used when changing a
/// memory-type setting (e.g. reprogramming the PAT) so no stale cached line
/// survives the type change.
#[inline]
pub fn wbinvd() {
    unsafe {
        asm!("wbinvd", options(nostack));
    }
}

/// IA32_PAT MSR (Page Attribute Table).
pub const IA32_PAT_MSR: u32 = 0x277;

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
///
/// # Safety
///
/// The caller must ensure `value` is a valid CR4 configuration; toggling
/// feature bits the rest of the kernel does not expect can fault or corrupt
/// execution.
#[inline]
pub unsafe fn write_cr4(value: u32) {
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nostack)); }
}

/// Read the time-stamp counter (RDTSC). Wall-clock-ish in cycles, advances
/// at CPU base frequency. Useful for cheap user/kernel-time accounting.
#[inline(always)]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
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
#[allow(dead_code)]
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

/// Read `buf.len()` words from an I/O port in one `rep insw`.
///
/// The bulk form is not a micro-optimization: on a virtualized host every
/// discrete `in` is a VM exit, so a 512-byte ATA sector cost 256 of them. A
/// `rep insw` is one instruction the hypervisor services as a single batched
/// transfer — the difference between an 80 ms 8 KB WAD read (which stalls the
/// audio pump and swallows the guest's timer ticks) and a sub-millisecond one.
#[inline]
pub fn insw(port: u16, buf: &mut [u16]) {
    unsafe {
        asm!(
            "rep insw",
            in("dx") port,
            inout("edi") buf.as_mut_ptr() => _,
            inout("ecx") buf.len() => _,
            options(nostack),
        );
    }
}

/// Write to I/O port
#[inline]
pub fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Write word (16-bit) to I/O port
#[inline]
pub fn outw(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack));
    }
}

/// Read dword (32-bit) from I/O port (PCI config, AC'97 32-bit registers)
#[inline]
pub fn inl(port: u16) -> u32 {
    let value: u32;
    unsafe {
        asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Write dword (32-bit) to I/O port
#[inline]
pub fn outl(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack));
    }
}

#[inline]
pub(super) unsafe fn read_dr6() -> u32 {
    let value: u32;
    unsafe { asm!("mov {}, dr6", out(reg) value, options(nomem, nostack)); }
    value
}

#[inline]
pub(super) unsafe fn write_dr6(value: u32) {
    unsafe { asm!("mov dr6, {}", in(reg) value, options(nomem, nostack)); }
}

#[inline]
pub(super) unsafe fn write_dr0(value: u32) {
    unsafe { asm!("mov dr0, {}", in(reg) value, options(nomem, nostack)); }
}

#[inline]
pub(super) unsafe fn read_dr7() -> u32 {
    let value: u32;
    unsafe { asm!("mov {}, dr7", out(reg) value, options(nomem, nostack)); }
    value
}

/// DR3 is reserved for the virtual-IF exit breakpoint; DR0/DR1 stay free for
/// the write-watchpoint debug feature (`set_debug_watch`), which writes DR7
/// wholesale. The two are not meant to be armed at the same time.
const DR3_EXEC_ENABLE: u32 = 1 << 6; // L3

#[inline]
unsafe fn write_dr3(value: u32) {
    unsafe { asm!("mov dr3, {}", in(reg) value, options(nomem, nostack)); }
}

/// Current privilege level, from CS's low two bits.
#[inline]
pub fn cpl() -> u16 {
    let cs: u16;
    unsafe { asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack)); }
    cs & 3
}

/// Program DR3 as an execute breakpoint at `addr` (`None` disables it):
/// R/W3 = 00 and LEN3 = 00, the only legal encoding for one, enabled via L3.
///
/// # Safety
///
/// `MOV DR` is CPL=0-only — a ring-1 caller #GPs. Reach this through
/// `Arch::set_exec_breakpoint`, which routes an unprivileged caller via the
/// arch call instead of faulting.
pub(super) unsafe fn program_exec_bp(addr: Option<u32>) {
    unsafe {
        match addr {
            Some(a) => {
                write_dr3(a);
                // Clear R/W3+LEN3 (bits 28..31) so it is an execute break, then
                // enable L3. Leaves DR0/DR1's watchpoint bits untouched.
                write_dr7((read_dr7() & !0xF000_0000) | DR3_EXEC_ENABLE);
            }
            None => write_dr7(read_dr7() & !DR3_EXEC_ENABLE),
        }
    }
}

#[inline]
pub(super) unsafe fn write_dr1(value: u32) {
    unsafe { asm!("mov dr1, {}", in(reg) value, options(nomem, nostack)); }
}

#[inline]
pub(super) unsafe fn write_dr7(value: u32) {
    unsafe { asm!("mov dr7, {}", in(reg) value, options(nomem, nostack)); }
}

/// Load Global Descriptor Table
///
/// # Safety
///
/// The caller must ensure `gdt_ptr` describes a valid GDT that stays alive and
/// is consistent with the segment selectors currently in use.
#[inline]
pub unsafe fn lgdt(gdt_ptr: &GdtPtr) {
    unsafe { asm!("lgdt [{}]", in(reg) gdt_ptr, options(nostack)); }
}

/// Load Interrupt Descriptor Table
///
/// # Safety
///
/// The caller must ensure `idt_ptr` describes a valid IDT that stays alive;
/// loading a malformed IDT makes the next interrupt fault.
#[inline]
pub unsafe fn lidt(idt_ptr: &IdtPtr) {
    unsafe { asm!("lidt [{}]", in(reg) idt_ptr, options(nostack)); }
}

/// Load Task Register
///
/// # Safety
///
/// The caller must ensure `selector` references a valid TSS descriptor in the
/// current GDT.
#[inline]
pub unsafe fn ltr(selector: u16) {
    unsafe { asm!("ltr {:x}", in(reg) selector, options(nostack)); }
}

/// Load Local Descriptor Table register
///
/// # Safety
///
/// The caller must ensure `selector` references a valid LDT descriptor in the
/// current GDT.
#[inline]
pub unsafe fn lldt(selector: u16) {
    unsafe { asm!("lldt {:x}", in(reg) selector, options(nostack)); }
}

/// Enable interrupts
#[inline]
pub(super) fn sti() {
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Disable interrupts
#[inline]
pub(super) fn cli() {
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

/// Shut the machine down. Writes the QEMU/Bochs ACPI shutdown ports —
/// QEMU exits cleanly. On real hardware this is a no-op fallback to a
/// halt loop; the user can power off manually.
pub fn shutdown() -> ! {
    cli();
    outw(0x604, 0x2000);   // QEMU PIIX (i440FX) ACPI shutdown
    outw(0xB004, 0x2000);  // QEMU pre-1.7 / Bochs
    outw(0x4004, 0x3400);  // VirtualBox
    // Fallback halt via halt_forever: shutdown() is called from the ring-1
    // kernel, where a direct `hlt` would #GP (CPL-0-only instruction).
    crate::halt_forever()
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
#[allow(dead_code)]
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
///
/// # Safety
///
/// The caller must ensure `msr` is a writable MSR and `value` is valid for it;
/// a bad write can `#GP` or change CPU behaviour globally.
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
///
/// # Safety
///
/// The caller must ensure both selectors reference valid descriptors in the
/// active GDT; the far return reloads CS, so a bad `code_selector` faults.
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
