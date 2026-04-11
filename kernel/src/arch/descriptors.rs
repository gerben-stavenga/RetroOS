//! GDT, IDT, and TSS setup for x86
//!
//! Segment selectors:
//! - 0x08: Kernel Code 32-bit (ring 0, arch)
//! - 0x10: Kernel Data (ring 0, arch)
//! - 0x18: Kernel Code 64-bit (ring 0, arch)
//! - 0x20: User Code 32-bit (ring 3)
//! - 0x28: User Data (ring 3)
//! - 0x30: User Code 64-bit (ring 3)
//! - 0x38: TSS32 (8 bytes - 32-bit descriptor)
//! - 0x40: TSS64 (16 bytes - 0x40 + 0x48)
//! - 0x50: Ring-1 Code 32-bit (OS kernel)
//! - 0x58: Ring-1 Data (OS kernel)

#![allow(static_mut_refs)]

use crate::arch::x86::{self, GdtPtr, IdtPtr};

/// Segment selectors
pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_CS64: u16 = 0x10;   // SYSCALL CS = STAR[47:32]
pub const KERNEL_DS: u16 = 0x18;     // SYSCALL SS = STAR[47:32]+8
pub const USER_CS: u16 = 0x20 | 3;   // Ring 3
pub const USER_DS: u16 = 0x28 | 3;   // Ring 3
pub const USER_CS64: u16 = 0x30 | 3; // Ring 3
pub const TSS32_SEL: u16 = 0x38;
pub const TSS64_SEL: u16 = 0x40;

/// Segment selectors - ring 1 (OS kernel)
pub const RING1_CS: u16 = 0x50 | 1; // Ring 1
pub const RING1_DS: u16 = 0x58 | 1; // Ring 1

/// Number of IDT entries (full 256: 0x00-0x1F exceptions, 0x20-0x2F IRQs, 0x30-0xFF user-callable)
const IDT_ENTRIES: usize = 256;

/// GDT entry (8 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

impl GdtEntry {
    const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    /// Create a 32-bit segment descriptor
    /// is_code: true for code segment, false for data segment
    /// dpl: privilege level (0 = kernel, 3 = user)
    const fn segment32(is_code: bool, dpl: u8) -> Self {
        // Access byte: Present(1) | DPL(2) | S=1 | Type(4)
        // Type: Execute(1) | DC(0) | RW(1) | Accessed(0)
        let type_bits = if is_code { 0b1010 } else { 0b0010 };
        let access = 0x80 | ((dpl & 3) << 5) | 0x10 | type_bits;

        // Granularity: G(1) | D/B(1) | L(0) | AVL(0) | Limit_high(4)
        // D=1 for 32-bit, L=0
        let granularity = 0xCF; // 4K granularity, 32-bit, limit=0xFFFFF

        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            granularity,
            base_high: 0,
        }
    }

    /// Set the segment base. Used to build the boot-time offset GDT.
    const fn with_base(mut self, base: u32) -> Self {
        self.base_low = base as u16;
        self.base_mid = (base >> 16) as u8;
        self.base_high = (base >> 24) as u8;
        self
    }

    /// Create a 64-bit code segment descriptor
    /// dpl: privilege level (0 = kernel, 3 = user)
    const fn segment64(dpl: u8) -> Self {
        // Access byte: Present(1) | DPL(2) | S=1 | Type(4)
        // Type: Execute(1) | DC(0) | RW(1) | Accessed(0)
        let access = 0x80 | ((dpl & 3) << 5) | 0x10 | 0b1010;

        // Granularity: G(1) | D(0) | L(1) | AVL(0) | Limit_high(4)
        // L=1 for long mode, D must be 0 when L=1
        let granularity = 0xAF; // 4K granularity, 64-bit (L=1, D=0), limit=0xFFFFF

        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            granularity,
            base_high: 0,
        }
    }

    /// Create a TSS descriptor (low 8 bytes)
    /// For 64-bit mode, this is followed by TssHigh for the upper 8 bytes
    fn tss_low(base: u64, limit: u32) -> Self {
        // Access: Present(1) | DPL=0 | S=0 | Type=0x9 (64-bit TSS available)
        let access = 0x89;
        let granularity = ((limit >> 16) & 0x0F) as u8;

        Self {
            limit_low: limit as u16,
            base_low: base as u16,
            base_mid: (base >> 16) as u8,
            access,
            granularity,
            base_high: (base >> 24) as u8,
        }
    }
}


/// 32-bit IDT entry (8 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry32 {
    offset_low: u16,
    selector: u16,
    zero: u8,
    type_attr: u8,
    offset_high: u16,
}

impl IdtEntry32 {
    const fn null() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            zero: 0,
            type_attr: 0,
            offset_high: 0,
        }
    }

    fn interrupt_gate(handler: u32, dpl: u8) -> Self {
        let type_attr = 0x80 | ((dpl & 3) << 5) | 0x0E;
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CS,
            zero: 0,
            type_attr,
            offset_high: (handler >> 16) as u16,
        }
    }
}

/// 64-bit IDT entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry64 {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

impl IdtEntry64 {
    const fn null() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    fn interrupt_gate(handler: u32, dpl: u8) -> Self {
        let type_attr = 0x80 | ((dpl & 3) << 5) | 0x0E;
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CS64,
            ist: 0,
            type_attr,
            offset_mid: (handler >> 16) as u16,
            offset_high: 0,  // Handler < 4GB
            _reserved: 0,
        }
    }
}

/// IOPB covers ports 0x000-0x3DF (VGA ports end at 0x3DF).
/// Byte count: (0x3DF / 8) + 1 = 124 data bytes + 1 terminating 0xFF = 125.
/// Ports above 0x3DF fall outside the IOPB (beyond TSS limit) and are denied.
const IOPB_SIZE: usize = 125;

/// Unified Task State Segment with interrupt redirection bitmap and IOPB.
/// Works for both 32-bit and 64-bit modes:
/// - 32-bit: CPU reads ESP0 from low 32 bits, SS0 from high 32 bits of sp0
/// - 64-bit: CPU reads RSP0 as full 64 bits of sp0
///
/// With CR4.VME=1, the CPU consults the interrupt redirection bitmap (32 bytes
/// before iopb_offset) for INT n in VM86 mode: bit SET = #GP to monitor,
/// bit CLEAR = through IVT directly. CLI/STI/PUSHF/POPF/IRET use hardware VIF.
#[repr(C, packed)]
pub struct Tss {
    _reserved0: u32,         // offset 0: link (32-bit) / reserved (64-bit)
    pub sp0: u64,            // offset 4: ESP0+SS0 (32-bit) / RSP0 (64-bit)
    pub sp1: u64,            // offset 12: ESP1+SS1 (32-bit) / RSP1 (64-bit)
    pub sp2: u64,            // offset 20: ESP2+SS2 (32-bit) / RSP2 (64-bit)
    _reserved1: u64,         // offset 28
    pub ist: [u64; 7],       // offset 36: IST1-IST7 (64-bit only, zero for 32-bit)
    _reserved2: u64,         // offset 92
    _reserved3: u16,         // offset 100
    iopb_offset: u16,        // offset 102
    int_redir: [u8; 32],     // offset 104: software interrupt redirection bitmap
    pub iopb: [u8; IOPB_SIZE], // offset 136: I/O Permission Bitmap
}

impl Tss {
    const fn new() -> Self {
        Self {
            _reserved0: 0,
            sp0: 0,
            sp1: 0,
            sp2: 0,
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iopb_offset: 136, // Points to iopb field (after 32-byte redirection bitmap)
            int_redir: [0; 32], // All INTs go through IVT by default
            iopb: [0xFF; IOPB_SIZE], // All ports denied by default
        }
    }
}

/// Set up TSS bitmaps for VM86:
/// - IOPB: allow VGA ports (0x3C0-0x3DF), deny everything else
/// - Interrupt redirection: trap handled INTs to monitor, rest through IVT
/// Safety: caller must ensure exclusive access to the TSS.
unsafe fn setup_vm86_bitmaps(tss: *mut Tss) {
    // IOPB: allow VGA ports 0x3C0-0x3DF (bytes 120-123)
    // Trap 0x3C0 (AC index/data) to track flip-flop state
    // Trap 0x3DA (Input Status 1) to synthesize retrace + reset flip-flop
    (*tss).iopb[120] = 0x01; // bit 0 = port 0x3C0
    (*tss).iopb[121] = 0x00;
    (*tss).iopb[122] = 0x00;
    (*tss).iopb[123] = 0x04; // trap bit 2 = port 0x3DA
    // Interrupt redirection: only INT 31h traps to monitor.
    // All other intercepted INTs (20h, 21h, 28h, 2Eh, 2Fh) go through IVT
    // to stubs that call INT 31h, which then traps here.
    (*tss).int_redir[(0x31 / 8) as usize] |= 1 << (0x31 % 8);
}

/// Check whether INT n is intercepted (bit set in redirection bitmap).
pub fn int_intercepted(int_num: u8) -> bool {
    unsafe { TSS32.int_redir[(int_num / 8) as usize] & (1 << (int_num % 8)) != 0 }
}

/// GDT entry indices
const GDT_NULL: usize = 0;        // 0x00
const GDT_KERNEL_CS: usize = 1;   // 0x08
const GDT_KERNEL_CS64: usize = 2; // 0x10 — STAR[47:32], SYSCALL CS
const GDT_KERNEL_DS: usize = 3;   // 0x18 — STAR[47:32]+8, SYSCALL SS
const GDT_USER_CS: usize = 4;     // 0x20 — STAR[63:48], SYSRET base
const GDT_USER_DS: usize = 5;     // 0x28 — SYSRET SS
const GDT_USER_CS64: usize = 6;   // 0x30 — SYSRET CS (64-bit)
const GDT_TSS32: usize = 7;       // 0x38
const GDT_TSS64_LO: usize = 8;    // 0x40
const GDT_TSS64_HI: usize = 9;    // 0x48 (null - upper 32 bits of base are 0)
const GDT_RING1_CS: usize = 10;   // 0x50
const GDT_RING1_DS: usize = 11;   // 0x58
const GDT_LDT: usize = 12;        // 0x60
const GDT_TLS_START: usize = 13;  // 0x68 — first of 3 per-thread TLS slots
// 14 = 0x70, 15 = 0x78

const GDT_ENTRIES: usize = 16;

/// LDT selector (GDT index 12 * 8 = 0x60)
pub const LDT_SEL: u16 = 0x60;

/// 32-bit Interrupt Descriptor Table
#[repr(C, align(8))]
struct Idt32 {
    entries: [IdtEntry32; IDT_ENTRIES],
}

/// 64-bit Interrupt Descriptor Table
#[repr(C, align(8))]
struct Idt64 {
    entries: [IdtEntry64; IDT_ENTRIES],
}

/// Segment base applied to the boot GDT so that linked kernel addresses
/// (0xC0Bxxxxx) resolve to physical memory (0x001xxxxx) via 32-bit segment
/// wraparound, before paging is enabled.
const BOOT_SEG_OFFSET: u32 =
    (super::boot::KERNEL_PHYS as u32).wrapping_sub(super::paging2::KERNEL_BASE as u32);

/// Boot GDT used by the asm `_start` stub until paging is enabled.
/// Layout: null / code32 @ 0x08 / data32 @ 0x10. Referenced by name from
/// entry.asm via `extern BOOT_GDT`.
#[unsafe(no_mangle)]
static BOOT_GDT: [GdtEntry; 3] = [
    GdtEntry::null(),
    GdtEntry::segment32(true, 0).with_base(BOOT_SEG_OFFSET),
    GdtEntry::segment32(false, 0).with_base(BOOT_SEG_OFFSET),
];

// Static tables
static mut GDT: [GdtEntry; GDT_ENTRIES] = [
    GdtEntry::null(),               // 0x00: Null
    GdtEntry::segment32(true, 0),   // 0x08: Kernel Code 32-bit (ring 0)
    GdtEntry::segment64(0),         // 0x10: Kernel Code 64-bit (SYSCALL CS)
    GdtEntry::segment32(false, 0),  // 0x18: Kernel Data (SYSCALL SS)
    GdtEntry::segment32(true, 3),   // 0x20: User Code 32-bit (SYSRET base)
    GdtEntry::segment32(false, 3),  // 0x28: User Data (SYSRET SS)
    GdtEntry::segment64(3),         // 0x30: User Code 64-bit (SYSRET CS)
    GdtEntry::null(),               // 0x38: TSS32 (filled at runtime)
    GdtEntry::null(),               // 0x40: TSS64 low (filled at runtime)
    GdtEntry::null(),               // 0x48: TSS64 high (always null for <4GB)
    GdtEntry::segment32(true, 1),   // 0x50: Ring-1 Code 32-bit (flat, no wrapping yet)
    GdtEntry::segment32(false, 1),  // 0x58: Ring-1 Data (flat, no wrapping yet)
    GdtEntry::null(),               // 0x60: LDT (filled at runtime by load_ldt)
    GdtEntry::null(),               // 0x68: TLS slot 0 (set_thread_area)
    GdtEntry::null(),               // 0x70: TLS slot 1
    GdtEntry::null(),               // 0x78: TLS slot 2
];

static mut IDT32: Idt32 = Idt32 {
    entries: [IdtEntry32::null(); IDT_ENTRIES],
};

static mut IDT64: Idt64 = Idt64 {
    entries: [IdtEntry64::null(); IDT_ENTRIES],
};

pub static mut TSS32: Tss = Tss::new();
pub static mut TSS64: Tss = Tss::new();

// External: unified interrupt vector table from entry.asm.
// Mode-agnostic encoding: the same table serves both IDT32 and IDT64.
unsafe extern "C" {
    static int_vector: [u64; 256];
}

/// Scratch slot for SYSCALL entry to stash user RSP before switching stacks.
#[unsafe(no_mangle)]
static mut SYSCALL_USER_RSP: u64 = 0;

/// Kernel RSP loaded by the SYSCALL entry stub. Kept in sync with TSS64.sp0
/// by `set_kernel_stack_64`.
#[unsafe(no_mangle)]
static mut SYSCALL_KERNEL_RSP: u64 = 0;

/// Set the kernel stack in TSS for 32-bit mode
/// Packs SS:ESP (SS in high 32 bits, ESP in low 32 bits)
pub fn set_kernel_stack(stack: u32) {
    unsafe {
        TSS32.sp0 = ((KERNEL_DS as u64) << 32) | (stack as u64);
    }
}

/// Set the kernel stack in TSS for 64-bit mode
/// Just the raw 64-bit address
pub fn set_kernel_stack_64(stack: u64) {
    unsafe {
        TSS64.sp0 = stack;
        SYSCALL_KERNEL_RSP = stack;
    }
}

/// Setup GDT, IDT, and TSS
pub fn setup_descriptor_tables(kernel_stack_top: u32) {
    unsafe {
        let tss_limit = core::mem::size_of::<Tss>() as u32 - 1;

        // Setup TSS32 with packed SS:ESP, VGA IOPB, and interrupt redirection
        TSS32.sp0 = ((KERNEL_DS as u64) << 32) | (kernel_stack_top as u64);
        setup_vm86_bitmaps(&raw mut TSS32);
        let tss32_addr = core::ptr::addr_of!(TSS32) as u64;
        GDT[GDT_TSS32] = GdtEntry::tss_low(tss32_addr, tss_limit);

        // Setup TSS64 with clean 64-bit address
        TSS64.sp0 = kernel_stack_top as u64;
        let tss64_addr = core::ptr::addr_of!(TSS64) as u64;
        GDT[GDT_TSS64_LO] = GdtEntry::tss_low(tss64_addr, tss_limit);
        // GDT[GDT_TSS64_HI] stays null (base bits 63:32 = 0 for <4GB)

        // Setup 32-bit IDT entries (256 vectors)
        // 0x00-0x1F: CPU exceptions (DPL=0), except 3 (#BP/INT3) and 4 (#OF/INTO)
        //            which are DPL=3 so user `INT3`/`INTO` can reach them. Vector
        //            5 (#BR) is CPU-raised by BOUND and stays DPL=0.
        // 0x20-0x2F: PIC IRQs (DPL=0)
        // 0x30-0xFF: user-callable (DPL=3) — includes 0x80 syscall, 0x31 DPMI, 0xF0 VM86 stubs
        let vector_base_32 = int_vector.as_ptr() as u32;
        for i in 0..256 {
            let dpl = if i == 3 || i == 4 || i >= 0x30 { 3 } else { 0 };
            let handler = vector_base_32 + (i as u32) * 8;
            IDT32.entries[i] = IdtEntry32::interrupt_gate(handler, dpl);
        }

        // Setup 64-bit IDT entries (same vector table, same DPL policy)
        for i in 0..256 {
            let dpl = if i == 3 || i == 4 || i >= 0x30 { 3 } else { 0 };
            let handler = vector_base_32 + (i as u32) * 8;
            IDT64.entries[i] = IdtEntry64::interrupt_gate(handler, dpl);
        }

        // Load GDT
        let gdt_ptr = GdtPtr {
            limit: (core::mem::size_of::<[GdtEntry; GDT_ENTRIES]>() - 1) as u16,
            base: core::ptr::addr_of!(GDT) as u32,
        };
        x86::lgdt(&gdt_ptr);
        x86::reload_segments(KERNEL_DS, KERNEL_CS);
    }

    // Enable VME if supported (hardware-accelerated VM86: CLI/STI/PUSHF/POPF/IRET use VIF)
    let (_, _, _, edx) = x86::cpuid(1);
    if edx & (1 << 1) != 0 {
        unsafe { x86::write_cr4(x86::read_cr4() | x86::cr4::VME); }
        crate::println!("VME enabled");
    } else {
        crate::println!("VME not supported, using software VM86 monitor");
    }

    // Enable SSE for userspace (musl std requires it)
    if edx & (1 << 25) != 0 {
        unsafe {
            // CR4: OSFXSR + OSXMMEXCPT
            x86::write_cr4(x86::read_cr4() | x86::cr4::OSFXSR | x86::cr4::OSXMMEXCPT);
            // CR0: clear EM, set MP, set NE (internal #MF reporting).
            // Without NE, unmasked x87 exceptions report via FERR#/IRQ13 —
            // fine for the host kernel but bypasses DPMI clients' vector 16
            // exception handlers.
            let cr0 = x86::read_cr0();
            x86::write_cr0(((cr0 & !x86::cr0::EM) | x86::cr0::MP) | x86::cr0::NE);
            // Initialize x87 state: BIOS/QEMU may leave the FSW with stale
            // exception flags set, which would fire a spurious #MF at the
            // first WAIT/FPU op in user code.
            core::arch::asm!("fninit", options(nomem, nostack));
        }
        // Snapshot the clean FPU state — new threads are initialized from
        // this template so they don't inherit whatever user code ran last.
        x86::capture_clean_fx_template();
    }

    // Load initial protected mode IDT, TSS, and segments
    load_prot_mode_descriptors();
}

/// Clear the TSS busy bit in GDT (required before reloading TSS with ltr)
unsafe fn clear_tss_busy(gdt_index: usize) {
    // TSS descriptor access byte bit 1 = busy bit
    // Access byte is at offset 5 in the GDT entry
    let entry_ptr = core::ptr::addr_of_mut!(GDT[gdt_index]) as *mut u8;
    let access_ptr = entry_ptr.add(5);
    *access_ptr &= !0x02;
}

/// Load 32-bit IDT, TSS, and reload segments (call when switching to protected mode)
pub fn load_prot_mode_descriptors() {
    unsafe {
        let idt_ptr = IdtPtr {
            limit: (core::mem::size_of::<Idt32>() - 1) as u16,
            base: core::ptr::addr_of!(IDT32) as u32,
        };
        x86::lidt(&idt_ptr);
        clear_tss_busy(GDT_TSS32);
        x86::ltr(TSS32_SEL);
    }
}

/// Load 64-bit IDT and TSS (call when switching to long mode compatibility)
/// Note: We stay on 32-bit CS (0x08) for compatibility mode - don't reload to 64-bit CS
pub fn load_long_mode_descriptors() {
    unsafe {
        let idt_ptr = IdtPtr {
            limit: (core::mem::size_of::<Idt64>() - 1) as u16,
            base: core::ptr::addr_of!(IDT64) as u32,
        };
        x86::lidt(&idt_ptr);
        clear_tss_busy(GDT_TSS64_LO);
        x86::ltr(TSS64_SEL);
        // Don't reload CS - stay on 0x08 (32-bit compat mode)
    }
}

/// Set a per-thread TLS GDT entry. `index` is the GDT slot (13-15).
/// Returns the GDT index on success, or -1 if the index is invalid.
/// If `index` is -1 (0xFFFFFFFF), auto-allocates the first free TLS slot.
pub fn set_tls_entry(index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
    let idx = if index == -1 {
        // Auto-allocate: pick first free (non-present) TLS slot
        let mut found = -1i32;
        unsafe {
            for i in GDT_TLS_START..GDT_TLS_START + 3 {
                if GDT[i].access & 0x80 == 0 { // not Present
                    found = i as i32;
                    break;
                }
            }
        }
        if found < 0 { return -1; }
        found as usize
    } else {
        let i = index as usize;
        if i < GDT_TLS_START || i >= GDT_TLS_START + 3 { return -1; }
        i
    };

    // Build a Ring-3 data segment descriptor with the given base/limit
    let limit_actual = if limit_in_pages { limit & 0xFFFFF } else { limit.min(0xFFFFF) };
    let g_bit: u8 = if limit_in_pages { 0x80 } else { 0 };
    let granularity = g_bit | 0x40 /*D/B=1*/ | ((limit_actual >> 16) as u8 & 0x0F);

    unsafe {
        GDT[idx] = GdtEntry {
            limit_low: limit_actual as u16,
            base_low: base as u16,
            base_mid: (base >> 16) as u8,
            access: 0x80 | (3 << 5) | 0x10 | 0x02, // Present, DPL=3, S=1, Data RW
            granularity,
            base_high: (base >> 24) as u8,
        };
    }

    idx as i32
}

/// Load an LDT: write base+limit into GDT[12] (LDT system descriptor) and execute LLDT.
/// base = linear address of the LDT array, limit = byte size - 1.
pub fn load_ldt(base: u32, limit: u32) {
    unsafe {
        // LDT system descriptor: type = 0x02 (LDT), Present, DPL=0
        GDT[GDT_LDT] = GdtEntry {
            limit_low: limit as u16,
            base_low: base as u16,
            base_mid: (base >> 16) as u8,
            access: 0x82,  // Present(1) | DPL=0 | S=0 | Type=0x2 (LDT)
            granularity: ((limit >> 16) & 0x0F) as u8,
            base_high: (base >> 24) as u8,
        };
        x86::lldt(LDT_SEL);
    }
}

/// Read a raw segment descriptor from the GDT or LDT.
///
/// The selector's TI bit picks the table: TI=0 reads from the GDT, TI=1
/// reads from the current LDT (whose base lives in `GDT[GDT_LDT]`). The
/// DPL and RPL bits are ignored — this is a pure table lookup.
///
/// Returns 0 for the null selector or out-of-range indices.
fn read_descriptor(sel: u16) -> u64 {
    if sel == 0 { return 0; }
    let idx = (sel >> 3) as usize;
    let table_base: u32 = if sel & 4 != 0 {
        // LDT: base encoded in GDT[GDT_LDT] system descriptor
        let g = unsafe { &GDT[GDT_LDT] };
        (g.base_low as u32)
            | ((g.base_mid as u32) << 16)
            | ((g.base_high as u32) << 24)
    } else {
        unsafe { &raw const GDT as *const _ as u32 }
    };
    // Limit is stored in the same descriptor; skip the check and let a bad
    // selector read whatever's there — consistent with the x86 behavior where
    // the monitor is decoding an already-trapped instruction.
    unsafe { core::ptr::read_unaligned((table_base + (idx as u32) * 8) as *const u64) }
}

/// Get the linear base address of the segment referenced by `sel`.
///
/// Works for both GDT and LDT selectors. Flat GDT segments (the kernel/user
/// code/data descriptors set up at boot) have base 0; LDT-resident DPMI
/// segments get their configured base.
pub fn seg_base(sel: u16) -> u32 {
    let desc = read_descriptor(sel);
    let b0 = ((desc >> 16) & 0xFFFF) as u32;
    let b1 = ((desc >> 32) & 0xFF) as u32;
    let b2 = ((desc >> 56) & 0xFF) as u32;
    b0 | (b1 << 16) | (b2 << 24)
}

/// True if the segment's D/B bit is set (32-bit default operand/stack size).
/// The null selector reports true — matches x86 behavior for a flat 32-bit
/// kernel where CS=0 never actually happens.
pub fn seg_is_32(sel: u16) -> bool {
    if sel == 0 { return true; }
    read_descriptor(sel) & (1u64 << 54) != 0
}

// =============================================================================
// Mode switching between protected mode and long mode
// =============================================================================

// External: mode toggle function from entry.asm
unsafe extern "fastcall" {
    fn toggle_prot_compat(new_cr3: u32);
}

/// Toggle between protected mode and long mode (compatibility)
///
/// Switches to the other mode by toggling EFER.LME and loading new page tables.
/// - From protected mode: switches to long mode (compatibility)
/// - From long mode (compat): switches to protected mode
///
/// The appropriate IDT/TSS is loaded based on EFER.LMA after the switch.
///
/// Safety: Requires trampoline copied to 0xF000 and identity-mapped.
pub fn toggle_mode(new_cr3: u32) {
    x86::cli();
    unsafe { toggle_prot_compat(new_cr3); }
    // Reload IDT/TSS based on current mode (check EFER.LMA)
    let efer = x86::rdmsr(x86::EFER_MSR);
    if efer & x86::efer::LMA != 0 {
        load_long_mode_descriptors();
    } else {
        load_prot_mode_descriptors();
    }
    x86::sti();
}

/// SYSCALL/SYSRET MSR addresses
const STAR_MSR: u32 = 0xC0000081;
const LSTAR_MSR: u32 = 0xC0000082;
const FMASK_MSR: u32 = 0xC0000084;

/// Set up SYSCALL MSRs for 64-bit user processes.
/// Call once during init, after GDT/TSS are configured.
pub fn setup_syscall() {
    if !crate::arch::paging2::cpu_supports_long_mode() {
        return;
    }
    unsafe {
        // STAR: bits [47:32] = SYSCALL CS, bits [63:48] = SYSRET base
        // SYSCALL loads CS=STAR[47:32], SS=STAR[47:32]+8
        // SYSRET loads CS=STAR[63:48]|3 (32-bit) or STAR[63:48]+16|3 (64-bit), SS=STAR[63:48]+8|3
        let star = ((USER_CS as u64 & !3) << 48) | ((KERNEL_CS64 as u64) << 32);
        x86::wrmsr(STAR_MSR, star);

        // LSTAR: 64-bit entry point for SYSCALL
        unsafe extern "C" { static syscall_entry_64: u8; }
        let entry_addr = &syscall_entry_64 as *const u8 as u64;
        x86::wrmsr(LSTAR_MSR, entry_addr);

        // FMASK: clear TF|IF|DF|IOPL|NT|AC on SYSCALL entry
        x86::wrmsr(FMASK_MSR, 0x47700);

        // Enable SYSCALL in EFER
        let efer = x86::rdmsr(x86::EFER_MSR);
        x86::wrmsr(x86::EFER_MSR, efer | x86::efer::SCE);

        SYSCALL_KERNEL_RSP = TSS64.sp0;
    }

    crate::println!("SYSCALL enabled");
}

/// Drop from ring 0 to ring 1 in place.
///
/// IRETDs to the next instruction with ring-1 CS/SS selectors and IOPL=1.
pub fn enter_ring1() {
    unsafe {
        core::arch::asm!(
            // Load ring-1 data segments
            "mov ds, {ds:e}",
            "mov es, {ds:e}",
            "mov fs, {ds:e}",
            "mov gs, {ds:e}",
            // Save ESP before pushes — this is the ESP we want after IRET
            "mov {tmp:e}, esp",
            // Build IRET frame: SS, ESP, EFLAGS, CS, EIP
            "push {ss:e}",            // SS = RING1_DS
            "push {tmp:e}",           // ESP = pre-push value (restored by IRET)
            "pushfd",                 // EFLAGS
            "or dword ptr [esp], 0x1000", // set IOPL=1 so ring-1 can do I/O
            "push {cs:e}",            // CS = RING1_CS
            "lea {tmp:e}, [2f]",
            "push {tmp:e}",           // EIP = label after IRET
            "iretd",
            "2:",
            tmp = out(reg) _,
            ss = in(reg) RING1_DS as u32,
            cs = in(reg) RING1_CS as u32,
            ds = in(reg) RING1_DS as u32,
        );
    }
}
