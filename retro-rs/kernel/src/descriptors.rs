//! GDT, IDT, and TSS setup for x86
//!
//! Segment selectors:
//! - 0x08: Kernel Code 32-bit (ring 0)
//! - 0x10: Kernel Data (ring 0)
//! - 0x18: Kernel Code 64-bit (ring 0)
//! - 0x20: User Code 32-bit (ring 3)
//! - 0x28: User Data (ring 3)
//! - 0x30: User Code 64-bit (ring 3)
//! - 0x38: TSS32 (8 bytes - 32-bit descriptor)
//! - 0x40: TSS64 (16 bytes - 0x40 + 0x48)

use crate::x86::{self, GdtPtr, IdtPtr};

/// Segment selectors - 32-bit (compatibility mode)
pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_CS: u16 = 0x20 | 3; // Ring 3
pub const USER_DS: u16 = 0x28 | 3; // Ring 3
pub const TSS32_SEL: u16 = 0x38;

/// Segment selectors - 64-bit (long mode)
pub const KERNEL_CS64: u16 = 0x18;
pub const USER_CS64: u16 = 0x30 | 3; // Ring 3
pub const TSS64_SEL: u16 = 0x40;

/// Number of IDT entries (0-48 for exceptions/IRQs, 0x80 for syscall)
const IDT_ENTRIES: usize = 0x81;

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

/// Unified Task State Segment (104 bytes)
/// Works for both 32-bit and 64-bit modes:
/// - 32-bit: CPU reads ESP0 from low 32 bits, SS0 from high 32 bits of sp0
/// - 64-bit: CPU reads RSP0 as full 64 bits of sp0
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
    _io_map_base: u16,       // offset 102
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
            _io_map_base: 104, // Points past TSS = no I/O bitmap
        }
    }
}

/// GDT entry indices
const GDT_NULL: usize = 0;        // 0x00
const GDT_KERNEL_CS: usize = 1;   // 0x08
const GDT_KERNEL_DS: usize = 2;   // 0x10
const GDT_KERNEL_CS64: usize = 3; // 0x18
const GDT_USER_CS: usize = 4;     // 0x20
const GDT_USER_DS: usize = 5;     // 0x28
const GDT_USER_CS64: usize = 6;   // 0x30
const GDT_TSS32: usize = 7;       // 0x38
const GDT_TSS64_LO: usize = 8;    // 0x40
const GDT_TSS64_HI: usize = 9;    // 0x48 (null - upper 32 bits of base are 0)

const GDT_ENTRIES: usize = 10;

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

// Static tables
static mut GDT: [GdtEntry; GDT_ENTRIES] = [
    GdtEntry::null(),               // 0x00: Null
    GdtEntry::segment32(true, 0),   // 0x08: Kernel Code 32-bit
    GdtEntry::segment32(false, 0),  // 0x10: Kernel Data
    GdtEntry::segment64(0),         // 0x18: Kernel Code 64-bit
    GdtEntry::segment32(true, 3),   // 0x20: User Code 32-bit
    GdtEntry::segment32(false, 3),  // 0x28: User Data
    GdtEntry::segment64(3),         // 0x30: User Code 64-bit
    GdtEntry::null(),               // 0x38: TSS32 (filled at runtime)
    GdtEntry::null(),               // 0x40: TSS64 low (filled at runtime)
    GdtEntry::null(),               // 0x48: TSS64 high (always null for <4GB)
];

static mut IDT32: Idt32 = Idt32 {
    entries: [IdtEntry32::null(); IDT_ENTRIES],
};

static mut IDT64: Idt64 = Idt64 {
    entries: [IdtEntry64::null(); IDT_ENTRIES],
};

pub static mut TSS32: Tss = Tss::new();
pub static mut TSS64: Tss = Tss::new();

// External: interrupt vector tables from entry.asm
unsafe extern "C" {
    static int_vector: [u64; 49];      // 32-bit handlers
    static int_vector_64: [u64; 49];   // 64-bit handlers
}

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
    }
}

/// Setup GDT, IDT, and TSS
pub fn setup_descriptor_tables(kernel_stack_top: u32) {
    unsafe {
        let tss_limit = core::mem::size_of::<Tss>() as u32 - 1;

        // Setup TSS32 with packed SS:ESP
        TSS32.sp0 = ((KERNEL_DS as u64) << 32) | (kernel_stack_top as u64);
        let tss32_addr = core::ptr::addr_of!(TSS32) as u64;
        GDT[GDT_TSS32] = GdtEntry::tss_low(tss32_addr, tss_limit);

        // Setup TSS64 with clean 64-bit address
        TSS64.sp0 = kernel_stack_top as u64;
        let tss64_addr = core::ptr::addr_of!(TSS64) as u64;
        GDT[GDT_TSS64_LO] = GdtEntry::tss_low(tss64_addr, tss_limit);
        // GDT[GDT_TSS64_HI] stays null (base bits 63:32 = 0 for <4GB)

        // Setup 32-bit IDT entries
        let vector_base_32 = int_vector.as_ptr() as u32;
        for i in 0..48 {
            let dpl = if (3..=5).contains(&i) { 3 } else { 0 };
            let handler = vector_base_32 + (i as u32) * 8;
            IDT32.entries[i] = IdtEntry32::interrupt_gate(handler, dpl);
        }
        let syscall_handler_32 = vector_base_32 + 48 * 8;
        IDT32.entries[0x80] = IdtEntry32::interrupt_gate(syscall_handler_32, 3);

        // Setup 64-bit IDT entries
        let vector_base_64 = int_vector_64.as_ptr() as u32;
        for i in 0..48 {
            let dpl = if (3..=5).contains(&i) { 3 } else { 0 };
            let handler = vector_base_64 + (i as u32) * 8;
            IDT64.entries[i] = IdtEntry64::interrupt_gate(handler, dpl);
        }
        let syscall_handler_64 = vector_base_64 + 48 * 8;
        IDT64.entries[0x80] = IdtEntry64::interrupt_gate(syscall_handler_64, 3);

        // Load GDT
        let gdt_ptr = GdtPtr {
            limit: (core::mem::size_of::<[GdtEntry; GDT_ENTRIES]>() - 1) as u16,
            base: core::ptr::addr_of!(GDT) as u32,
        };
        x86::lgdt(&gdt_ptr);

        x86::reload_segments(KERNEL_DS, KERNEL_CS);
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
    /// Reload IDT/TSS based on current mode (check EFER.LMA)
    let efer = x86::rdmsr(x86::EFER_MSR);
    if efer & x86::efer::LMA != 0 {
        load_long_mode_descriptors();
    } else {
        load_prot_mode_descriptors();
    }
    x86::sti()
}
