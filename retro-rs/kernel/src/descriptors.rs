//! GDT, IDT, and TSS setup for x86
//!
//! Segment selectors:
//! - 0x08: Kernel Code (ring 0)
//! - 0x10: Kernel Data (ring 0)
//! - 0x18: User Code (ring 3)
//! - 0x20: User Data (ring 3)
//! - 0x28: TSS

use crate::x86::{self, GdtPtr, IdtPtr};

/// Segment selectors
pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_CS: u16 = 0x18 | 3; // Ring 3
pub const USER_DS: u16 = 0x20 | 3; // Ring 3
pub const TSS_SEL: u16 = 0x28;

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

    /// Create a segment descriptor
    /// is_code: true for code segment, false for data segment
    /// dpl: privilege level (0 = kernel, 3 = user)
    const fn segment(is_code: bool, dpl: u8) -> Self {
        // Access byte: Present(1) | DPL(2) | S=1 | Type(4)
        // Type: Execute(1) | DC(0) | RW(1) | Accessed(0)
        let type_bits = if is_code { 0b1010 } else { 0b0010 };
        let access = 0x80 | ((dpl & 3) << 5) | 0x10 | type_bits;

        // Granularity: G(1) | D/B(1) | L(0) | AVL(0) | Limit_high(4)
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

    /// Create a TSS descriptor
    fn tss(base: u32, limit: u32) -> Self {
        // Access: Present(1) | DPL=0 | S=0 | Type=0x9 (32-bit TSS available)
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

/// IDT entry (8 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    zero: u8,
    type_attr: u8,
    offset_high: u16,
}

impl IdtEntry {
    const fn null() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            zero: 0,
            type_attr: 0,
            offset_high: 0,
        }
    }

    /// Create an interrupt gate
    /// dpl: 0 = kernel only, 3 = user callable (for syscalls, breakpoint)
    fn interrupt_gate(handler: u32, dpl: u8) -> Self {
        // Type: Present(1) | DPL(2) | 0 | Type(4)
        // Type = 0xE for 32-bit interrupt gate
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

/// Task State Segment (104 bytes)
#[repr(C, packed)]
pub struct Tss {
    _link: u32,
    pub esp0: u32,  // Kernel stack pointer
    pub ss0: u32,   // Kernel stack segment
    _unused: [u32; 22],
    _trap: u16,
    _io_map_base: u16,
}

impl Tss {
    const fn new() -> Self {
        Self {
            _link: 0,
            esp0: 0,
            ss0: KERNEL_DS as u32,
            _unused: [0; 22],
            _trap: 0,
            _io_map_base: 104, // Points past TSS = no I/O bitmap
        }
    }
}

/// Global Descriptor Table
#[repr(C, align(8))]
struct Gdt {
    entries: [GdtEntry; 6],
}

/// Interrupt Descriptor Table
#[repr(C, align(8))]
struct Idt {
    entries: [IdtEntry; IDT_ENTRIES],
}

// Static tables
static mut GDT: Gdt = Gdt {
    entries: [
        GdtEntry::null(),              // 0x00: Null
        GdtEntry::segment(true, 0),    // 0x08: Kernel Code
        GdtEntry::segment(false, 0),   // 0x10: Kernel Data
        GdtEntry::segment(true, 3),    // 0x18: User Code
        GdtEntry::segment(false, 3),   // 0x20: User Data
        GdtEntry::null(),              // 0x28: TSS (filled at runtime)
    ],
};

static mut IDT: Idt = Idt {
    entries: [IdtEntry::null(); IDT_ENTRIES],
};

#[unsafe(no_mangle)]
pub static mut TSS: Tss = Tss::new();

// External: interrupt vector table from entry.asm
unsafe extern "C" {
    static int_vector: [u64; 49];
}

/// Set the kernel stack in TSS (called on task switch)
pub fn set_kernel_stack(stack: u32) {
    unsafe {
        TSS.esp0 = stack;
    }
}

/// Setup GDT, IDT, and TSS
pub fn setup_descriptor_tables(kernel_stack_top: u32) {
    unsafe {
        // Setup TSS with kernel stack
        TSS.esp0 = kernel_stack_top;

        // Add TSS descriptor to GDT
        let tss_addr = core::ptr::addr_of!(TSS) as u32;
        GDT.entries[5] = GdtEntry::tss(tss_addr, core::mem::size_of::<Tss>() as u32 - 1);

        // Setup IDT entries
        let vector_base = int_vector.as_ptr() as u32;

        // CPU exceptions (0-31) and IRQs (32-47)
        for i in 0..48 {
            // DPL 3 for int3 (3), into (4), bounds (5) - user can trigger these
            let dpl = if (3..=5).contains(&i) { 3 } else { 0 };
            let handler = vector_base + (i as u32) * 8;
            IDT.entries[i] = IdtEntry::interrupt_gate(handler, dpl);
        }

        // Syscall interrupt 0x80 (user callable)
        let syscall_handler = vector_base + 48 * 8;
        IDT.entries[0x80] = IdtEntry::interrupt_gate(syscall_handler, 3);

        // Load GDT
        let gdt_ptr = GdtPtr {
            limit: (core::mem::size_of::<Gdt>() - 1) as u16,
            base: core::ptr::addr_of!(GDT) as u32,
        };
        x86::lgdt(&gdt_ptr);

        // Load IDT
        let idt_ptr = IdtPtr {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base: core::ptr::addr_of!(IDT) as u32,
        };
        x86::lidt(&idt_ptr);

        // Load TSS
        x86::ltr(TSS_SEL);

        // Reload segment registers
        x86::reload_segments(KERNEL_DS, KERNEL_CS);
    }
}
