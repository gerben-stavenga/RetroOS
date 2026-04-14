//! Kernel boot sequence (ring 0)
//!
//! Entry flow:
//! 1. _start (asm stub: offset GDT, kernel stack, calls boot_kernel)
//! 2. boot_kernel (enables paging, initializes kernel, drops to ring 1)

use super::{paging2, phys_mm, descriptors, irq, x86};
use crate::{vga, println, MultibootMmapEntry};
use paging2::{PAGE_SIZE, LOW_MEM_BASE};

/// Kernel physical load address (must match KERNEL_PHYS in kernel.ld)
pub const KERNEL_PHYS: usize = 0x0010_0000;

/// Magic value the Multiboot bootloader places in EAX before jumping to us.
const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;

// Linker symbols
unsafe extern "C" {
    static _kernel_start: u8;
    static _end: u8;
}

/// boot_kernel - Entry point called by asm boot stub
///
/// Runs with offset segments (base = KERNEL_PHYS - KERNEL_BASE) so linked
/// addresses access physical memory correctly. Paging is off on entry.
/// Stack is already set to KERNEL_STACK by the asm stub.
///
/// `magic` is the Multiboot bootloader magic (EAX on entry).
/// `info` is a Multiboot info pointer (physical address, in low memory).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boot_kernel(magic: u32, info: *const crate::MultibootInfo) -> ! {
    let kernel_size =
        core::ptr::addr_of!(_end) as usize - core::ptr::addr_of!(_kernel_start) as usize
    ;
    let kernel_pages = (kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;

    // Enable paging (auto-detects Legacy vs PAE)
    // With offset segments, linked pointers work directly — no delta adjustment needed
    paging2::enable_paging(
        &raw mut crate::SCRATCH,
        KERNEL_PHYS,
        kernel_pages,
    );
    // Update VGA base for paged addressing before any println
    vga::vga().base = LOW_MEM_BASE + 0xB8000;

    // Switch to flat GDT (base=0) + IDT + TSS immediately after paging.
    // Offset segments are no longer needed — paging maps KERNEL_BASE to KERNEL_PHYS.
    #[allow(static_mut_refs)]
    let arch_stack_top = unsafe { crate::ARCH_STACK.top() as u32 } - 16;
    descriptors::setup_descriptor_tables(arch_stack_top);
    descriptors::setup_syscall();

    // Verify the bootloader is Multiboot-compliant before touching info.
    assert!(
        magic == MULTIBOOT_BOOTLOADER_MAGIC,
        "Bad Multiboot magic: {:#x} (expected {:#x})",
        magic, MULTIBOOT_BOOTLOADER_MAGIC
    );

    // Multiboot info is in low memory — access through LOW_MEM_BASE mapping
    let info = unsafe { &*((info as usize + LOW_MEM_BASE) as *const crate::MultibootInfo) };

    println!("\x1b[96mRetroOS Rust Kernel\x1b[0m");

    paging2::finish_setup_paging();

    println!("kernel_phys: {:#x}", KERNEL_PHYS);

    let kernel_low_page = (KERNEL_PHYS / PAGE_SIZE) as u64;
    let kernel_high_page = ((KERNEL_PHYS + kernel_size + PAGE_SIZE - 1) / PAGE_SIZE) as u64;

    // Parse Multiboot memory map
    assert!(info.flags & (1 << 6) != 0, "No Multiboot memory map");
    let mmap_addr = (info.mmap_addr as usize + LOW_MEM_BASE) as *const MultibootMmapEntry;
    let mmap_length = info.mmap_length as usize;
    let entry_size = core::mem::size_of::<MultibootMmapEntry>();
    let mmap_count = mmap_length / entry_size;
    let mmap_entries = unsafe { core::slice::from_raw_parts(mmap_addr, mmap_count) };

    phys_mm::init_phys_mm(
        mmap_entries,
        mmap_count,
        kernel_low_page,
        kernel_high_page,
    );

    println!("Physical memory: {:#x} pages free", phys_mm::free_page_count());

    crate::kernel::heap::init();
    println!("Heap initialized");

    println!("Memory regions: {}", mmap_count);
    for entry in mmap_entries {
        if entry.typ == 1 {
            let base = entry.base;
            let length = entry.length;
            println!("  Available: {:#x} - {:#x}", base, base + length);
        }
    }

    irq::init_interrupts();
    println!("Interrupts initialized");

    if paging2::cpu_supports_long_mode() {
        paging2::sync_hw_pdpt();
        x86::flush_tlb();
        let saved = paging2::ensure_trampoline_mapped();
        descriptors::toggle_mode(paging2::toggle_cr3(true));
        paging2::clear_trampoline(saved);
        println!("Switched to Compat mode");
    }

    x86::sti();
    println!("Interrupts enabled");

    println!();
    println!("\x1b[92mHello from Rust kernel!\x1b[0m");

    descriptors::enter_ring1();

    crate::kernel::startup::startup();
}
