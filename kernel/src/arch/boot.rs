//! Kernel boot sequence (ring 0)
//!
//! Entry flow:
//! 1. _entry (asm stub: offset GDT, kernel stack, calls PrepareKernel)
//! 2. PrepareKernel (enables paging, initializes kernel, drops to ring 1)

use super::{paging2, phys_mm, descriptors, irq, x86};
use crate::{vga, println};
use paging2::{PAGE_SIZE, LOW_MEM_BASE};

/// Kernel physical load address (must match KERNEL_PHYS in kernel.ld)
pub const KERNEL_PHYS: usize = 0x0010_0000;

// Linker symbols
unsafe extern "C" {
    static _start: u8;
    static _end: u8;
}

/// PrepareKernel - Entry point called by asm boot stub
///
/// Runs with offset segments (base = KERNEL_PHYS - KERNEL_BASE) so linked
/// addresses access physical memory correctly. Paging is off on entry.
/// Stack is already set to KERNEL_STACK by the asm stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PrepareKernel(boot_data: *const crate::BootData) -> ! {
    let kernel_size = unsafe {
        core::ptr::addr_of!(_end) as usize - core::ptr::addr_of!(_start) as usize
    };
    let kernel_pages = (kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;

    // Enable paging (auto-detects Legacy vs PAE)
    // With offset segments, linked pointers work directly — no delta adjustment needed
    unsafe {
        paging2::enable_paging(
            &raw mut crate::KERNEL_PAGES,
            &raw mut crate::SCRATCH,
            KERNEL_PHYS,
            kernel_pages,
        );
    }
    // Update VGA base for paged addressing before any println
    vga::vga().base = LOW_MEM_BASE + 0xB8000;

    // Switch to flat GDT (base=0) + IDT + TSS immediately after paging.
    // Offset segments are no longer needed — paging maps KERNEL_BASE to KERNEL_PHYS.
    #[allow(static_mut_refs)]
    let arch_stack_top = unsafe { crate::ARCH_STACK.top() as u32 } - 16;
    descriptors::setup_descriptor_tables(arch_stack_top);

    // boot_data is in low memory — access through LOW_MEM_BASE mapping
    let boot_data = unsafe { &*((boot_data as usize + LOW_MEM_BASE) as *const crate::BootData) };

    println!("\x1b[96mRetroOS Rust Kernel\x1b[0m");

    paging2::finish_setup_paging();

    println!("kernel_phys: {:#x}", KERNEL_PHYS);

    let kernel_low_page = (KERNEL_PHYS / PAGE_SIZE) as u64;
    let kernel_high_page = ((KERNEL_PHYS + kernel_size + PAGE_SIZE - 1) / PAGE_SIZE) as u64;

    phys_mm::init_phys_mm(
        &boot_data.mmap_entries,
        boot_data.mmap_count as usize,
        kernel_low_page,
        kernel_high_page,
    );

    println!("Physical memory: {:#x} pages free", phys_mm::free_page_count());

    paging2::init_temp_map();

    crate::kernel::heap::init();
    println!("Heap initialized");

    println!("Memory regions: {}", boot_data.mmap_count);
    for i in 0..boot_data.mmap_count as usize {
        if i >= 32 { break; }
        let entry = boot_data.mmap_entries[i];
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

    crate::kernel::startup::startup(boot_data.start_sector);
}
