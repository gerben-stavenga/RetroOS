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

/// Metal debug-log sink: emit one byte to the 0xE9 debug port. Installed into
/// the kernel console via `set_debug_sink` so the kernel logs without ever
/// issuing a port op itself.
fn log_byte_0xe9(b: u8) {
    x86::outb(0xE9, b);
}

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

    // Install the kernel's debug-log sink: on metal, a byte to the 0xE9 debug
    // port. Logging is a platform concern, not an arch call — the kernel never
    // touches a port itself; it just hands bytes to this sink.
    crate::vga::set_debug_sink(log_byte_0xe9);

    // Switch to flat GDT (base=0) + IDT + TSS immediately after paging.
    // Offset segments are no longer needed — paging maps KERNEL_BASE to KERNEL_PHYS.
    let arch_stack_top = (&raw const crate::ARCH_STACK_TOP) as u32 - 16;
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

    lib::println!("\x1b[96mRetroOS Rust Kernel\x1b[0m");

    paging2::finish_setup_paging();

    lib::println!("kernel_phys: {:#x}", KERNEL_PHYS);

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

    lib::println!("Physical memory: {:#x} pages free", phys_mm::free_page_count());

    lib::println!("Memory regions: {}", mmap_count);
    for entry in mmap_entries {
        if entry.typ == 1 {
            let base = entry.base;
            let length = entry.length;
            lib::println!("  Available: {:#x} - {:#x}", base, base + length);
        }
    }

    irq::init_interrupts();
    lib::println!("Interrupts initialized");

    if paging2::cpu_supports_long_mode() {
        paging2::sync_hw_pdpt();
        x86::flush_tlb();
        let saved = paging2::ensure_trampoline_mapped();
        descriptors::toggle_mode(paging2::toggle_cr3(true));
        paging2::clear_trampoline(saved);
        lib::println!("Switched to Compat mode");
    }

    x86::sti();
    lib::println!("Interrupts enabled");

    // Install stack guard pages: unmap the page directly below each stack
    // so any overflow takes a clean #PF (caught and labeled in
    // try_handle_page_fault) instead of silently corrupting adjacent
    // memory. Must be done at ring 0 because entries() reads CR4.
    let kstack_guard = (&raw const crate::KERNEL_STACK_GUARD) as usize;
    let astack_guard = (&raw const crate::ARCH_STACK_GUARD) as usize;
    paging2::unmap_kernel_page(kstack_guard);
    paging2::unmap_kernel_page(astack_guard);
    lib::println!("Stack guards at {:#x} (kernel) {:#x} (arch)", kstack_guard, astack_guard);

    lib::println!();
    lib::println!("\x1b[92mHello from Rust kernel!\x1b[0m");

    // Read the boot config (QEMU fw_cfg) at the platform boundary, before
    // handing it to the kernel — the kernel no longer pokes firmware ports.
    let config = read_boot_config();

    descriptors::enter_ring1();

    // The arch backend handle, threaded as `&mut` through the kernel from here
    // on so its mutable state is borrow-checked rather than global. Lives for
    // the rest of the kernel's life (startup never returns).
    let mut machine = crate::new_arch();
    crate::kernel::startup::startup(&mut machine, &config);
}

/// Read QEMU's fw_cfg interface into a `BootConfig` (headless cmdline/cwd,
/// debug-watch, is-QEMU signature). Absent fw_cfg (Bochs / real hardware) reads
/// 0xFF → no QEMU signature → an empty interactive config. Port I/O is a real
/// `out`/`in` here in the metal boot glue, so the kernel never touches it.
fn read_boot_config() -> crate::BootConfig {
    const SEL: u16 = 0x510;
    const DATA: u16 = 0x511;
    fn select(sel: u16) { x86::outw(SEL, sel); }
    fn read_bytes(buf: &mut [u8]) { for b in buf.iter_mut() { *b = x86::inb(DATA); } }
    // Find a named fw_cfg file via the file directory (selector 0x0019), select
    // it, and read up to `buf.len()` bytes. Returns the byte count read.
    fn read_named(name: &[u8], buf: &mut [u8]) -> Option<usize> {
        select(0x0019);
        let mut count_be = [0u8; 4];
        read_bytes(&mut count_be);
        let count = u32::from_be_bytes(count_be);
        for _ in 0..count {
            let mut entry = [0u8; 64];
            read_bytes(&mut entry);
            let size = u32::from_be_bytes(entry[0..4].try_into().unwrap()) as usize;
            let sel = u16::from_be_bytes(entry[4..6].try_into().unwrap());
            let name_end = entry[8..].iter().position(|&c| c == 0).unwrap_or(56);
            if &entry[8..8 + name_end] == name {
                let n = size.min(buf.len());
                select(sel);
                read_bytes(&mut buf[..n]);
                return Some(n);
            }
        }
        None
    }

    let mut cfg = crate::BootConfig::empty();
    select(0x0000); // FW_CFG_SIGNATURE
    let mut sig = [0u8; 4];
    read_bytes(&mut sig);
    cfg.is_qemu = &sig == b"QEMU";
    if !cfg.is_qemu {
        return cfg; // no fw_cfg interface — interactive boot
    }
    let mut buf = [0u8; 4096];
    if let Some(n) = read_named(b"opt/cmdline", &mut buf) { cfg.set_cmdline(&buf[..n]); }
    let mut cwd = [0u8; 256];
    if let Some(n) = read_named(b"opt/cwd", &mut cwd) { cfg.set_cwd(&cwd[..n]); }
    let mut dw = [0u8; 64];
    if let Some(n) = read_named(b"opt/debug-watch", &mut dw) {
        cfg.debug_watch = crate::parse_debug_watch(&dw[..n]);
    }
    cfg
}
