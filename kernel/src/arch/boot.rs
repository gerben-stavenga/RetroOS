//! Kernel boot sequence (ring 0)
//!
//! Entry flow:
//! 1. _start (asm stub: offset GDT, kernel stack, calls boot_kernel)
//! 2. boot_kernel (enables paging, initializes kernel, drops to ring 1)

use arch::{paging2, phys_mm, descriptors, irq, x86};
use crate::vga;
use arch::MultibootMmapEntry;
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

// Pre-paging copies of the multiboot info + memory map. GRUB may place them
// anywhere below 4GB, but after enable_paging only the first 1MB of physical
// memory stays reachable (LOW_MEM_BASE window) — assuming the MBI sits there
// reads garbage on machines where it doesn't. Copy both while the offset
// segments can still address all 32-bit physical memory.
static mut BOOT_INFO: arch::MultibootInfo = unsafe { core::mem::zeroed() };
static mut BOOT_MMAP: [MultibootMmapEntry; 128] =
    [MultibootMmapEntry { size: 0, base: 0, length: 0, typ: 0 }; 128];
static mut BOOT_MMAP_LEN: usize = 0;

/// Physical address P is reachable pre-paging at P + (KERNEL_BASE -
/// KERNEL_PHYS), wrapping (the boot GDT's offset segments).
const PHYS_TO_SEG: usize = paging2::KERNEL_BASE - KERNEL_PHYS;

/// Copy the multiboot info + memory map into kernel statics. Pre-paging only.
unsafe fn capture_boot_info(info: *const arch::MultibootInfo) {
    let src = (info as usize).wrapping_add(PHYS_TO_SEG) as *const arch::MultibootInfo;
    let inf = unsafe { core::ptr::read_unaligned(src) };
    if inf.flags & (1 << 6) != 0 {
        let count = (inf.mmap_length as usize / core::mem::size_of::<MultibootMmapEntry>())
            .min(128);
        let m = (inf.mmap_addr as usize).wrapping_add(PHYS_TO_SEG)
            as *const MultibootMmapEntry;
        let dst = unsafe { &mut *(&raw mut BOOT_MMAP) };
        for i in 0..count {
            dst[i] = unsafe { core::ptr::read_unaligned(m.add(i)) };
        }
        unsafe { BOOT_MMAP_LEN = count };
    }
    unsafe { BOOT_INFO = inf };
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
pub unsafe extern "C" fn boot_kernel(magic: u32, info: *const arch::MultibootInfo) -> ! {
    // FIRST life sign, before paging: paint a strip into the framebuffer the
    // loader handed us. On real hardware there is no debug port and no
    // display until fbcon::init — a kernel that dies in early init reboots
    // with a black screen and zero evidence. The strip separates "GRUB never
    // entered the kernel" from "kernel died during init". Pre-paging we run
    // on offset segments (base = KERNEL_PHYS - KERNEL_BASE), so a physical
    // address P is reached at P + (KERNEL_BASE - KERNEL_PHYS), wrapping.
    unsafe { capture_boot_info(info) };

    let kernel_size =
        core::ptr::addr_of!(_end) as usize - core::ptr::addr_of!(_kernel_start) as usize
    ;
    let kernel_pages = (kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;

    // Enable paging (auto-detects Legacy vs PAE)
    // With offset segments, linked pointers work directly — no delta adjustment needed
    paging2::enable_paging(
        &raw mut arch::SCRATCH,
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

    // The multiboot info was copied into kernel statics pre-paging (GRUB may
    // place the original anywhere below 4GB; only low 1MB is mapped now).
    let info = unsafe { &*(&raw const BOOT_INFO) };

    // UEFI-class machine (loader handed us a linear framebuffer, there is no
    // VGA text mode): console cells go to a RAM buffer instead of B8000.
    // Pixels start flowing at `fbcon::init` below; cells written until then
    // are rendered as backlog.
    crate::fbcon::early(info);

    lib::println!("\x1b[96mRetroOS Rust Kernel\x1b[0m");

    paging2::finish_setup_paging();

    lib::println!("kernel_phys: {:#x}", KERNEL_PHYS);

    let kernel_low_page = (KERNEL_PHYS / PAGE_SIZE) as u64;
    let kernel_high_page = ((KERNEL_PHYS + kernel_size + PAGE_SIZE - 1) / PAGE_SIZE) as u64;

    // Parse Multiboot memory map (the pre-paging copy)
    assert!(info.flags & (1 << 6) != 0, "No Multiboot memory map");
    let mmap_count = unsafe { BOOT_MMAP_LEN };
    let mmap_entries: &[MultibootMmapEntry] =
        unsafe { &(&*(&raw const BOOT_MMAP))[..mmap_count] };

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

    // GOP machines: map the framebuffer and render the boot backlog NOW —
    // as early as its dependencies allow (the IDT for the COW page-table
    // faults, phys_mm for the frames) — so every later init phase can paint
    // its panics. The mappings land in the dual-use PDPT page that the
    // compat-mode toggle below reuses, so they survive the switch.
    crate::fbcon::init(info);

    irq::init_interrupts();
    lib::println!("Interrupts initialized");

    // The compat-mode switch was a test harness to force the experimental
    // x64/long-mode path — the kernel normally runs PAE 32-bit. On a real CPU
    // (KVM/metal) it switches to long mode and the first IRQ through the 64-bit
    // IDT triple-faults (TCG was hiding it); flip this on only to exercise x64.
    const ENTER_COMPAT_MODE: bool = false;
    if ENTER_COMPAT_MODE && paging2::cpu_supports_long_mode() {
        paging2::sync_hw_pdpt();
        x86::flush_tlb();
        let saved = paging2::ensure_trampoline_mapped();
        descriptors::toggle_mode(paging2::toggle_cr3(true));
        paging2::clear_trampoline(saved);
        lib::println!("Switched to Compat mode");
    }

    // Interrupts are enabled by `enter_ring1` (it sets IF in the IRET frame it
    // builds) — the kernel side never touches `sti`/`cli`.

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

    // Diagnostic: with IF still 0, dump the timer chain to the VGA console so a
    // freeze-at-first-IRQ on real hardware is readable instead of a black hang.
    irq::timer_selftest();

    descriptors::enter_ring1();

    lib::println!("Ring1 entered, paging + interrupts + syscall setup complete");

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
