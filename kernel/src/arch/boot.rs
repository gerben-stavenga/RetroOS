//! Kernel boot sequence (ring 0)
//!
//! Entry flow:
//! 1. _start (asm stub: offset GDT, kernel stack, calls boot_kernel)
//! 2. boot_kernel (enables paging, initializes kernel, drops to ring 1)

use arch::{paging2, phys_mm, descriptors, irq, x86};
use arch::MultibootMmapEntry;
use paging2::{PAGE_SIZE, LOW_MEM_BASE};

/// Kernel physical load address (must match KERNEL_PHYS in kernel.ld)
pub const KERNEL_PHYS: usize = 0x0010_0000;

/// The kernel's global allocator on metal: the freestanding demand-paged heap
/// algorithm (`lib::heap::DemandHeap`), bound here in the binary-side boot glue.
/// Hosted builds don't compile `boot.rs` at all and use std's allocator, so the
/// kernel crate itself stays allocator-agnostic (no `#[global_allocator]`, no
/// `cfg`). The heap VA window and its first-touch `#PF` page-backing are
/// arch-owned (`arch::{heap_base, HEAP_END}` + the metal `#PF` handler); this is
/// only the binding and its one-time `init()` call site (below, before startup).
#[global_allocator]
static ALLOCATOR: lib::heap::DemandHeap = lib::heap::DemandHeap::new();

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

/// Physical address P is reachable pre-paging at P + (KERNEL_BASE -
/// KERNEL_PHYS), wrapping (the boot GDT's offset segments).
const PHYS_TO_SEG: usize = paging2::KERNEL_BASE - KERNEL_PHYS;

/// Copy the multiboot info, memory map, and command line out of wherever GRUB
/// left them (anywhere below 4GB) before paging restricts us to the low-1MB
/// window. Returns the owned info plus the number of map and command-line bytes
/// written. The copies live as `boot_kernel` locals — the only reader is the
/// rest of `boot_kernel`, so there is no need for a global.
/// Pre-paging only; the caller's stack frame holds the copies across the paging
/// switch (the stack's linked address is mapped identically before and after).
unsafe fn capture_boot_info(
    info: *const arch::MultibootInfo,
    mmap_out: &mut [MultibootMmapEntry; 128],
    cmdline_out: &mut [u8],
) -> (arch::MultibootInfo, usize, usize) {
    let src = (info as usize).wrapping_add(PHYS_TO_SEG) as *const arch::MultibootInfo;
    let inf = unsafe { core::ptr::read_unaligned(src) };
    let mut count = 0;
    if inf.flags & (1 << 6) != 0 {
        count = (inf.mmap_length as usize / core::mem::size_of::<MultibootMmapEntry>())
            .min(128);
        let m = (inf.mmap_addr as usize).wrapping_add(PHYS_TO_SEG)
            as *const MultibootMmapEntry;
        for (i, slot) in mmap_out.iter_mut().enumerate().take(count) {
            *slot = unsafe { core::ptr::read_unaligned(m.add(i)) };
        }
    }
    let mut cmdline_len = 0;
    if inf.flags & (1 << 2) != 0 && inf.cmdline != 0 {
        let command = (inf.cmdline as usize).wrapping_add(PHYS_TO_SEG) as *const u8;
        while cmdline_len < cmdline_out.len() {
            let b = unsafe { core::ptr::read_volatile(command.add(cmdline_len)) };
            if b == 0 { break; }
            cmdline_out[cmdline_len] = b;
            cmdline_len += 1;
        }
    }
    (inf, count, cmdline_len)
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
    let mut mmap_buf = [MultibootMmapEntry { size: 0, base: 0, length: 0, typ: 0 }; 128];
    let mut boot_cmdline = [0u8; 512];
    let (boot_info, mmap_count, boot_cmdline_len) =
        unsafe { capture_boot_info(info, &mut mmap_buf, &mut boot_cmdline) };
    let info = &boot_info;

    let kernel_size =
        core::ptr::addr_of!(_end) as usize - core::ptr::addr_of!(_kernel_start) as usize
    ;
    let kernel_pages = kernel_size.div_ceil(PAGE_SIZE);

    // Enable paging (auto-detects Legacy vs PAE)
    // With offset segments, linked pointers work directly — no delta adjustment needed
    paging2::enable_paging(
        &raw mut arch::SCRATCH,
        KERNEL_PHYS,
        kernel_pages,
    );

    // The text aperture moves with paging: point the terminal at the mapped
    // low-memory B8000 before anything prints. Its grid comes along, so what
    // the bootloader already put on screen survives the move.
    lib::term::term().set_aperture(Some(LOW_MEM_BASE + 0xB8000));

    // The shared log ring uses kernel-owned static storage, so it is available
    // before the heap and captures the interrupt/device bring-up below.
    crate::kernel::klog::init();

    // Install the kernel's debug-log sink: on metal, a byte to the 0xE9 debug
    // port. Logging is a platform concern, not an arch call — the kernel never
    // touches a port itself; it just hands bytes to this sink.
    lib::log::set_debug_sink(log_byte_0xe9);
    // Inject the metal backend into the (backend-agnostic) kernel: port I/O
    // for the deep driver call sites, and the host-environment facts the
    // platform probe reads (real 0xE9 debugcon, GOP fbcon detection, metal).
    crate::install_portio(crate::PortIo {
        inb: arch::inb, inw: arch::inw, inl: arch::inl, insw: arch::insw,
        outb: arch::outb, outw: arch::outw, outl: arch::outl, outsw: arch::outsw,
    });
    crate::kernel::display::set_present_hook(crate::fbcon::present);
    crate::set_host_env(crate::HostEnv {
        framebuffer: crate::fbcon::framebuffer,
        debug: crate::DebugSink::Debugcon,
        is_metal: true,
    });

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

    // UEFI-class machine (loader handed us a linear framebuffer, there is no
    // VGA text mode): console cells go to a RAM buffer instead of B8000.
    // Pixels start flowing at `fbcon::init` below; cells written until then
    // are rendered as backlog.
    crate::fbcon::early(info);

    // Nothing else is running yet, so there is no display to arbitrate: write
    // to the terminal directly. Once `startup` builds a `Console`, on-screen
    // kernel text needs that value; ambient println! stays log-only throughout.
    let mut screen = lib::term::term();

    lib::screenln!(screen, "\x1b[96mRetroOS Rust Kernel\x1b[0m");

    paging2::finish_setup_paging();

    lib::screenln!(screen, "kernel_phys: {:#x}", KERNEL_PHYS);

    let kernel_low_page = (KERNEL_PHYS / PAGE_SIZE) as u64;
    let kernel_high_page = (KERNEL_PHYS + kernel_size).div_ceil(PAGE_SIZE) as u64;

    // Parse Multiboot memory map (the pre-paging copy)
    assert!(info.flags & (1 << 6) != 0, "No Multiboot memory map");
    let mmap_entries: &[MultibootMmapEntry] = &mmap_buf[..mmap_count];

    phys_mm::init_phys_mm(
        mmap_entries,
        mmap_count,
        kernel_low_page,
        kernel_high_page,
    );

    // VGA framebuffer scanout needs its packed shadow as soon as fbcon is
    // attached below. Paging, phys_mm, and the #PF page-backing are now ready,
    // so the demand-paged heap can safely be enabled here.
    ALLOCATOR.init(arch::heap_base(), arch::HEAP_END);

    lib::screenln!(screen, "Physical memory: {:#x} pages free", phys_mm::free_page_count());

    lib::screenln!(screen, "Memory regions: {}", mmap_count);
    for entry in mmap_entries {
        if entry.typ == 1 {
            let base = entry.base;
            let length = entry.length;
            lib::screenln!(screen, "  Available: {:#x} - {:#x}", base, base + length);
        }
    }

    // GOP machines: map the framebuffer and render the boot backlog NOW —
    // as early as its dependencies allow (the IDT for the COW page-table
    // faults, phys_mm for the frames) — so every later init phase can paint
    // its panics. The mappings land in the dual-use PDPT page that the
    // compat-mode toggle below reuses, so they survive the switch.
    crate::fbcon::init(info, &mut screen);

    irq::init_interrupts();
    lib::screenln!(screen, "Interrupts initialized");

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
        lib::screenln!(screen, "Switched to Compat mode");
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
    lib::screenln!(screen, "Stack guards at {:#x} (kernel) {:#x} (arch)", kstack_guard, astack_guard);

    lib::screenln!(screen);
    lib::screenln!(screen, "\x1b[92mHello from Rust kernel!\x1b[0m");

    // Read platform boot configuration at the boundary, before handing it to
    // the kernel. The Multiboot command line carries physical-machine policy;
    // QEMU-only launch settings additionally come from fw_cfg.
    let config = read_boot_config(&boot_cmdline[..boot_cmdline_len]);

    // Diagnostic: with IF still 0, dump the timer chain to the VGA console so a
    // freeze-at-first-IRQ on real hardware is readable instead of a black hang.
    irq::timer_selftest(screen);

    descriptors::enter_ring1();

    lib::screenln!(screen, "Ring1 entered, paging + interrupts + syscall setup complete");

    // The arch backend handle, threaded as `&mut` through the kernel from here
    // on so its mutable state is borrow-checked rather than global. Lives for
    // the rest of the kernel's life (startup never returns).
    let mut machine = arch::Metal;

    lib::screenln!(screen, "Heap base: {:#x}", arch::heap_base());

    crate::kernel::startup::startup(&mut machine, &config);
}

/// Read platform boot settings into a `BootConfig`. The Multiboot command line
/// is available on real hardware; QEMU additionally supplies its headless
/// cmdline/cwd/debug settings through fw_cfg. Port I/O remains here in the
/// metal boot glue, so the kernel never touches firmware ports.
fn read_boot_config(multiboot_cmdline: &[u8]) -> crate::BootConfig {
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
    cfg.ram_overlay = multiboot_cmdline
        .split(|b| b.is_ascii_whitespace())
        .any(|arg| arg.eq_ignore_ascii_case(b"ram-overlay"));

    select(0x0000); // FW_CFG_SIGNATURE
    let mut sig = [0u8; 4];
    read_bytes(&mut sig);
    cfg.is_qemu = &sig == b"QEMU";
    if !cfg.is_qemu {
        return cfg; // no fw_cfg interface — retain Multiboot policy only
    }
    let mut buf = [0u8; 4096];
    if let Some(n) = read_named(b"opt/cmdline", &mut buf) { cfg.set_cmdline(&buf[..n]); }
    let mut cwd = [0u8; 256];
    if let Some(n) = read_named(b"opt/cwd", &mut cwd) { cfg.set_cwd(&cwd[..n]); }
    let mut c_root = [0u8; 128];
    if let Some(n) = read_named(b"opt/c_root", &mut c_root) { cfg.set_c_root(&c_root[..n]); }
    let mut dw = [0u8; 64];
    if let Some(n) = read_named(b"opt/debug-watch", &mut dw) {
        cfg.debug_watch = crate::parse_debug_watch(&dw[..n]);
    }
    let mut audio = [0u8; 16];
    if let Some(n) = read_named(b"opt/audio", &mut audio) {
        cfg.audio_mixed = audio[..n].starts_with(b"mixed");
    }
    cfg
}

/// Metal `#[panic_handler]`. Like the global allocator above, this is a
/// binary-level lang item the metal glue owns — the hosted build is a `std`
/// binary that supplies its own, so it lives here rather than as a
/// `#[cfg]`'d item in the backend-agnostic kernel crate.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Stop HDA DMA and hold its link in reset first: a hard reboot from a
    // panic mid-stream can wedge the codec until a cold power-off.
    crate::kernel::drivers::hda::emergency_quiesce();

    // The console lives somewhere up the dead call chain; a panic does not
    // follow the ownership rules — they protect a *running* program's screen,
    // and nothing runs after this. Write straight to the terminal. Its writes
    // mirror to the log stream, so debugcon/klog get every line too.
    let screen = lib::term::term();
    screen.clear();

    lib::screenln!(screen, "\x1b[91m!!! KERNEL PANIC !!!\x1b[0m");
    if let Some(location) = info.location() {
        lib::screenln!(screen, "at {}:{}", location.file(), location.line());
    } else {
        lib::screenln!(screen, "at <unknown location>");
    }
    lib::screenln!(screen, "  {}", info.message());
    lib::screenln!(screen);

    crate::kernel::stacktrace::stack_trace(screen);

    arch::halt_forever();
}
