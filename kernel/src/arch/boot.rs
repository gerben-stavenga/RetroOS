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

// Boot configuration is immutable after the one-shot handoff and needed for
// the kernel's lifetime.  Keeping it here avoids retaining its 4 KiB command
// line array in the bottom frame of the permanent kernel stack.
static mut BOOT_CONFIG: core::mem::MaybeUninit<crate::BootConfig> =
    core::mem::MaybeUninit::uninit();

/// Metal log sink: preserve the emulator debug port and mirror to the optional
/// physical serial logger. The kernel only hands bytes to this platform sink.
fn log_byte(b: u8) {
    // Preserve the emulator debug console sink; harmless on real hardware.
    x86::outb(0xE9, b);

    // Mirror to the configured physical serial console once it is active.
    crate::kernel::serial_log::write_byte(b);
}

/// Magic value the Multiboot bootloader places in EAX before jumping to us.
const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;
const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D7_6289;

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
    magic: u32,
    info: *const u8,
    mmap_out: &mut [MultibootMmapEntry; 128],
    cmdline_out: &mut [u8],
) -> (arch::MultibootInfo, usize, usize, [Option<crate::multiboot::AcceptedModule>; arch_abi::MAX_BOOT_MODULES], [u8; 4096], usize) {
    assert!(
        magic == MULTIBOOT_BOOTLOADER_MAGIC || magic == MULTIBOOT2_BOOTLOADER_MAGIC,
        "Bad Multiboot magic: {:#x} (expected v1 {:#x} or v2 {:#x})",
        magic, MULTIBOOT_BOOTLOADER_MAGIC, MULTIBOOT2_BOOTLOADER_MAGIC
    );
    if magic == MULTIBOOT2_BOOTLOADER_MAGIC {
        return unsafe { capture_boot_info_v2(info, mmap_out, cmdline_out) };
    }
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
    let modules = unsafe {
        crate::multiboot::capture_modules(
            inf.flags,
            inf.mods_count,
            inf.mods_addr,
            |index| {
                let src = (inf.mods_addr as usize).wrapping_add(PHYS_TO_SEG)
                    as *const [u32; 4];
                core::ptr::read_unaligned(src.add(index as usize))
            },
            |string, out| {
                let src = (string as usize).wrapping_add(PHYS_TO_SEG) as *const u8;
                for (i, slot) in out.iter_mut().enumerate() {
                    let byte = core::ptr::read_volatile(src.add(i));
                    if byte == 0 { return Some(i); }
                    *slot = byte;
                }
                None
            },
        )
    };
    (inf, count, cmdline_len, modules, [0; 4096], 0)
}

/// Normalize GRUB's tagged Multiboot2 block into the legacy fields used by
/// the rest of early boot. Keep the ACPI RSDP tag as an owned copy because its
/// embedded root-table pointers remain physical addresses after this handoff.
unsafe fn capture_boot_info_v2(
    info: *const u8,
    mmap_out: &mut [MultibootMmapEntry; 128],
    cmdline_out: &mut [u8],
) -> (arch::MultibootInfo, usize, usize, [Option<crate::multiboot::AcceptedModule>; arch_abi::MAX_BOOT_MODULES], [u8; 4096], usize) {
    let src = (info as usize).wrapping_add(PHYS_TO_SEG) as *const u8;
    let total_size = unsafe { core::ptr::read_unaligned(src.cast::<u32>()) as usize };
    assert!((16..=16 * 1024 * 1024).contains(&total_size), "invalid Multiboot2 info size");
    let mut normalized = arch::MultibootInfo {
        flags: 0, mem_lower: 0, mem_upper: 0, boot_device: 0, cmdline: 0,
        mods_count: 0, mods_addr: 0, syms: [0; 4], mmap_length: 0, mmap_addr: 0,
        drives_length: 0, drives_addr: 0, config_table: 0, boot_loader_name: 0,
        apm_table: 0, vbe_control_info: 0, vbe_mode_info: 0, vbe_mode: 0,
        vbe_interface_seg: 0, vbe_interface_off: 0, vbe_interface_len: 0,
        framebuffer_addr: 0, framebuffer_pitch: 0, framebuffer_width: 0,
        framebuffer_height: 0, framebuffer_bpp: 0, framebuffer_type: 0,
        color_pad: [0; 2], color_info: [0; 6],
    };
    let mut mmap_count = 0usize;
    let mut cmdline_len = 0usize;
    let mut accepted = [None; arch_abi::MAX_BOOT_MODULES];
    let mut acpi_rsdp = [0u8; 4096];
    let mut acpi_rsdp_len = 0usize;
    let mut offset = 8usize;

    while offset.checked_add(8).is_some_and(|end| end <= total_size) {
        let tag = unsafe { src.add(offset) };
        let tag_type = unsafe { core::ptr::read_unaligned(tag.cast::<u32>()) };
        let tag_size = unsafe { core::ptr::read_unaligned(tag.add(4).cast::<u32>()) as usize };
        assert!(tag_size >= 8 && offset + tag_size <= total_size, "invalid Multiboot2 tag");
        if tag_type == 0 { break; }
        match tag_type {
            1 => {
                let bytes = (tag_size - 8).min(cmdline_out.len());
                for i in 0..bytes {
                    let byte = unsafe { core::ptr::read_volatile(tag.add(8 + i)) };
                    if byte == 0 { break; }
                    cmdline_out[cmdline_len] = byte;
                    cmdline_len += 1;
                }
                normalized.flags |= 1 << 2;
            }
            3 if tag_size >= 17 => {
                let start = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) };
                let end = unsafe { core::ptr::read_unaligned(tag.add(12).cast::<u32>()) };
                let command_bytes = tag_size - 16;
                let mut command = [0u8; 256];
                let mut length = 0usize;
                while length < command.len() && length < command_bytes {
                    let byte = unsafe { core::ptr::read_volatile(tag.add(16 + length)) };
                    if byte == 0 { break; }
                    command[length] = byte;
                    length += 1;
                }
                crate::multiboot::capture_module(start, end, &command[..length], &mut accepted);
            }
            6 if tag_size >= 16 => {
                let entry_size = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) as usize };
                assert!(entry_size >= 24, "invalid Multiboot2 memory map entry size");
                let mut entry_offset = 16usize;
                while entry_offset + entry_size <= tag_size && mmap_count < mmap_out.len() {
                    let entry = unsafe { tag.add(entry_offset) };
                    mmap_out[mmap_count] = MultibootMmapEntry {
                        size: 20,
                        base: unsafe { core::ptr::read_unaligned(entry.cast::<u64>()) },
                        length: unsafe { core::ptr::read_unaligned(entry.add(8).cast::<u64>()) },
                        typ: unsafe { core::ptr::read_unaligned(entry.add(16).cast::<u32>()) },
                    };
                    mmap_count += 1;
                    entry_offset += entry_size;
                }
                normalized.flags |= 1 << 6;
                normalized.mmap_length = (mmap_count * core::mem::size_of::<MultibootMmapEntry>()) as u32;
            }
            8 if tag_size >= 32 => {
                normalized.framebuffer_addr = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u64>()) };
                normalized.framebuffer_pitch = unsafe { core::ptr::read_unaligned(tag.add(16).cast::<u32>()) };
                normalized.framebuffer_width = unsafe { core::ptr::read_unaligned(tag.add(20).cast::<u32>()) };
                normalized.framebuffer_height = unsafe { core::ptr::read_unaligned(tag.add(24).cast::<u32>()) };
                normalized.framebuffer_bpp = unsafe { core::ptr::read_unaligned(tag.add(28)) };
                normalized.framebuffer_type = unsafe { core::ptr::read_unaligned(tag.add(29)) };
                if normalized.framebuffer_type == 1 && tag_size >= 38 {
                    for (i, value) in normalized.color_info.iter_mut().enumerate() {
                        *value = unsafe { core::ptr::read_unaligned(tag.add(32 + i)) };
                    }
                }
                normalized.flags |= arch::MULTIBOOT_INFO_FRAMEBUFFER;
            }
            14 | 15 if tag_size > 8 => {
                let bytes = (tag_size - 8).min(acpi_rsdp.len());
                if tag_type == 15 || acpi_rsdp_len == 0 {
                    for (i, value) in acpi_rsdp.iter_mut().enumerate().take(bytes) {
                        *value = unsafe { core::ptr::read_volatile(tag.add(8 + i)) };
                    }
                    acpi_rsdp_len = bytes;
                }
            }
            _ => {}
        }
        offset = (offset + tag_size + 7) & !7;
    }
    assert!(normalized.flags & (1 << 6) != 0, "Multiboot2 memory map missing");
    (normalized, mmap_count, cmdline_len, accepted, acpi_rsdp, acpi_rsdp_len)
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
pub unsafe extern "C" fn boot_kernel(magic: u32, info: *const u8) -> ! {
    let config = unsafe { prepare_boot(magic, info) };

    // The arch backend handle, threaded as `&mut` through the kernel from here
    // on so its mutable state is borrow-checked rather than global. Lives for
    // the rest of the kernel's life (startup never returns).
    let mut machine = arch::Metal;
    lib::compact_screenln!(lib::term::term(), "Heap base: {:#x}", arch::heap_base());
    crate::kernel::startup::startup(&mut machine, config);
}

/// Finish all one-shot metal boot work and return only the configuration that
/// the runtime needs.  Keep this out of `boot_kernel`: with fat LTO, inlining
/// this phase otherwise reserves its large capture/probe temporaries for the
/// entire non-returning kernel call chain.
#[inline(never)]
unsafe fn prepare_boot(
    magic: u32,
    info: *const u8,
) -> &'static crate::BootConfig {
    // FIRST life sign, before paging: paint a strip into the framebuffer the
    // loader handed us. On real hardware there is no debug port and no
    // display until fbcon::init — a kernel that dies in early init reboots
    // with a black screen and zero evidence. The strip separates "GRUB never
    // entered the kernel" from "kernel died during init". Pre-paging we run
    // on offset segments (base = KERNEL_PHYS - KERNEL_BASE), so a physical
    // address P is reached at P + (KERNEL_BASE - KERNEL_PHYS), wrapping.
    let mut mmap_buf = [MultibootMmapEntry { size: 0, base: 0, length: 0, typ: 0 }; 128];
    let mut boot_cmdline = [0u8; 512];
    let (boot_info, mmap_count, boot_cmdline_len, boot_modules_raw, acpi_rsdp, acpi_rsdp_len) =
        unsafe { capture_boot_info(magic, info, &mut mmap_buf, &mut boot_cmdline) };
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

    // Install the kernel's metal log sink before any normal startup output.
    lib::log::set_debug_sink(log_byte);
    lib::log::set_fatal_handler(fatal_finish);
    // Inject the metal backend into the (backend-agnostic) kernel: port I/O
    // for the deep driver call sites, and the host-environment facts the
    // platform probe reads (real 0xE9 debugcon, GOP fbcon detection, metal).
    crate::install_portio(crate::PortIo {
        now_ns: || arch::now(false),
        inb: arch::inb, inw: arch::inw, inl: arch::inl, insw: arch::insw,
        outb: arch::outb, outw: arch::outw, outl: arch::outl, outsw: arch::outsw,
    });

    // Read the base boot configuration before normal startup output. The
    // Multiboot command line was copied before paging; fw_cfg uses direct PIO,
    // and this read needs neither the heap nor interrupts.
    let mut config = read_boot_config(&boot_cmdline[..boot_cmdline_len]);
    if let Some(port) = config.serial_console_port {
        if crate::kernel::serial_log::init(port) {
            crate::compact_println!("serial: {:?} logging enabled at 115200 8N1", port);
        } else {
            crate::compact_println!("serial: {:?} unavailable", port);
        }
    }

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

    // UEFI-class machine (loader handed us a linear framebuffer, there is no
    // VGA text mode): console cells go to a RAM buffer instead of B8000.
    // Pixels start flowing at `fbcon::init` below; cells written until then
    // are rendered as backlog.
    crate::fbcon::early(info);

    // Nothing else is running yet, so there is no display to arbitrate: write
    // to the terminal directly. Once `startup` builds a `Console`, on-screen
    // kernel text needs that value; ambient println! stays log-only throughout.
    let screen = lib::term::term();

    lib::compact_screenln!(screen, "\x1b[96mRetroOS Rust Kernel\x1b[0m");

    paging2::finish_setup_paging();

    lib::compact_screenln!(screen, "kernel_phys: {:#x}", KERNEL_PHYS);

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
    crate::multiboot::reserve_modules(&boot_modules_raw, |start, end| {
        phys_mm::mark_reserved(start, end)
    });
    phys_mm::reserve_dma_regions();

    // VGA framebuffer scanout needs its packed shadow as soon as fbcon is
    // attached below. Paging, phys_mm, and the #PF page-backing are now ready,
    // so the demand-paged heap can safely be enabled here.
    ALLOCATOR.init_with_release(arch::heap_base(), arch::HEAP_END, Some(arch::release_heap_pages));
    arch::aperture::init();

    let boot_modules = crate::multiboot::handoff_modules(boot_modules_raw);

    lib::compact_screenln!(screen, "Physical memory: {:#x} pages free", phys_mm::free_page_count());

    lib::compact_screenln!(screen, "Memory regions: {}", mmap_count);
    for entry in mmap_entries {
        if entry.typ == 1 {
            let base = entry.base;
            let length = entry.length;
            lib::compact_screenln!(screen, "  Available: {:#x} - {:#x}", base, base + length);
        }
    }

    // GOP machines: map the framebuffer and render the boot backlog NOW —
    // as early as its dependencies allow (the IDT for the COW page-table
    // faults, phys_mm for the frames) — so every later init phase can paint
    // its panics. The mappings land in the dual-use PDPT page that the
    // compat-mode toggle below reuses, so they survive the switch.
    lib::compact_screenln!(screen, "Boot: framebuffer init");
    crate::fbcon::init(info, screen);
    lib::compact_screenln!(screen, "Boot: framebuffer ready");

    lib::compact_screenln!(screen, "Boot: ACPI timer search");
    let tagged_hpet_base = if acpi_rsdp_len != 0 {
        arch::acpi::hpet_base_from_rsdp(&acpi_rsdp[..acpi_rsdp_len])
    } else {
        None
    };
    let (hpet_base, hpet_discovery) = if let Some(base) = tagged_hpet_base {
        (Some(base), Some("Multiboot2 ACPI tag"))
    } else if let Some(base) = arch::acpi::hpet_base_from_legacy_scan() {
        (Some(base), Some("firmware memory scan"))
    } else {
        (None, None)
    };
    if let (Some(base), Some(source)) = (hpet_base, hpet_discovery) {
        lib::compact_screenln!(screen, "HPET: ACPI base {:#x} ({})", base, source);
    } else {
        lib::compact_screenln!(screen, "HPET: no ACPI table found; using timer fallback");
    }
    lib::compact_screenln!(screen, "Boot: IRQ init");
    irq::init_interrupts(hpet_base);
    lib::compact_screenln!(screen, "Interrupts initialized");

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
        lib::compact_screenln!(screen, "Switched to Compat mode");
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
    lib::compact_screenln!(screen, "Stack guards at {:#x} (kernel) {:#x} (arch)", kstack_guard, astack_guard);

    lib::screenln!(screen);
    lib::compact_screenln!(screen, "\x1b[92mHello from Rust kernel!\x1b[0m");

    // Complete the boot configuration with loader-owned module data now that
    // the later handoff has produced it.
    config.boot_modules = boot_modules;
    if config.boot_modules.iter().any(Option::is_some) {
        config.boot_physical_io = Some(arch_abi::BootPhysicalIo {
            read: arch::aperture::copy_from_physical,
            write: arch::aperture::copy_to_physical,
        });
    }

    // Diagnostic: with IF still 0, dump the timer chain to the VGA console so a
    // freeze-at-first-IRQ on real hardware is readable instead of a black hang.
    irq::timer_selftest(screen);

    descriptors::enter_ring1();
    irq::timer_delivery_selftest(screen);

    lib::compact_screenln!(screen, "Ring1 entered, paging + interrupts + syscall setup complete");

    let dst = (&raw mut BOOT_CONFIG).cast::<crate::BootConfig>();
    unsafe {
        dst.write(config);
        &*dst
    }
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
    cfg.set_serial_services_from_cmdline(multiboot_cmdline);
    crate::kernel::boot_filesystems::apply(&mut cfg, multiboot_cmdline);
    cfg.ram_overlay = multiboot_cmdline
        .split(|b| b.is_ascii_whitespace())
        .any(|arg| arg.eq_ignore_ascii_case(b"ram-overlay"));

    cfg.boot_log_only = multiboot_cmdline
        .split(|b| b.is_ascii_whitespace())
        .any(|arg| arg.eq_ignore_ascii_case(b"boot-log-only"));

    cfg.isa_lpc_disappointment = multiboot_cmdline
        .split(|b| b.is_ascii_whitespace())
        .any(|arg| arg.eq_ignore_ascii_case(b"isa-lpc=disappointment"));

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
    // Separate from opt/cmdline: a directive-only launch line shuts the
    // machine down, and an interactive boot still needs the control UART.
    let mut mcp = [0u8; 16];
    if let Some(n) = read_named(b"opt/mcp", &mut mcp)
        && !cfg.set_mcp_value(&mcp[..n]) {
        crate::compact_println!("serial-control: invalid opt/mcp value");
    }
    cfg
}

/// Metal `#[panic_handler]`. Like the global allocator above, this is a
/// binary-level lang item the metal glue owns — the hosted build is a `std`
/// binary that supplies its own, so it lives here rather than as a
/// `#[cfg]`'d item in the backend-agnostic kernel crate.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // The console lives somewhere up the dead call chain; a panic does not
    // follow the ownership rules — they protect a *running* program's screen,
    // and nothing runs after this. Write straight to the terminal. Its writes
    // mirror to the log stream, so debugcon/klog get every line too.
    let screen = lib::term::term();
    screen.clear();

    lib::compact_screenln!(screen, "\x1b[91m!!! KERNEL PANIC !!!\x1b[0m");
    lib::compact_screenln!(screen, "{}", crate::build_info::VersionBanner);
    if let Some(location) = info.location() {
        lib::compact_screenln!(screen, "at {}:{}", location.file(), location.line());
    } else {
        lib::compact_screenln!(screen, "at <unknown location>");
    }
    let _ = core::fmt::Write::write_fmt(screen, format_args!("{}\n", info.message()));
    fatal_finish()
}

fn fatal_finish() -> ! {
    crate::kernel::drivers::hda::emergency_quiesce();
    let screen = lib::term::term();
    lib::screenln!(screen);
    lib::compact_screenln!(screen, "{}", crate::build_info::VersionBanner);
    crate::kernel::stacktrace::stack_trace(screen);

    // Capture any final partial line as well. A panic can occur while VFS is
    // locked or in an interrupt; sync_live uses try_lock and this guard avoids
    // issuing disk I/O from an interrupt handler.
    if x86::interrupts_enabled() {
        crate::kernel::klog::sync_live();
    }

    // The normal display owner is somewhere up the dead call chain. Seize the
    // mapped framebuffer for one best-effort publication before stopping.
    crate::fbcon::panic_present();
    arch::halt_forever();
}
