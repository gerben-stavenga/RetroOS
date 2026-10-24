//! Early core startup. Allocation and processor discovery belong to the caller.
//!
//! Both ELF entry and the AP trampoline call `boot_kernel(core_id, magic, info)`
//! with paging off, offset segments, a private stack, and initialized Rust TLS.
//! The consumer calls `init_core` on both paths; only core 0 initializes devices.
//! AP memory comes first from the final BSS pool through `boot_mem::BootMemory`,
//! keeping the kernel's linear physical mapping instead of using the heap. Keep that storage alive for the CPU's lifetime.

use crate::{descriptors, paging2, x86};
use core::alloc::Layout;
use core::sync::atomic::{AtomicU32, Ordering};

unsafe extern "C" {
    static TLS_TEMPLATE: u8;
    static TLS_FILE_SIZE: u8;
    static TLS_SIZE: u8;
    static TLS_ALIGN: u8;
    static ARCH_STACK_TOP: u8;
    static _kernel_start: u8;
    static ap_trampoline: u8;
    static ap_trampoline_end: u8;
}

#[thread_local]
static mut CORE_ID: u32 = 0;
#[thread_local]
static mut START: Option<CoreStart> = None;

/// Dense, caller-assigned identity. The ELF boot CPU is always zero.
pub fn current_core_id() -> u32 {
    unsafe { CORE_ID }
}

/// Caller-owned stacks and TLS; all addresses are linked virtual addresses.
#[derive(Clone, Copy)]
pub struct CoreStart {
    pub core_id: u32,
    pub stack_top: u32,
    pub trap_stack_top: u32,
    pub tls: *mut u8,
    pub entry: extern "C" fn(u32, usize) -> !,
    pub argument: usize,
    /// Written with Release after CPU-local initialization, before `entry`.
    pub ready: &'static AtomicU32,
}

pub fn tls_layout() -> Layout {
    Layout::from_size_align(
        (&raw const TLS_SIZE) as usize + 8,
        ((&raw const TLS_ALIGN) as usize).max(4),
    )
    .unwrap()
}

/// Common BSP/AP initialization, called once per core before any other Rust
/// code that needs paging or descriptors. Assembly has already installed TLS.
///
/// # Safety
/// Must run at ring 0 with interrupts and paging off, under the boot offset
/// segments. The linker-reserved image and pool must fit the identity window.
pub unsafe fn init_core(core_id: u32) {
    unsafe {
        CORE_ID = core_id;
    }
    let stack = if core_id == 0 {
        (&raw const ARCH_STACK_TOP) as u32 - 16
    } else {
        unsafe { START.expect("AP missing startup context").trap_stack_top }
    };
    assert!(
        crate::boot_mem::pool_start() - paging2::KERNEL_BASE + paging2::KERNEL_PHYS
            <= paging2::BOOT_IDENTITY_END,
        "boot storage exceeds the physical 4 MiB identity window"
    );
    let pages = (crate::boot_mem::end() - (&raw const _kernel_start) as usize).div_ceil(4096);
    paging2::enable_paging(&raw mut crate::SCRATCH, paging2::KERNEL_PHYS, pages);
    descriptors::setup_descriptor_tables(stack);
    descriptors::setup_syscall();
    if core_id != 0 && paging2::is_pae() {
        // Before READY: the BSP will harden shared PTEs and publish WC device
        // mappings. Their interpretation must already match on every AP.
        paging2::enable_nx();
        paging2::enable_wc_pat();
    }
}

/// Complete the AP branch of the common Rust entry. No shared allocator,
/// device initialization, timer setup, or scheduler is entered implicitly.
///
/// # Safety
/// `init_core` must have completed on this AP, with interrupts still disabled.
pub unsafe fn run_secondary() -> ! {
    paging2::refresh_kernel_mappings();
    let start = unsafe { START.expect("not a secondary core") };
    // The active GDT is now private TLS storage; the trampoline can be reused.
    start.ready.store(start.core_id, Ordering::Release);
    (start.entry)(start.core_id, start.argument)
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartError {
    InvalidMemory,
    InvalidCore,
    NoApic,
    OutOfMemory,
    DeliveryTimeout,
    StartupTimeout,
}

/// Start a known, stopped processor using one reserved SIPI page below 1 MiB.
/// `delay_us` must provide a calibrated, bounded delay without enabling IRQs.
/// Returns after the AP has completed `init_core` and acknowledged its handoff.
///
/// # Safety
/// Call after `init_core(0)` on the BSP at ring 0 with IRQs off, and serialize
/// all startup requests. Assign distinct nonzero logical IDs to the APs.
/// `apic_id` must identify an enabled, offline AP (never a running CPU).
/// The 4 KiB `page_phys` page must be reserved RAM, writable via LOW_MEM_BASE.
/// `start` must provide exclusive, mapped, resident storage: a 64 KiB kernel
/// stack, a 16 KiB trap stack in one 64 KiB window, and `tls_layout()` bytes.
/// These allocations must come from the finished `boot_mem::BootMemory`
/// phase of the final BSS pool, and must never be freed.
/// `ready` must be distinct for each AP, initially zero, and valid on both CPUs.
/// After ANY delivery/startup timeout, retain the page and all AP storage and
/// do not retry/reuse them: an AP may still arrive late. Callback code must
/// synchronize shared state and must not use the unsynchronized global heap.
pub unsafe fn start_core(
    apic_id: u32,
    page_phys: u32,
    start: CoreStart,
    delay_us: fn(u32),
) -> Result<(), StartError> {
    if start.core_id == 0
        || current_core_id() != 0
        || x86::interrupts_enabled()
        || start.ready.load(Ordering::Acquire) != 0
    {
        return Err(StartError::InvalidCore);
    }
    let own = x86::current_apic_id().ok_or(StartError::NoApic)?;
    if own == apic_id {
        return Err(StartError::InvalidCore);
    }
    let layout = tls_layout();
    let lo = crate::boot_mem::pool_start();
    let hi = crate::boot_mem::boot_limit();
    let valid = |base: usize, size: usize| {
        base >= lo && base.checked_add(size).is_some_and(|end| end <= hi)
    };
    if !(0x1000..0xa0000).contains(&page_phys)
        || page_phys & 4095 != 0
        || start.tls as usize & (layout.align() - 1) != 0
        || !valid(start.tls as usize, layout.size())
        || start.stack_top & 15 != 0
        || start.trap_stack_top & 15 != 0
        || !valid(start.stack_top.saturating_sub(65536) as usize, 65536)
        || !valid(start.trap_stack_top.saturating_sub(16368) as usize, 16368)
        || start.trap_stack_top >> 16 != start.trap_stack_top.saturating_sub(16368) >> 16
    {
        return Err(StartError::InvalidMemory);
    }
    let base = x86::rdmsr(0x1b);
    if base & (1 << 11) == 0 || base & (1 << 8) == 0 {
        return Err(StartError::NoApic);
    }
    let x2 = base & (1 << 10) != 0;
    if apic_id == u32::MAX || (!x2 && apic_id >= 255) {
        return Err(StartError::InvalidCore);
    }
    let mmio = 0xfff0_0000usize;
    if !x2 && !paging2::map_boot_mmio(mmio, base & 0x000f_ffff_ffff_f000) {
        return Err(StartError::OutOfMemory);
    }
    unsafe {
        core::ptr::write_bytes(start.tls, 0, layout.size());
        core::ptr::copy_nonoverlapping(
            &raw const TLS_TEMPLATE,
            start.tls,
            (&raw const TLS_FILE_SIZE) as usize,
        );
        let tp = start.tls.add((&raw const TLS_SIZE) as usize);
        tp.cast::<u32>().write(tp as u32);
        let offset = ((&raw const START) as usize).wrapping_sub(x86::thread_pointer() as usize);
        tp.wrapping_add(offset)
            .cast::<Option<CoreStart>>()
            .write(Some(start));
        let page = (paging2::LOW_MEM_BASE + page_phys as usize) as *mut u8;
        let len = (&raw const ap_trampoline_end) as usize - (&raw const ap_trampoline) as usize;
        assert!(len <= 0x800);
        core::ptr::write_bytes(page, 0, 4096);
        core::ptr::copy_nonoverlapping(&raw const ap_trampoline, page, len);
        // Header at 0x800: GDTR, padding, ESP, logical ID, then 19 GDT slots.
        page.add(0x800).cast::<u16>().write_unaligned(19 * 8 - 1);
        page.add(0x802)
            .cast::<u32>()
            .write_unaligned(page_phys + 0x820);
        page.add(0x808).cast::<u32>().write(start.stack_top);
        page.add(0x80c).cast::<u32>().write(start.core_id);
        let offset = (paging2::KERNEL_PHYS as u32).wrapping_sub(paging2::KERNEL_BASE as u32);
        let segment = |base: u32, code: bool, ring: u64| -> u64 {
            0x00cf_0000_0000_ffff
                | ((if code { 0x9a } else { 0x92 }) | (ring << 5)) << 40
                | ((base as u64 & 0xffff) << 16)
                | ((base as u64 & 0xff0000) << 16)
                | ((base as u64 & 0xff000000) << 32)
        };
        page.add(0x828)
            .cast::<u64>()
            .write_unaligned(segment(offset, true, 0));
        page.add(0x830)
            .cast::<u64>()
            .write_unaligned(segment(offset, false, 0));
        let phys_tp = (tp as u32).wrapping_add(offset);
        page.add(0x8b0)
            .cast::<u64>()
            .write_unaligned(segment(phys_tp, false, 1));
    }
    // A locked fence also orders startup memory before x2APIC WRMSR.
    core::sync::atomic::fence(Ordering::SeqCst);
    let send = |command: u32| -> Result<(), StartError> {
        if x2 {
            unsafe {
                x86::wrmsr(0x830, ((apic_id as u64) << 32) | command as u64);
            }
        } else {
            let wait = || -> Result<(), StartError> {
                for _ in 0..1000 {
                    if unsafe { core::ptr::read_volatile((mmio + 0x300) as *const u32) } & (1 << 12)
                        == 0
                    {
                        return Ok(());
                    }
                    delay_us(10);
                }
                Err(StartError::DeliveryTimeout)
            };
            wait()?;
            unsafe {
                core::ptr::write_volatile((mmio + 0x310) as *mut u32, apic_id << 24);
                core::ptr::write_volatile((mmio + 0x300) as *mut u32, command);
            }
            wait()?;
        }
        Ok(())
    };
    send(0xc500)?; // INIT, level assert
    delay_us(10_000);
    send(0x8500)?; // INIT deassert
    let sipi = 0x600 | (page_phys >> 12);
    send(sipi)?;
    delay_us(200);
    if start.ready.load(Ordering::Acquire) != start.core_id {
        send(sipi)?;
    }
    for _ in 0..10_000 {
        if start.ready.load(Ordering::Acquire) == start.core_id {
            return Ok(());
        }
        delay_us(100);
    }
    Err(StartError::StartupTimeout)
}
