//! BSP boot policy. Core 1 waits for the resident-buffer media worker;
//! remaining APs execute pinned Linux processes. Kernel services stay on the BSP.
use arch::{smp, x86};
use arch_abi::page_supply::FrameLayout;
use core::alloc::Layout;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const MAX_CPUS: usize = arch::smp::MAX_CORES;
static READY: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static TICKS_PER_US: AtomicU32 = AtomicU32::new(0);
static MEDIA_START: AtomicBool = AtomicBool::new(false);
static WORKER_TIMER: spin::Once<arch::irq::WorkerTimer> = spin::Once::new();
static MEDIA_AVAILABLE: AtomicBool = AtomicBool::new(false);

extern "C" fn park(id: u32, _argument: usize) -> ! {
    if id != 1 {
        let slot = unsafe { &*(_argument as *const crate::kernel::parallel::Slot<arch::Metal>) };
        while !crate::kernel::parallel::started() { core::hint::spin_loop(); }
        arch::paging2::refresh_kernel_mappings();
        let Some(timer) = WORKER_TIMER.get().copied() else {
            crate::kernel::parallel::disable(slot);
            arch::halt_forever();
        };
        arch::irq::init_worker_timer(timer);
        if arch::paging2::is_pae() { arch::paging2::setup_long_mode_tables(); arch::paging2::flush_tlb(); }
        arch::descriptors::enter_ring1();
        unsafe { crate::kernel::parallel::worker(arch::Metal::bind_current(), slot) }
    }
    while !MEDIA_START.load(Ordering::Acquire) { core::hint::spin_loop(); }
    fn refresh() {
        arch::paging2::refresh_kernel_mappings();
        // Leaf mappings may have been released/reused without changing a root.
        // This handoff does not change the worker's user-root entries, so its
        // hardware PDPT is already current. Only invalidate translations;
        // rebuilding that PDPT repeatedly probes the CPU paging mode.
        x86::flush_tlb();
    }
    refresh();
    lib::compact_println!("Media worker: audio and graphics ready");
    unsafe { crate::kernel::media::worker(refresh) }
}

pub(super) fn enable_parallel() {
    if let Some(timer) = arch::irq::worker_timer() { WORKER_TIMER.call_once(|| timer); }
    crate::kernel::parallel::enable();
}

pub(super) fn enable_media() {
    if !MEDIA_AVAILABLE.load(Ordering::Acquire) { return; }
    MEDIA_START.store(true, Ordering::Release);
    while !crate::kernel::media::enabled() { core::hint::spin_loop(); }
}

// No shared clock or interrupts yet. Prefer the architectural TSC ratio;
// otherwise use PIT channel 2, with a bounded probe for machines without PIT.
fn calibrate() -> bool {
    let cpu = x86::cpu_capabilities();
    if !cpu.tsc() {
        return false;
    }
    let mut hz = 0u64;
    if let Some(ratio) = cpu.tsc_ratio {
        let (den, num, crystal) = (ratio.denominator, ratio.numerator, ratio.crystal_hz);
        if den != 0 && num != 0 {
            hz = u64::from(crystal) * u64::from(num) / u64::from(den);
        }
    }
    if hz == 0 {
        let gate = x86::inb(0x61);
        x86::outb(0x61, gate & !3);
        x86::outb(0x43, 0xb0);
        x86::outb(0x42, 11932u16 as u8);
        x86::outb(0x42, (11932u16 >> 8) as u8);
        // Mode 0 must begin low, then transition high at terminal count.
        let low = x86::inb(0x61) & 0x20 == 0;
        let begin = x86::rdtsc();
        x86::outb(0x61, (gate & !2) | 1);
        let mut elapsed = None;
        if low {
            for _ in 0..1_000_000 {
                if x86::inb(0x61) & 0x20 != 0 {
                    elapsed = Some(x86::rdtsc().wrapping_sub(begin));
                    break;
                }
                core::hint::spin_loop();
            }
        }
        x86::outb(0x61, gate);
        let Some(ticks) = elapsed else {
            return false;
        };
        hz = ticks.saturating_mul(100);
    }
    let ticks = hz.div_ceil(1_000_000);
    if ticks == 0 || ticks > u32::MAX as u64 {
        return false;
    }
    TICKS_PER_US.store(ticks as u32, Ordering::Relaxed);
    true
}
fn delay(us: u32) {
    let begin = x86::rdtsc();
    let ticks = u64::from(TICKS_PER_US.load(Ordering::Relaxed)) * u64::from(us);
    while x86::rdtsc().wrapping_sub(begin) < ticks {
        core::hint::spin_loop();
    }
}

pub(super) fn trampoline(layout: &FrameLayout) -> Option<u32> {
    // PAE's bootstrap identity table uses the first two slots as directory links.
    (2..0x80000 / arch_abi::PAGE_SIZE as u64)
        .find(|&page| layout.index(page).is_some())
        .map(|page| (page * arch_abi::PAGE_SIZE as u64) as u32)
}

pub(super) unsafe fn start(
    screen: &mut lib::term::Term,
    rsdp: &[u8],
    page: Option<u32>,
) {
    let slots = crate::kernel::parallel::provision::<arch::Metal>(MAX_CPUS);
    let mut ids = [0; MAX_CPUS];
    let own = x86::current_apic_id();
    let count = arch::acpi::processor_ids(rsdp, &mut ids)
        .filter(|&n| own.is_some_and(|id| ids[..n].contains(&id)));
    let mut starts = [None; MAX_CPUS];
    let mut selected = 0;
    let can_start = if count.is_none() {
        lib::compact_screenln!(
            screen,
            "SMP: no usable MADT containing the BSP; keeping one CPU"
        );
        false
    } else if count == Some(1) {
        false
    } else if page.is_none() {
        lib::compact_screenln!(screen, "SMP: no safe trampoline page; keeping one CPU");
        false
    } else if !calibrate() {
        lib::compact_screenln!(screen, "SMP: no reliable startup delay; keeping one CPU");
        false
    } else {
        true
    };
    if can_start {
        let x2 = x86::rdmsr(0x1b) & (1 << 10) != 0;
        let trap = Layout::from_size_align(16384, 16384).unwrap();
        let tls = smp::tls_layout();
        let stack = Layout::from_size_align(65536, 16).unwrap();
        for &id in &ids[..count.unwrap()] {
            if Some(id) == own || (!x2 && id >= 255) {
                continue;
            }
            // TLS contains CR3 targets, which must be physically below 4 GiB.
            // start_core initializes it before handing it to the AP.
            let tls = match arch::boot_mem::allocate_permanent(tls) {
                Ok(storage) => storage,
                Err(_) => {
                    lib::compact_screenln!(screen, "SMP: low TLS pool exhausted; limiting cores");
                    break;
                }
            };
            // Stacks only need resident mappings; their frames can be high.
            let resident = |layout: Layout| {
                let storage = unsafe { alloc::alloc::alloc_zeroed(layout) };
                assert!(!storage.is_null(), "cannot allocate resident AP storage");
                storage
            };
            let trap = resident(trap);
            let stack = resident(stack);
            let logical = selected + 1;
            slots[logical].processor.store(id, Ordering::Relaxed);
            starts[selected] = Some((
                id,
                smp::CoreStart {
                    core_id: logical as u32,
                    stack_top: stack as u32 + 65536,
                    trap_stack_top: trap as u32 + 16384 - 16,
                    tls,
                    entry: park,
                    argument: &slots[logical] as *const _ as usize,
                    memory: crate::kernel::platform::bootstrap_supply(),
                    ready: &READY[logical],
                },
            ));
            selected += 1;
        }
    }
    if selected != 0 {
        lib::compact_screenln!(screen, "SMP: AP TLS uses low BSS pool; stacks use resident heap");
    }
    let mut online = 1;
    for &(id, start) in starts.iter().flatten() {
        match unsafe { smp::start_core(id, page.unwrap(), start, delay) } {
            Ok(()) => {
                online += 1;
                if start.core_id == 1 { MEDIA_AVAILABLE.store(true, Ordering::Release); }
                lib::compact_screenln!(
                    screen,
                    "SMP: core {} APIC {} initialized, parking",
                    start.core_id,
                    id
                );
            }
            Err(error) => {
                let reason = match error {
                    smp::StartError::InvalidMemory => "invalid memory",
                    smp::StartError::InvalidCore => "invalid core",
                    smp::StartError::NoApic => "APIC unavailable",
                    smp::StartError::OutOfMemory => "pool exhausted",
                    smp::StartError::DeliveryTimeout => "delivery timeout",
                    smp::StartError::StartupTimeout => "startup timeout",
                };
                lib::compact_screenln!(
                    screen,
                    "SMP: APIC {} startup failed: {}; stopping AP startup",
                    id,
                    reason
                );
                // A delayed AP may still use the trampoline and borrowed BSP
                // root. Stop boot instead of removing or reusing either.
                lib::compact_panic!("AP startup unacknowledged; retaining bootstrap state");
            }
        }
    }
    lib::compact_screenln!(
        screen,
        "SMP: {} CPUs initialized, {} firmware CPUs, {} APs selected",
        online,
        count.unwrap_or(1),
        selected
    );
}
