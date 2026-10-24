//! Minimal SMP consumer: arch setup, AP pool allocations, core startup, kernel init.
#![no_std]
#![no_main]
#![feature(thread_local)]
extern crate alloc;
use arch_metal::{smp, x86};
use core::alloc::Layout;
use core::sync::atomic::{AtomicU32, Ordering};

#[global_allocator]
static ALLOC: lib::heap::DemandHeap = lib::heap::DemandHeap::new();
static READY: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static DONE: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static ROOTS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static TLS_ADDR: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static GDT: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static STACKS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static MISSING_READY: AtomicU32 = AtomicU32::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
#[thread_local]
static mut INITIALIZED: u32 = 0x12345678;
#[thread_local]
static mut ZERO: u32 = 0;

fn print(s: &str) {
    for b in s.bytes() {
        x86::outb(0xe9, b);
    }
}
fn stop(code: u32) -> ! {
    x86::outl(0xf4, code);
    arch_metal::halt_forever()
}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    struct Output;
    impl core::fmt::Write for Output {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            print(s);
            Ok(())
        }
    }
    use core::fmt::Write;
    let _ = writeln!(Output, "SMP FAIL: {info}");
    stop(1)
}

// QEMU PC has a PIT; calibrate an actual 10ms interval instead of assuming
// a TSC frequency. This timer is owned exclusively by the boot CPU here.
static TICKS_PER_US: AtomicU32 = AtomicU32::new(0);
fn calibrate() {
    let gate = x86::inb(0x61);
    x86::outb(0x61, gate & !3);
    x86::outb(0x43, 0xb0);
    x86::outb(0x42, 11932u16 as u8);
    x86::outb(0x42, (11932u16 >> 8) as u8);
    let begin = x86::rdtsc();
    x86::outb(0x61, (gate & !2) | 1);
    while x86::inb(0x61) & 0x20 == 0 {
        core::hint::spin_loop();
    }
    TICKS_PER_US.store(
        ((x86::rdtsc() - begin) / 10000).max(1) as u32,
        Ordering::Relaxed,
    );
    x86::outb(0x61, gate);
}
fn delay(us: u32) {
    let start = x86::rdtsc();
    let ticks = TICKS_PER_US.load(Ordering::Relaxed) as u64 * us as u64;
    while x86::rdtsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}
fn check_local(id: u32) {
    assert_eq!(smp::current_core_id(), id);
    assert!(!x86::interrupts_enabled());
    assert_ne!(x86::read_cr0() & (1 << 31), 0);
    unsafe {
        assert_eq!({ INITIALIZED }, 0x12345678);
        assert_eq!({ ZERO }, 0);
        INITIALIZED = id + 100;
        ZERO = id + 200;
    }
    let here = (&raw const id) as u32;
    if id != 0 {
        let top = STACKS[id as usize].load(Ordering::Acquire);
        assert!(here < top && here >= top - 65536);
    }
    let mut gdtr = [0u8; 6];
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack));
    }
    GDT[id as usize].store(
        u32::from_le_bytes(gdtr[2..6].try_into().unwrap()),
        Ordering::Release,
    );
    ROOTS[id as usize].store(x86::read_cr3(), Ordering::Release);
    TLS_ADDR[id as usize].store((&raw const ZERO) as u32, Ordering::Release);
}
extern "C" fn secondary(id: u32, argument: usize) -> ! {
    assert_eq!(argument, 0xabcdef);
    assert_eq!(x86::current_apic_id(), Some(id)); // QEMU fixture uses IDs 0..3
    check_local(id);
    while GO.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    unsafe {
        assert_eq!({ INITIALIZED }, id + 100);
        assert_eq!({ ZERO }, id + 200);
    }
    DONE[id as usize].store(1, Ordering::Release);
    arch_metal::halt_forever()
}

fn allocate_core(
    memory: &mut arch_metal::boot_mem::BootMemory,
    id: u32,
    ready: &'static AtomicU32,
) -> smp::CoreStart {
    let mut allocate = |layout| memory.allocate(layout).unwrap();
    // Allocate the most strongly aligned stack first to avoid wasting pool space.
    let trap = allocate(Layout::from_size_align(16384, 65536).unwrap());
    let tls = allocate(smp::tls_layout());
    let stack = allocate(Layout::from_size_align(65536, 16).unwrap());
    smp::CoreStart {
        core_id: id,
        tls,
        stack_top: stack as u32 + 65536,
        trap_stack_top: trap as u32 + 16384 - 16,
        entry: secondary,
        argument: 0xabcdef,
        ready,
    }
}

/// Shared ELF/SIPI entry for this example.
///
/// # Safety
/// Called only by arch entry assembly with boot segments, private stack/TLS,
/// paging off, and valid Multiboot pointers on core zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boot_kernel(core_id: u32, _magic: u32, _info: *const u8) -> ! {
    // Read the fixture option while the Multiboot pointer is still physical.
    let (use_x2, missing_test) = if core_id == 0 && _magic == 0x2badb002 {
        unsafe {
            let info = (_info as usize)
                .wrapping_add(arch_metal::paging2::KERNEL_BASE - arch_metal::paging2::KERNEL_PHYS)
                as *const u32;
            if info.read() & 4 != 0 {
                let cmd = (info.add(4).read() as usize).wrapping_add(
                    arch_metal::paging2::KERNEL_BASE - arch_metal::paging2::KERNEL_PHYS,
                ) as *const u8;
                let mut len = 0;
                while len < 256 && cmd.add(len).read() != 0 {
                    len += 1;
                }
                let args = core::slice::from_raw_parts(cmd, len);
                (
                    args.windows(6).any(|s| s == b"x2apic"),
                    args.windows(7).any(|s| s == b"missing"),
                )
            } else {
                (false, false)
            }
        }
    } else {
        (false, false)
    };
    let mut map = [arch_metal::MultibootMmapEntry {
        size: 20,
        base: 0,
        length: 0,
        typ: 0,
    }; 128];
    let mut count = 0;
    let mut starts = [None; 3];
    if core_id == 0 {
        assert_eq!(_magic, 0x2badb002);
        let delta = arch_metal::paging2::KERNEL_BASE - arch_metal::paging2::KERNEL_PHYS;
        let info = unsafe {
            ((_info as usize).wrapping_add(delta) as *const arch_metal::MultibootInfo)
                .read_unaligned()
        };
        assert_ne!(info.flags & (1 << 6), 0);
        let mut offset = 0usize;
        while offset < info.mmap_length as usize {
            assert!(count < map.len());
            let entry = (info.mmap_addr as usize)
                .wrapping_add(delta)
                .wrapping_add(offset)
                as *const arch_metal::MultibootMmapEntry;
            let value = unsafe { entry.read_unaligned() };
            offset += value.size as usize + 4;
            map[count] = value;
            count += 1;
        }
        // The loader reserved the pool with the image before placing modules.
    }
    unsafe {
        smp::init_core(core_id);
    }
    if core_id != 0 {
        unsafe {
            smp::run_secondary();
        }
    }
    // Minimal arch first, then reserve ALL AP resources, then engage CPUs.
    let mut memory = unsafe { arch_metal::boot_mem::BootMemory::new() };
    assert!(arch_metal::boot_mem::allocate_permanent(Layout::new::<u8>()).is_err());
    let missing = if missing_test {
        Some(allocate_core(&mut memory, 4, &MISSING_READY))
    } else {
        for id in 1..4u32 {
            starts[id as usize - 1] = Some(allocate_core(&mut memory, id, &READY[id as usize]));
        }
        None
    };
    memory.finish();
    assert_eq!(arch_metal::boot_mem::pool_end(), arch_metal::heap_base());
    if use_x2 {
        assert_ne!(x86::cpuid(1).2 & (1 << 21), 0);
        unsafe {
            x86::wrmsr(0x1b, x86::rdmsr(0x1b) | (1 << 10));
        }
        print("SMP x2APIC sender\n");
    }
    print("SMP BSP initialized\n");
    check_local(0);
    calibrate();
    if let Some(missing) = missing {
        let failure = unsafe { smp::start_core(254, 0x8000, missing, delay) };
        assert!(matches!(
            failure,
            Err(smp::StartError::StartupTimeout | smp::StartError::DeliveryTimeout)
        ));
        assert_eq!(MISSING_READY.load(Ordering::Acquire), 0);
        print("SMP TIMEOUT PASS\n");
        stop(0);
    }
    for id in 1..4u32 {
        let start = starts[id as usize - 1].unwrap();
        STACKS[id as usize].store(start.stack_top, Ordering::Release);
        assert_eq!(
            unsafe { smp::start_core(0, 0x8000, start, delay) },
            Err(smp::StartError::InvalidCore)
        );
        assert_eq!(
            unsafe { smp::start_core(id, 0x8001, start, delay) },
            Err(smp::StartError::InvalidMemory)
        );
        // The test owns low RAM and reserves this page for the entire boot.
        unsafe {
            smp::start_core(id, 0x8000, start, delay).unwrap();
        }
        print("SMP AP initialized\n");
    }
    // Only after the APs are engaged do we initialize the ordinary allocators.
    let physical_end = arch_metal::boot_mem::end() - arch_metal::paging2::KERNEL_BASE
        + arch_metal::paging2::KERNEL_PHYS;
    arch_metal::phys_mm::init_phys_mm(
        &map[..count],
        count,
        0x100,
        physical_end.div_ceil(4096) as u64,
    );
    ALLOC.init(arch_metal::heap_base(), arch_metal::HEAP_END);
    arch_metal::phys_mm::complete_initialization();
    // Normal heap allocations must follow the entire early extension.
    let ordinary = alloc::boxed::Box::new(0xfeed1234u32);
    assert!((&*ordinary as *const u32 as usize) >= arch_metal::boot_mem::end());
    assert_eq!(*ordinary, 0xfeed1234);
    assert!(
        arch_metal::paging2::physical_page((&*ordinary as *const u32) as usize)
            >= physical_end.div_ceil(4096) as u64
    );
    for channel in [1, 5] {
        let dma = arch_metal::phys_mm::dma_channel_buf(channel);
        assert_ne!(dma, 0);
        let alignment = if channel < 4 { 65536 } else { 131072 };
        assert_eq!((dma * 4096) % alignment, 0);
        assert!(dma * 4096 < 0x1000000);
        assert_eq!(arch_metal::phys_mm::dma_channel_buf(channel), dma);
        let dma_va = dma as usize * 4096 - arch_metal::paging2::KERNEL_PHYS
            + arch_metal::paging2::KERNEL_BASE;
        for start in starts.iter().flatten() {
            assert!(dma_va >= start.stack_top as usize);
        }
    }
    print("SMP DMA allocated after AP resources\n");
    GO.store(1, Ordering::Release);
    for id in 1..4 {
        for _ in 0..10000 {
            if DONE[id].load(Ordering::Acquire) == 1 {
                break;
            }
            delay(100);
        }
        assert_eq!(DONE[id].load(Ordering::Acquire), 1);
        for other in 0..id {
            assert_ne!(
                GDT[id].load(Ordering::Acquire),
                GDT[other].load(Ordering::Acquire)
            );
            assert_ne!(
                ROOTS[id].load(Ordering::Acquire),
                ROOTS[other].load(Ordering::Acquire)
            );
            assert_ne!(
                TLS_ADDR[id].load(Ordering::Acquire),
                TLS_ADDR[other].load(Ordering::Acquire)
            );
        }
    }
    unsafe {
        assert_eq!({ INITIALIZED }, 100);
        assert_eq!({ ZERO }, 200);
    }
    print("SMP PASS: 4 cores, private TLS and page roots, shared Rust entry\n");
    stop(0)
}
