//! Opt-in startup/event timings. Run includes guest execution and arch
//! entry/exit; dispatch covers event handling. No logging in measured paths.
use crate::{Arch, KernelEvent, Regs};
use super::thread::Personality;

#[repr(C)]
#[derive(Clone, Copy)]
struct Counter {
    kind: u32, key: u32, cs: u32, ip: u32,
    calls: u64, run: u64, dispatch: u64, max_dispatch: u64,
}
const EMPTY: Counter = Counter {
    kind: 0, key: 0, cs: 0, ip: 0, calls: 0, run: 0, dispatch: 0, max_dispatch: 0,
};
const SLOTS: usize = 256;
// The cooperative event loop owns this optional diagnostic storage. Allocate
// on first use, outside the measured dispatch interval, rather than reserving
// 12 KiB in every kernel's bootstrap footprint.
static mut COUNTERS: alloc::vec::Vec<Counter> = alloc::vec::Vec::new();
static mut OVERFLOW: u64 = 0;
const RM_TARGET_SLOTS: usize = 32;
static mut RM_TARGETS: [(u8, u16, u16, u64); RM_TARGET_SLOTS] = [(0, 0, 0, 0); RM_TARGET_SLOTS];
const READ_DETAIL_SLOTS: usize = 64;
static mut READ_DETAILS: [(u16, u64, u64); READ_DETAIL_SLOTS] = [(0, 0, 0); READ_DETAIL_SLOTS];
// calls, RM-call setup, DOS vector dispatch, continuation unwind.
static mut DIRECT_RM_PHASES: [u64; 4] = [0; 4];
// Native device shortcuts do not create event-loop events. Keep their cost
// separate, including failed attempts that subsequently take the normal path.
pub(super) const DEVICE_NAMES: [&str; 5] = ["vga_mov", "vga_generic", "vga_status", "vga_mask", "dma_poll"];
static mut DEVICE_ENTRIES: [[u64; 2]; 5] = [[0; 2]; 5];
#[derive(Clone, Copy)]
pub(super) struct VgaInstruction { pub cs: u16, pub ip: u32, pub bytes: u32, pub calls: u64, pub max_count: u32 }
const EMPTY_VGA: VgaInstruction = VgaInstruction { cs: 0, ip: 0, bytes: 0, calls: 0, max_count: 0 };
static mut VGA_INSTRUCTIONS: [VgaInstruction; 32] = [EMPTY_VGA; 32];

#[cfg(target_arch = "x86")]
pub(super) fn record_vga_instruction(cs: u16, ip: u32, bytes: u32, count: u32) {
    // Only the guest CPU writes; the event loop reads after that loan returns.
    for entry in unsafe { &mut *core::ptr::addr_of_mut!(VGA_INSTRUCTIONS) } {
        if entry.calls == 0 || (entry.cs == cs && entry.ip == ip && entry.bytes == bytes) {
            *entry = VgaInstruction { cs, ip, bytes, calls: entry.calls.wrapping_add(1), max_count: entry.max_count.max(count) };
            return;
        }
    }
}

pub(super) fn vga_instructions() -> [VgaInstruction; 32] {
    unsafe { *core::ptr::addr_of!(VGA_INSTRUCTIONS) }
}

#[cfg(target_arch = "x86")]
pub(super) fn record_device_entries(details: [[u32; 4]; 5]) {
    for (kind, [calls_lo, calls_hi, cycles_lo, cycles_hi]) in details.into_iter().enumerate() {
        unsafe {
            let counters = &mut (&mut *core::ptr::addr_of_mut!(DEVICE_ENTRIES))[kind];
            counters[0] = counters[0].wrapping_add(u64::from(calls_lo) | (u64::from(calls_hi) << 32));
            counters[1] = counters[1].wrapping_add(u64::from(cycles_lo) | (u64::from(cycles_hi) << 32));
        }
    }
}

pub(super) fn device_entries() -> [[u64; 2]; 5] {
    unsafe { *core::ptr::addr_of!(DEVICE_ENTRIES) }
}

pub(super) struct Sample(Option<u64>);
pub(super) struct Dispatch(Option<(usize, u64, u64)>);

impl Sample {
    pub(super) fn start<A: Arch>(machine: &A) -> Self {
        Self(super::startup::profile_enabled().then(|| machine.rdtsc()))
    }

    pub(super) fn returned<A: Arch>(
        self, machine: &A, event: &KernelEvent, regs: &Regs, personality: &Personality<A>,
    ) -> Dispatch {
        let Some(start) = self.0 else { return Dispatch(None) };
        let run = machine.rdtsc().wrapping_sub(start);
        let site = match personality {
            Personality::Dos(dos) => super::dos::vif_profile_site(dos).unwrap_or(0),
            _ => 0,
        };
        let (kind, key) = match *event {
            KernelEvent::Irq => (1, 0),
            KernelEvent::DebugTrap => (2, site),
            KernelEvent::VifWindow { entry_ip, .. } => (3, entry_ip),
            KernelEvent::SoftInt(n) => (4, if matches!(personality, Personality::Dos(_)) {
                super::dos::profile_interrupt_key(regs, n)
            } else { (u32::from(n) << 16) | regs.rax as u32 & 0xFFFF }),
            KernelEvent::In { port, .. } => (5, u32::from(port)),
            KernelEvent::Out { port, .. } => (6, u32::from(port)),
            KernelEvent::EmulatedStep { .. } => (7, site),
            KernelEvent::PageFault { addr } => (8, addr >> 12),
            KernelEvent::Hlt => (9, 0),
            KernelEvent::Fault => (10, 0),
            KernelEvent::Exception(n) => (11, u32::from(n)),
            KernelEvent::Syscall => (12, regs.rax as u32),
            KernelEvent::Ins { .. } => (13, regs.rdx as u32 & 0xFFFF),
            KernelEvent::Outs { .. } => (14, regs.rdx as u32 & 0xFFFF),
        };
        // Single cooperative event loop owns this storage. No IRQ accesses.
        // Keep table lookup outside the measured dispatch interval.
        unsafe {
            let counters = &mut *core::ptr::addr_of_mut!(COUNTERS);
            if counters.is_empty() { counters.resize(SLOTS, EMPTY); }
            let first = (key.wrapping_mul(2654435761) ^ kind) as usize % SLOTS;
            for probe in 0..SLOTS {
                let index = (first + probe) % SLOTS;
                let counter = &mut counters[index];
                if counter.kind == 0 || (counter.kind == kind && counter.key == key) {
                    counter.kind = kind;
                    counter.key = key;
                    counter.cs = u32::from(regs.code_seg());
                    counter.ip = regs.ip32();
                    return Dispatch(Some((index, run, machine.rdtsc())));
                }
            }
            OVERFLOW += 1;
        }
        Dispatch(None)
    }
}

impl Dispatch {
    pub(super) fn finish<A: Arch>(self, machine: &A) {
        let Some((index, run, start)) = self.0 else { return };
        let elapsed = machine.rdtsc().wrapping_sub(start);
        unsafe {
            let counter = &mut (&mut *core::ptr::addr_of_mut!(COUNTERS))[index];
            counter.calls += 1;
            counter.run += run;
            counter.dispatch += elapsed;
            counter.max_dispatch = counter.max_dispatch.max(elapsed);
        }
    }
}

pub(super) fn reset() {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(COUNTERS)).fill(EMPTY);
        OVERFLOW = 0;
        RM_TARGETS = [(0, 0, 0, 0); RM_TARGET_SLOTS];
        READ_DETAILS = [(0, 0, 0); READ_DETAIL_SLOTS];
        DIRECT_RM_PHASES = [0; 4];
        DEVICE_ENTRIES = [[0; 2]; 5];
        VGA_INSTRUCTIONS = [EMPTY_VGA; 32];
    }
    super::block::cache::profile_reset();
}

pub(super) fn record_direct_rm_phases(setup: u64, dispatch: u64, unwind: u64) {
    unsafe {
        let phases = &mut *core::ptr::addr_of_mut!(DIRECT_RM_PHASES);
        phases[0] = phases[0].wrapping_add(1);
        phases[1] = phases[1].wrapping_add(setup);
        phases[2] = phases[2].wrapping_add(dispatch);
        phases[3] = phases[3].wrapping_add(unwind);
    }
}

pub(super) fn direct_rm_phases() -> [u64; 4] {
    unsafe { *core::ptr::addr_of!(DIRECT_RM_PHASES) }
}

fn record_dos_read_detail(size: u16, fetch: u64, copy: u64) {
    if !super::startup::profile_enabled() { return; }
    unsafe {
        let details = &mut *core::ptr::addr_of_mut!(READ_DETAILS);
        if let Some(entry) = details.iter_mut().find(|entry| entry.0 == size || entry.0 == 0) {
            entry.0 = size;
            entry.1 = entry.1.wrapping_add(fetch);
            entry.2 = entry.2.wrapping_add(copy);
        }
    }
}

pub(super) fn record_dos_read_fetch(size: u16, cycles: u64) {
    record_dos_read_detail(size, cycles, 0);
}

pub(super) fn record_dos_read_copy(size: u16, cycles: u64) {
    record_dos_read_detail(size, 0, cycles);
}

/// Record a DPMI 0300/0301/0302 destination.
pub(super) fn record_rm_target(kind: u8, cs: u16, ip: u16) {
    if !super::startup::profile_enabled() { return; }
    unsafe {
        let targets = &mut *core::ptr::addr_of_mut!(RM_TARGETS);
        if let Some(entry) = targets
            .iter_mut()
            .find(|entry| (entry.0 == kind && entry.1 == cs && entry.2 == ip) || entry.3 == 0)
        {
            entry.0 = kind;
            entry.1 = cs;
            entry.2 = ip;
            entry.3 = entry.3.wrapping_add(1);
        }
    }
}

pub(super) fn visit_rm_targets(mut visit: impl FnMut(u8, u16, u16, u64)) {
    for &(kind, cs, ip, calls) in unsafe { &*core::ptr::addr_of!(RM_TARGETS) } {
        if calls != 0 {
            visit(kind, cs, ip, calls);
        }
    }
}

pub(super) fn print() {
    for (name, [calls, cycles]) in DEVICE_NAMES.into_iter().zip(device_entries()) {
        crate::compact_println!("[device-prof] {} calls={} cycles={}", name, calls, cycles);
    }
    for entry in vga_instructions().into_iter().filter(|entry| entry.calls != 0) {
        crate::compact_println!("[vga-instruction] at={:04x}:{:08x} bytes={:08x} calls={} max_count={}",
            entry.cs, entry.ip, entry.bytes, entry.calls, entry.max_count);
    }
    for c in unsafe { &*core::ptr::addr_of!(COUNTERS) } {
        if c.calls != 0 {
            crate::compact_println!(
                "[event-prof] kind={} key={:08x} calls={} run={} dispatch={} max={} at={:04x}:{:08x}",
                c.kind, c.key, c.calls, c.run, c.dispatch, c.max_dispatch, c.cs, c.ip,
            );
        }
    }
    crate::compact_println!("[event-prof] overflow={}", unsafe { OVERFLOW });
}

/// Visit profiled DOS file reads without routing the data through the ambient
/// log UART. Large COM1 dumps can outrun an emulator's serial sink; the
/// diagnostic control channel emits these counters as one structured reply.
pub(super) fn visit_dos_file_reads(mut visit: impl FnMut(u16, u64, u64, u64, u64, u64)) {
    for counter in unsafe { &*core::ptr::addr_of!(COUNTERS) } {
        if counter.kind == 4 && counter.key >> 16 == 0x213F && counter.calls != 0 {
            let detail = unsafe { &*core::ptr::addr_of!(READ_DETAILS) }
                .iter()
                .find(|detail| detail.0 == counter.key as u16)
                .copied()
                .unwrap_or((0, 0, 0));
            visit(
                counter.key as u16,
                counter.calls,
                counter.dispatch,
                counter.max_dispatch,
                detail.1,
                detail.2,
            );
        }
    }
}

/// kind, key, CS, IP, calls, guest cycles, dispatch cycles, maximum dispatch.
pub(super) type EventSummary = (u32, u32, u32, u32, u64, u64, u64, u64);

/// Return the busiest event classes in descending dispatch-cycle order for
/// the serial-control profiler. A bounded list keeps the reply well below the
/// UART timeout while retaining every material kernel-side cost.
pub(super) fn top(limit: usize) -> alloc::vec::Vec<EventSummary> {
    let mut counters: alloc::vec::Vec<_> = unsafe { &*core::ptr::addr_of!(COUNTERS) }
        .iter()
        .filter(|counter| counter.calls != 0)
        .map(|counter| (
            counter.kind,
            counter.key,
            counter.cs,
            counter.ip,
            counter.calls,
            counter.run,
            counter.dispatch,
            counter.max_dispatch,
        ))
        .collect();
    counters.sort_unstable_by_key(|counter| core::cmp::Reverse(counter.6));
    counters.truncate(limit);
    counters
}
