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
pub(super) const FILE_IO_NAMES: [&str; 50] = ["read_allocate", "read_fetch", "read_copy", "mmap_zero", "mmap_read", "mmap_copy", "elf_allocate", "elf_read", "elf_copy", "ext4_read", "volume_read", "vfs_lock", "vfs_read", "cache_check", "cache_miss", "elf_seek", "cache_insert", "pipe_wait", "pipe_allocate", "disk_read", "disk_write", "disk_flush", "volume_flush", "smb_send", "smb_receive", "smb_sign", "smb_verify", "smb_response_allocate", "smb_read_decode", "smb_encode", "ext4_create", "ext4_set_meta", "ext4_mkdir", "ext4_commit_write", "ext4_unlink", "ext4_rmdir", "ext4_fsync", "ext4_resize", "directory_scan", "path_resolve", "write_permission", "loop_writeback", "loop_klog_sync", "loop_deadlines", "task_snapshot", "loop_network", "write_refresh", "rtc_read", "loop_prelude", "alarm_arm"];
pub(super) const LOOP_WRITEBACK: usize = 41;
pub(super) const LOOP_KLOG_SYNC: usize = 42;
pub(super) const LOOP_DEADLINES: usize = 43;
pub(super) const TASK_SNAPSHOT: usize = 44;
pub(super) const LOOP_NETWORK: usize = 45;
pub(super) const WRITE_REFRESH: usize = 46;
pub(super) const RTC_READ: usize = 47;
pub(super) const LOOP_PRELUDE: usize = 48;
pub(super) const ALARM_ARM: usize = 49;
static mut FILE_IO: [[u64; 3]; FILE_IO_NAMES.len()] = [[0; 3]; FILE_IO_NAMES.len()];
static mut FILE_IO_MAX: [u64; FILE_IO_NAMES.len()] = [0; FILE_IO_NAMES.len()];
pub(super) fn file_io_max() -> [u64; FILE_IO_NAMES.len()] { unsafe { *core::ptr::addr_of!(FILE_IO_MAX) } }

pub(super) const DIRECTORY_FIELDS: [&str; 10] = ["hits", "misses", "builds", "entries_loaded", "build_ns",
    "namespace_invalidations", "metadata_invalidations", "write_invalidations", "dynamic_invalidations", "global_invalidations"];
static mut DIRECTORIES: alloc::collections::BTreeMap<alloc::vec::Vec<u8>, [u64; 10]> = alloc::collections::BTreeMap::new();
pub(super) fn directory_event(path: &[u8], field: usize, count: u64) {
    if !super::startup::profile_enabled() { return; }
    let counters = unsafe { &mut *core::ptr::addr_of_mut!(DIRECTORIES) };
    if let Some(row) = counters.get_mut(path) { row[field] = row[field].wrapping_add(count); }
    else { let mut row = [0; 10]; row[field] = count; counters.insert(path.to_vec(), row); }
}
pub(super) fn directory_count() -> usize { unsafe { (&*core::ptr::addr_of!(DIRECTORIES)).len() } }
pub(super) fn directory_totals() -> [u64; 10] {
    let mut totals = [0u64; 10];
    for row in unsafe { &*core::ptr::addr_of!(DIRECTORIES) }.values() {
        for (total, value) in totals.iter_mut().zip(row) { *total = total.wrapping_add(*value); }
    }
    totals
}
pub(super) fn directories_top(limit: usize) -> alloc::vec::Vec<(&'static [u8], [u64; 10])> {
    let mut rows: alloc::vec::Vec<_> = unsafe { &*core::ptr::addr_of!(DIRECTORIES) }.iter()
        .map(|(path, counters)| (path.as_slice(), *counters)).collect();
    rows.sort_unstable_by_key(|(_, values)| core::cmp::Reverse(values[4]));
    rows.truncate(limit);
    rows
}
pub(super) fn overflow() -> u64 { unsafe { OVERFLOW } }

pub(super) struct FileIoScope { stage: usize, bytes: usize, start: Option<u64> }
impl FileIoScope {
    pub(super) fn start(stage: usize, bytes: usize) -> Self {
        Self { stage, bytes, start: file_io_start() }
    }
}
impl Drop for FileIoScope {
    fn drop(&mut self) { file_io_finish(self.stage, self.bytes, self.start); }
}

pub(crate) fn file_io_start() -> Option<u64> {
    super::startup::profile_enabled().then(super::portio::now_ns)
}
pub(crate) fn file_io_finish(stage: usize, bytes: usize, start: Option<u64>) {
    if let Some(start) = start {
        let elapsed = super::portio::now_ns().saturating_sub(start);
        let counters = unsafe { &mut (*core::ptr::addr_of_mut!(FILE_IO))[stage] };
        counters[0] = counters[0].wrapping_add(1);
        counters[1] = counters[1].wrapping_add(bytes as u64);
        counters[2] = counters[2].wrapping_add(elapsed);
        unsafe {
            let maximum = &mut (*core::ptr::addr_of_mut!(FILE_IO_MAX))[stage];
            *maximum = (*maximum).max(elapsed);
        }
    }
}
pub(super) fn file_io() -> [[u64; 3]; FILE_IO_NAMES.len()] { unsafe { *core::ptr::addr_of!(FILE_IO) } }
// Native device shortcuts do not create event-loop events. Keep their cost
// separate, including failed attempts that subsequently take the normal path.
pub(super) const DEVICE_NAMES: [&str; 7] = ["vga_mov", "vga_generic", "vga_status", "vga_mask", "dma_poll", "vga_palette", "opl_status"];
static mut DEVICE_ENTRIES: [[u64; 2]; 7] = [[0; 2]; 7];
#[derive(Clone, Copy)]
pub(super) struct VgaInstruction { pub cs: u16, pub ip: u32, pub bytes: u32, pub calls: u64, pub max_count: u32 }
const EMPTY_VGA: VgaInstruction = VgaInstruction { cs: 0, ip: 0, bytes: 0, calls: 0, max_count: 0 };
static mut VGA_INSTRUCTIONS: [VgaInstruction; 32] = [EMPTY_VGA; 32];
#[derive(Clone, Copy)]
struct StatusPoll { cs: u16, ip: u32, calls: u64, high: u64, max_ns: u64 }
const EMPTY_POLL: StatusPoll = StatusPoll { cs: 0, ip: 0, calls: 0, high: 0, max_ns: 0 };
static mut STATUS_POLLS: [StatusPoll; 8] = [EMPTY_POLL; 8];
static mut LAST_STATUS_POLL: Option<(u16, u32, u8, u64)> = None;
#[derive(Clone, Copy)]
struct TimedEvent { ns: u64, kind: u32, value: u32 }
const EMPTY_TIMED: TimedEvent = TimedEvent { ns: 0, kind: 0, value: 0 };
static mut TIMELINE: alloc::vec::Vec<TimedEvent> = alloc::vec::Vec::new();
static mut TIMELINE_USED: usize = 0;
static mut OPL_INDEX: u8 = 0;

/// BSP-only, preallocated diagnostic events: frame address, palette begin/end,
/// and OPL key transitions. Recording never allocates or logs in the hot path.
pub(super) fn timed_event(now: u64, kind: u32, value: u32) {
    if !super::startup::profile_enabled() { return; }
    unsafe {
        let events = &mut *core::ptr::addr_of_mut!(TIMELINE);
        if TIMELINE_USED < events.len() {
            events[TIMELINE_USED] = TimedEvent { ns: now, kind, value };
            TIMELINE_USED += 1;
        }
    }
}

#[cfg(target_arch = "x86")]
pub(super) fn record_status_poll(cs: u16, ip: u32, status: u8, now: u64) {
    // Consecutive reads at one instruction, including time spent in timer
    // handlers between reads. The status level changing ends that wait.
    let level = status & 8;
    let start = unsafe {
        match LAST_STATUS_POLL {
            Some((old_cs, old_ip, old_level, start))
                if (cs, ip, level) == (old_cs, old_ip, old_level) => start,
            _ => { LAST_STATUS_POLL = Some((cs, ip, level, now)); now }
        }
    };
    for entry in unsafe { &mut *core::ptr::addr_of_mut!(STATUS_POLLS) } {
        if entry.calls == 0 || (entry.cs, entry.ip) == (cs, ip) {
            entry.cs = cs;
            entry.ip = ip;
            entry.calls += 1;
            entry.high += u64::from(level != 0);
            entry.max_ns = entry.max_ns.max(now.saturating_sub(start));
            break;
        }
    }
}

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
pub(super) fn record_device_entries(details: [[u32; 4]; 7]) {
    for (kind, [calls_lo, calls_hi, cycles_lo, cycles_hi]) in details.into_iter().enumerate() {
        unsafe {
            let counters = &mut (&mut *core::ptr::addr_of_mut!(DEVICE_ENTRIES))[kind];
            counters[0] = counters[0].wrapping_add(u64::from(calls_lo) | (u64::from(calls_hi) << 32));
            counters[1] = counters[1].wrapping_add(u64::from(cycles_lo) | (u64::from(cycles_hi) << 32));
        }
    }
}

pub(super) fn device_entries() -> [[u64; 2]; 7] {
    unsafe { *core::ptr::addr_of!(DEVICE_ENTRIES) }
}

/// Syscalls have their own unbounded table: faults and port traffic must not
/// evict them from the bounded guest-event profile. ABI distinguishes equal
/// syscall numbers with different meanings. Only the event loop accesses it.
static mut SYSCALLS: alloc::collections::BTreeMap<(u32, u32), [u64; 3]> =
    alloc::collections::BTreeMap::new();

pub(crate) struct SyscallScope { key: (u32, u32), start: Option<u64> }
impl SyscallScope {
    pub(crate) fn start(number: u32, mode64: bool) -> Self {
        let key = (if mode64 { 64 } else { 32 }, number);
        let start = if super::startup::profile_enabled() {
            // Allocate/lookup outside the measured handler interval.
            unsafe { (&mut *core::ptr::addr_of_mut!(SYSCALLS)).entry(key).or_default(); }
            Some(super::portio::now_ns())
        } else { None };
        Self { key, start }
    }
}
impl Drop for SyscallScope {
    fn drop(&mut self) {
        let Some(start) = self.start else { return; };
        let elapsed = super::portio::now_ns().saturating_sub(start);
        unsafe {
            let counters = (&mut *core::ptr::addr_of_mut!(SYSCALLS)).get_mut(&self.key)
                .expect("profiled syscall has a counter");
            counters[0] = counters[0].wrapping_add(1);
            counters[1] = counters[1].wrapping_add(elapsed);
            counters[2] = counters[2].max(elapsed);
        }
    }
}

pub(super) fn visit_syscalls(mut visit: impl FnMut(u32, u32, u64, u64, u64)) {
    for (&(abi, number), &[calls, ns, max]) in unsafe { &*core::ptr::addr_of!(SYSCALLS) } {
        visit(abi, number, calls, ns, max);
    }
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
            KernelEvent::PageFault { addr } => (8, (addr >> 12) as u32),
            KernelEvent::Hlt => (9, 0),
            KernelEvent::Fault => (10, 0),
            KernelEvent::Exception(n) => (11, u32::from(n)),
            KernelEvent::Syscall => (12, regs.rax as u32),
            KernelEvent::Ins { .. } => (13, regs.rdx as u32 & 0xFFFF),
            KernelEvent::Outs { .. } => (14, regs.rdx as u32 & 0xFFFF),
        };
        if let KernelEvent::Out { port, .. } = *event {
            if port == 0x388 { unsafe { OPL_INDEX = regs.rax as u8; } }
            if port == 0x389 {
                let index = unsafe { OPL_INDEX };
                if (0xb0..=0xb8).contains(&index) {
                    timed_event(machine.now(), 4, u32::from(index) << 8 | regs.rax as u32 & 255);
                }
            }
        }
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
        (&mut *core::ptr::addr_of_mut!(SYSCALLS)).clear();
        RM_TARGETS = [(0, 0, 0, 0); RM_TARGET_SLOTS];
        READ_DETAILS = [(0, 0, 0); READ_DETAIL_SLOTS];
        DIRECT_RM_PHASES = [0; 4];
        FILE_IO = [[0; 3]; FILE_IO_NAMES.len()];
        FILE_IO_MAX = [0; FILE_IO_NAMES.len()];
        (&mut *core::ptr::addr_of_mut!(DIRECTORIES)).clear();
        DEVICE_ENTRIES = [[0; 2]; 7];
        VGA_INSTRUCTIONS = [EMPTY_VGA; 32];
        STATUS_POLLS = [EMPTY_POLL; 8];
        LAST_STATUS_POLL = None;
        (&mut *core::ptr::addr_of_mut!(TIMELINE)).resize(2048, EMPTY_TIMED);
        TIMELINE_USED = 0;
        OPL_INDEX = 0;
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
    let [allocs, alloc_ticks, alloc_max, frees, free_ticks, free_max] = lib::heap::profile();
    crate::compact_println!("[heap-prof] allocs={} ticks={} max={} frees={} ticks={} max={}",
        allocs, alloc_ticks, alloc_max, frees, free_ticks, free_max);
    visit_syscalls(|abi, number, calls, ns, max| {
        crate::compact_println!("[syscall-prof] abi={} nr={} calls={} ns={} max_ns={}",
            abi, number, calls, ns, max);
    });
    // Include I/O in the F12 dump as well as COM2 replies: physical machines
    // may have no connected diagnostic UART, but retain their kernel log.
    for (name, [calls, bytes, ns]) in FILE_IO_NAMES.into_iter().zip(file_io()) {
        if calls != 0 {
            crate::compact_println!("[io-prof] {} calls={} bytes={} ns={}", name, calls, bytes, ns);
        }
    }
    for event in unsafe { &(&*core::ptr::addr_of!(TIMELINE))[..TIMELINE_USED] } {
        crate::compact_println!("[frame-timeline] ns={} kind={} value={}", event.ns, event.kind, event.value);
    }
    for entry in unsafe { *core::ptr::addr_of!(STATUS_POLLS) }.into_iter().filter(|entry| entry.calls != 0) {
        crate::compact_println!("[vga-poll] at={:04x}:{:08x} calls={} high={} max_us={}",
            entry.cs, entry.ip, entry.calls, entry.high, entry.max_ns / 1000);
    }
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
