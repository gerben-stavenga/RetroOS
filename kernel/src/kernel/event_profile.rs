//! Opt-in startup/event timings. Run includes guest execution and arch
//! entry/exit; dispatch covers event handling. No logging in measured paths.
#![forbid(unsafe_code)]

use crate::{Core, KernelEvent, Regs};
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
static COUNTERS: spin::Mutex<alloc::vec::Vec<Counter>> = spin::Mutex::new(alloc::vec::Vec::new());
static OVERFLOW: spin::Mutex<u64> = spin::Mutex::new(0);
const RM_TARGET_SLOTS: usize = 32;
static RM_TARGETS: spin::Mutex<[(u8, u16, u16, u64); RM_TARGET_SLOTS]> = spin::Mutex::new([(0, 0, 0, 0); RM_TARGET_SLOTS]);
const READ_DETAIL_SLOTS: usize = 64;
static READ_DETAILS: spin::Mutex<[(u16, u64, u64); READ_DETAIL_SLOTS]> = spin::Mutex::new([(0, 0, 0); READ_DETAIL_SLOTS]);
// calls, RM-call setup, DOS vector dispatch, continuation unwind.
static DIRECT_RM_PHASES: spin::Mutex<[u64; 4]> = spin::Mutex::new([0; 4]);
pub(super) const FILE_IO_NAMES: [&str; 49] = ["read_allocate", "read_fetch", "read_copy", "mmap_zero", "mmap_read", "mmap_copy", "elf_allocate", "elf_read", "elf_copy", "ext4_read", "volume_read", "vfs_lock", "vfs_read", "cache_check", "cache_miss", "elf_seek", "cache_insert", "pipe_wait", "pipe_allocate", "disk_read", "disk_write", "disk_flush", "volume_flush", "smb_send", "smb_receive", "smb_sign", "smb_verify", "smb_response_allocate", "smb_read_decode", "smb_encode", "ext4_create", "ext4_set_meta", "ext4_mkdir", "ext4_commit_write", "ext4_unlink", "ext4_rmdir", "ext4_fsync", "ext4_resize", "directory_scan", "path_resolve", "write_permission", "loop_writeback", "loop_klog_sync", "loop_deadlines", "task_snapshot", "loop_network", "write_refresh", "rtc_read", "loop_prelude"];
pub(super) const LOOP_WRITEBACK: usize = 41;
pub(super) const LOOP_KLOG_SYNC: usize = 42;
pub(super) const LOOP_DEADLINES: usize = 43;
pub(super) const TASK_SNAPSHOT: usize = 44;
pub(super) const LOOP_NETWORK: usize = 45;
pub(super) const WRITE_REFRESH: usize = 46;
pub(super) const RTC_READ: usize = 47;
pub(super) const LOOP_PRELUDE: usize = 48;
static FILE_IO: spin::Mutex<([[u64; 3]; FILE_IO_NAMES.len()], [u64; FILE_IO_NAMES.len()])> =
    spin::Mutex::new(([[0; 3]; FILE_IO_NAMES.len()], [0; FILE_IO_NAMES.len()]));
pub(super) fn file_io_max() -> [u64; FILE_IO_NAMES.len()] { FILE_IO.lock().1 }

pub(super) const DIRECTORY_FIELDS: [&str; 10] = ["hits", "misses", "builds", "entries_loaded", "build_ns",
    "namespace_invalidations", "metadata_invalidations", "write_invalidations", "dynamic_invalidations", "global_invalidations"];
static DIRECTORIES: spin::Mutex<alloc::collections::BTreeMap<alloc::vec::Vec<u8>, [u64; 10]>> = spin::Mutex::new(alloc::collections::BTreeMap::new());
pub(super) fn directory_event(path: &[u8], field: usize, count: u64) {
    if super::parallel::on_worker() {
        if super::startup::detail_profile_enabled() {
            let mut profile = worker_profile().lock();
            if !super::startup::detail_profile_enabled() { return; }
            let row = profile.directories.entry(path.to_vec()).or_default();
            row[field] = row[field].wrapping_add(count);
        }
        return;
    }
    if !super::startup::profile_enabled() { return; }
    let mut counters = DIRECTORIES.lock();
    if let Some(row) = counters.get_mut(path) { row[field] = row[field].wrapping_add(count); }
    else { let mut row = [0; 10]; row[field] = count; counters.insert(path.to_vec(), row); }
}
pub(super) fn directory_count() -> usize { DIRECTORIES.lock().len() }
pub(super) fn directory_totals() -> [u64; 10] {
    let mut totals = [0u64; 10];
    for row in DIRECTORIES.lock().values() {
        for (total, value) in totals.iter_mut().zip(row) { *total = total.wrapping_add(*value); }
    }
    totals
}
pub(super) fn directories_top(limit: usize) -> alloc::vec::Vec<(alloc::vec::Vec<u8>, [u64; 10])> {
    let mut rows: alloc::vec::Vec<_> = DIRECTORIES.lock().iter()
        .map(|(path, counters)| (path.clone(), *counters)).collect();
    rows.sort_unstable_by_key(|(_, values)| core::cmp::Reverse(values[4]));
    rows.truncate(limit);
    rows
}
pub(super) fn overflow() -> u64 { *OVERFLOW.lock() }

/// Worker measurements are CPU time and may overlap. They never contribute
/// to the disjoint BSP wall-time ledger or its nested I/O tables.
#[derive(Clone)]
pub(super) struct WorkerProfile {
    pub reset_ns: u64,
    pub syscalls: alloc::collections::BTreeMap<(u32, u32), [u64; 3]>,
    pub io: [[u64; 3]; FILE_IO_NAMES.len()],
    pub io_max: [u64; FILE_IO_NAMES.len()],
    pub directories: alloc::collections::BTreeMap<alloc::vec::Vec<u8>, [u64; 10]>,
}
impl WorkerProfile {
    const fn new() -> Self { Self { reset_ns: 0,
        syscalls: alloc::collections::BTreeMap::new(),
        io: [[0; 3]; FILE_IO_NAMES.len()], io_max: [0; FILE_IO_NAMES.len()],
        directories: alloc::collections::BTreeMap::new() } }
}
static WORKER_PROFILES: [spin::Mutex<WorkerProfile>; 64] =
    [const { spin::Mutex::new(WorkerProfile::new()) }; 64];
fn worker_profile() -> &'static spin::Mutex<WorkerProfile> {
    &WORKER_PROFILES[super::parallel::profile_cpu()]
}
pub(super) fn worker_profiles() -> alloc::vec::Vec<(usize, WorkerProfile)> {
    WORKER_PROFILES.iter().enumerate().skip(1).filter_map(|(cpu, profile)| {
        let profile = profile.lock();
        (!profile.syscalls.is_empty() || profile.io.iter().any(|row| row[0] != 0))
            .then(|| (cpu, profile.clone()))
    }).collect()
}

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
    super::startup::detail_profile_enabled().then(super::portio::now_ns)
}
pub(crate) fn file_io_finish(stage: usize, bytes: usize, start: Option<u64>) {
    if let Some(start) = start {
        let elapsed = super::portio::now_ns().saturating_sub(start);
        if super::parallel::on_worker() {
            let mut profile = worker_profile().lock();
            if start < profile.reset_ns || !super::startup::detail_profile_enabled() { return; }
            let row = &mut profile.io[stage];
            row[0] = row[0].wrapping_add(1);
            row[1] = row[1].wrapping_add(bytes as u64);
            row[2] = row[2].wrapping_add(elapsed);
            profile.io_max[stage] = profile.io_max[stage].max(elapsed);
            return;
        }
        let mut profile = FILE_IO.lock();
        let counters = &mut profile.0[stage];
        counters[0] = counters[0].wrapping_add(1);
        counters[1] = counters[1].wrapping_add(bytes as u64);
        counters[2] = counters[2].wrapping_add(elapsed);
        profile.1[stage] = profile.1[stage].max(elapsed);
    }
}
pub(super) fn file_io() -> [[u64; 3]; FILE_IO_NAMES.len()] { FILE_IO.lock().0 }
// Native device shortcuts do not create event-loop events. Keep their cost
// separate, including failed attempts that subsequently take the normal path.
pub(super) const DEVICE_NAMES: [&str; 7] = ["vga_mov", "vga_generic", "vga_status", "vga_mask", "dma_poll", "vga_palette", "opl_status"];
static DEVICE_ENTRIES: spin::Mutex<[[u64; 2]; 7]> = spin::Mutex::new([[0; 2]; 7]);
#[derive(Clone, Copy)]
struct TimedEvent { ns: u64, kind: u32, value: u32 }
static TIMELINE: spin::Mutex<alloc::vec::Vec<TimedEvent>> = spin::Mutex::new(alloc::vec::Vec::new());
static OPL_INDEX: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// BSP-only, preallocated diagnostic events: frame address, palette begin/end,
/// and OPL key transitions. Recording never allocates or logs in the hot path.
pub(super) fn timed_event(now: u64, kind: u32, value: u32) {
    if !super::startup::profile_enabled() { return; }
    let mut events = TIMELINE.lock();
    if events.len() < events.capacity() {
        events.push(TimedEvent { ns: now, kind, value });
    }
}

pub(super) fn record_device_entries(details: [[u32; 4]; 7]) {
    let mut entries = DEVICE_ENTRIES.lock();
    for (kind, [calls_lo, calls_hi, cycles_lo, cycles_hi]) in details.into_iter().enumerate() {
        let counters = &mut entries[kind];
        counters[0] = counters[0].wrapping_add(u64::from(calls_lo) | (u64::from(calls_hi) << 32));
        counters[1] = counters[1].wrapping_add(u64::from(cycles_lo) | (u64::from(cycles_hi) << 32));
    }
}

pub(super) fn device_entries() -> [[u64; 2]; 7] {
    *DEVICE_ENTRIES.lock()
}

/// Syscalls have their own unbounded table: faults and port traffic must not
/// evict them from the bounded guest-event profile. ABI distinguishes equal
/// syscall numbers with different meanings. Only the event loop accesses it.
static SYSCALLS: spin::Mutex<alloc::collections::BTreeMap<(u32, u32), [u64; 3]>> = spin::Mutex::new(alloc::collections::BTreeMap::new());

pub(crate) struct SyscallScope { key: (u32, u32), start: Option<u64> }
impl SyscallScope {
    pub(crate) fn start(number: u32, mode64: bool) -> Self {
        let key = (if mode64 { 64 } else { 32 }, number);
        let start = if super::startup::detail_profile_enabled() {
            // Allocate/lookup outside the measured handler interval.
            if super::parallel::on_worker() {
                let mut profile = worker_profile().lock();
                if !super::startup::detail_profile_enabled() { return Self { key, start: None }; }
                profile.syscalls.entry(key).or_default();
            }
            else { SYSCALLS.lock().entry(key).or_default(); }
            Some(super::portio::now_ns())
        } else { None };
        Self { key, start }
    }
}
impl Drop for SyscallScope {
    fn drop(&mut self) {
        let Some(start) = self.start else { return; };
        let elapsed = super::portio::now_ns().saturating_sub(start);
        if super::parallel::on_worker() {
            let mut profile = worker_profile().lock();
            if start < profile.reset_ns || !super::startup::detail_profile_enabled() { return; }
            let row = profile.syscalls.entry(self.key).or_default();
            row[0] = row[0].wrapping_add(1);
            row[1] = row[1].wrapping_add(elapsed);
            row[2] = row[2].max(elapsed);
            return;
        }
        let mut syscalls = SYSCALLS.lock();
        let counters = syscalls.get_mut(&self.key)
            .expect("profiled syscall has a counter");
        counters[0] = counters[0].wrapping_add(1);
        counters[1] = counters[1].wrapping_add(elapsed);
        counters[2] = counters[2].max(elapsed);
    }
}

pub(super) fn visit_syscalls(mut visit: impl FnMut(u32, u32, u64, u64, u64)) {
    let syscalls = SYSCALLS.lock().clone();
    for ((abi, number), [calls, ns, max]) in syscalls {
        visit(abi, number, calls, ns, max);
    }
}

pub(super) struct Sample(Option<u64>);
pub(super) struct Dispatch(Option<(usize, u64, u64)>);

impl Sample {
    pub(super) fn start<A: Core>(_machine: &A) -> Self {
        Self(super::startup::profile_enabled().then(crate::kernel::event_profile::cycles))
    }

    pub(super) fn returned<A: Core>(
        self, machine: &A, event: &KernelEvent, regs: &Regs, personality: &Personality<A>,
    ) -> Dispatch {
        let Some(start) = self.0 else { return Dispatch(None) };
        let run = crate::kernel::event_profile::cycles().wrapping_sub(start);
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
            if port == 0x388 { OPL_INDEX.store(regs.rax as u8, core::sync::atomic::Ordering::Relaxed); }
            if port == 0x389 {
                let index = OPL_INDEX.load(core::sync::atomic::Ordering::Relaxed);
                if (0xb0..=0xb8).contains(&index) {
                    timed_event(machine.now(), 4, u32::from(index) << 8 | regs.rax as u32 & 255);
                }
            }
        }
        // Single cooperative event loop owns this storage. No IRQ accesses.
        // Keep table lookup outside the measured dispatch interval.
        let mut counters = COUNTERS.lock();
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
                return Dispatch(Some((index, run, crate::kernel::event_profile::cycles())));
            }
        }
        *OVERFLOW.lock() += 1;
        Dispatch(None)
    }
}

impl Dispatch {
    pub(super) fn finish<A: Core>(self, _machine: &A) {
        let Some((index, run, start)) = self.0 else { return };
        let elapsed = crate::kernel::event_profile::cycles().wrapping_sub(start);
        let mut counters = COUNTERS.lock();
        let counter = &mut counters[index];
        counter.calls += 1;
        counter.run += run;
        counter.dispatch += elapsed;
        counter.max_dispatch = counter.max_dispatch.max(elapsed);
    }
}

pub(super) fn reset() {
    let reset_ns = super::portio::now_ns();
    for profile in &WORKER_PROFILES {
        let mut profile = profile.lock();
        *profile = WorkerProfile { reset_ns, ..WorkerProfile::new() };
    }
    COUNTERS.lock().fill(EMPTY);
    *OVERFLOW.lock() = 0;
    SYSCALLS.lock().clear();
    *RM_TARGETS.lock() = [(0, 0, 0, 0); RM_TARGET_SLOTS];
    *READ_DETAILS.lock() = [(0, 0, 0); READ_DETAIL_SLOTS];
    *DIRECT_RM_PHASES.lock() = [0; 4];
    *FILE_IO.lock() = ([[0; 3]; FILE_IO_NAMES.len()], [0; FILE_IO_NAMES.len()]);
    DIRECTORIES.lock().clear();
    *DEVICE_ENTRIES.lock() = [[0; 2]; 7];
    {
        let mut timeline = TIMELINE.lock();
        timeline.clear();
        timeline.reserve_exact(2048);
    }
    OPL_INDEX.store(0, core::sync::atomic::Ordering::Relaxed);
    super::block::cache::profile_reset();
}

pub(super) fn record_direct_rm_phases(setup: u64, dispatch: u64, unwind: u64) {
    let mut phases = DIRECT_RM_PHASES.lock();
    phases[0] = phases[0].wrapping_add(1);
    phases[1] = phases[1].wrapping_add(setup);
    phases[2] = phases[2].wrapping_add(dispatch);
    phases[3] = phases[3].wrapping_add(unwind);
}

pub(super) fn direct_rm_phases() -> [u64; 4] {
    *DIRECT_RM_PHASES.lock()
}

fn record_dos_read_detail(size: u16, fetch: u64, copy: u64) {
    if !super::startup::profile_enabled() { return; }
    let mut details = READ_DETAILS.lock();
    if let Some(entry) = details.iter_mut().find(|entry| entry.0 == size || entry.0 == 0) {
        entry.0 = size;
        entry.1 = entry.1.wrapping_add(fetch);
        entry.2 = entry.2.wrapping_add(copy);
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
    let mut targets = RM_TARGETS.lock();
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

pub(super) fn visit_rm_targets(mut visit: impl FnMut(u8, u16, u16, u64)) {
    let targets = *RM_TARGETS.lock();
    for (kind, cs, ip, calls) in targets {
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
    let timeline = TIMELINE.lock().clone();
    for event in timeline {
        crate::compact_println!("[frame-timeline] ns={} kind={} value={}", event.ns, event.kind, event.value);
    }
    for (name, [calls, cycles]) in DEVICE_NAMES.into_iter().zip(device_entries()) {
        crate::compact_println!("[device-prof] {} calls={} cycles={}", name, calls, cycles);
    }
    let counters = COUNTERS.lock().clone();
    for c in counters {
        if c.calls != 0 {
            crate::compact_println!(
                "[event-prof] kind={} key={:08x} calls={} run={} dispatch={} max={} at={:04x}:{:08x}",
                c.kind, c.key, c.calls, c.run, c.dispatch, c.max_dispatch, c.cs, c.ip,
            );
        }
    }
    crate::compact_println!("[event-prof] overflow={}", overflow());
}

/// Visit profiled DOS file reads without routing the data through the ambient
/// log UART. Large COM1 dumps can outrun an emulator's serial sink; the
/// diagnostic control channel emits these counters as one structured reply.
pub(super) fn visit_dos_file_reads(mut visit: impl FnMut(u16, u64, u64, u64, u64, u64)) {
    let counters = COUNTERS.lock().clone();
    let details = *READ_DETAILS.lock();
    for counter in counters {
        if counter.kind == 4 && counter.key >> 16 == 0x213F && counter.calls != 0 {
            let detail = details
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
    let mut counters: alloc::vec::Vec<_> = COUNTERS.lock().iter()
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

/// Diagnostic cycle count in the units of the native execution counters.
#[inline]
pub fn cycles() -> u64 { super::portio::cycles() }
