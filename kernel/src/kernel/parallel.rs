//! Parallel Linux execution and ordinary syscall dispatch on worker CPUs.
//! Lifecycle actions acquire affected process loans while unrelated CPUs run.
use alloc::{boxed::Box, vec::Vec};
use core::{any::TypeId, cell::UnsafeCell, sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering}};
use crate::{Arch, KernelEvent, Regs};
use super::{exec_ctx::ExecutionContext, thread::{self, Thread, ThreadState}};

const PARKED: u32 = 0;
const IDLE: u32 = 1;
const RUN: u32 = 2;
const DONE: u32 = 3;
const DISABLED: u32 = 4;
const MAX_CPUS: usize = 64;
static START: AtomicBool = AtomicBool::new(false);
static SLOTS: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static BACKEND: spin::Once<TypeId> = spin::Once::new();
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_HANDLERS: AtomicUsize = AtomicUsize::new(0);
static BSP_EVENTS_WITH_WORKERS: AtomicUsize = AtomicUsize::new(0);
static PARALLEL_LIFECYCLES: AtomicUsize = AtomicUsize::new(0);
static PEAK_HANDLERS: AtomicUsize = AtomicUsize::new(0);
struct HandlerGuard;
impl HandlerGuard {
    fn enter() -> Self {
        let active = ACTIVE_HANDLERS.fetch_add(1, Ordering::AcqRel) + 1;
        PEAK_HANDLERS.fetch_max(active, Ordering::Relaxed); Self
    }
}
impl Drop for HandlerGuard { fn drop(&mut self) { ACTIVE_HANDLERS.fetch_sub(1, Ordering::Release); } }
pub(crate) fn bsp_events_with_workers() -> usize { BSP_EVENTS_WITH_WORKERS.load(Ordering::Relaxed) }
pub(crate) fn parallel_lifecycles() -> usize { PARALLEL_LIFECYCLES.load(Ordering::Relaxed) }
pub(crate) fn peak_handlers() -> usize { PEAK_HANDLERS.load(Ordering::Relaxed) }
#[thread_local]
static mut ON_WORKER: bool = false;
pub fn on_worker() -> bool { unsafe { ON_WORKER } }
#[thread_local]
static PROFILE_CPU: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
pub(crate) fn profile_cpu() -> usize { PROFILE_CPU.get() }

struct Loan<A: Arch> {
    space: A::PageTable,
    fx: A::Fx,
    regs: Regs,
    event: KernelEvent,
    deadline: u64,
    tls: (i32, u32, u32, bool),
    kernel: thread::KernelThread<A>,
    linux: super::linux::LinuxState,
    stats: WorkerStats,
}
#[derive(Clone, Copy, Default)]
pub(crate) struct WorkerStats {
    pub syscalls: u64,
    pub handler_ns: u64,
    pub lock_wait_ns: u64,
}
pub struct Slot<A: Arch> {
    state: AtomicU32,
    cancel: AtomicBool,
    pub processor: AtomicU32,
    supply: AtomicUsize,
    tid: AtomicUsize,
    loan: UnsafeCell<Loan<A>>,
}
// One BSP producer and one CPU consumer. RUN transfers the whole loan; DONE
// transfers it back after the worker removes all user entries from its root.
// Only cancel/state/processor/supply atomics are accessed by the BSP during
// execution. Shared Linux descriptors have their own Arc/Mutex protection;
// each process owns its remaining mutable Linux state.
unsafe impl<A: Arch> Sync for Slot<A> where A::PageTable: Send, A::Fx: Send {}
impl<A: Arch> Slot<A> {
    fn new() -> Self { Self {
        state: AtomicU32::new(PARKED), cancel: AtomicBool::new(false),
        processor: AtomicU32::new(0), supply: AtomicUsize::new(0), tid: AtomicUsize::new(0),
        loan: UnsafeCell::new(Loan { space: Default::default(), fx: Default::default(),
            regs: Regs::empty(), event: KernelEvent::Irq, deadline: 0, tls: (-1, 0, 0, false),
            kernel: thread::KernelThread::empty(), linux: super::linux::LinuxState::new(), stats: WorkerStats::default() }),
    } }
}
/// BSP boot only, before any worker starts. Storage remains resident forever.
pub fn provision<A: Arch>(count: usize) -> &'static [Slot<A>] {
    assert!(count <= MAX_CPUS && SLOTS.load(Ordering::Relaxed) == 0);
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count { slots.push(Slot::<A>::new()); }
    let slots = Box::leak(slots.into_boxed_slice());
    BACKEND.call_once(TypeId::of::<A>);
    SLOTS.store(slots.as_ptr() as usize, Ordering::Relaxed);
    COUNT.store(count, Ordering::Release);
    slots
}
fn slots<A: Arch>() -> &'static [Slot<A>] {
    if BACKEND.get() != Some(&TypeId::of::<A>()) { return &[]; }
    let count = COUNT.load(Ordering::Acquire);
    // The TypeId check proves this is exactly the A used to allocate the array.
    unsafe { core::slice::from_raw_parts(SLOTS.load(Ordering::Relaxed) as *const Slot<A>, count) }
}
pub fn enable() { START.store(true, Ordering::Release); }
pub fn started() -> bool { START.load(Ordering::Acquire) }
pub fn disable<A: Arch>(slot: &Slot<A>) { slot.state.store(DISABLED, Ordering::Release); }

/// AP ring-1 loop. Owns the process state while running the normal Linux
/// handlers. Shared task-table actions and device polling remain outside it.
/// # Safety
/// This CPU exclusively consumes slot. Stacks/TLS/slot storage are resident.
pub unsafe fn worker<A: Arch>(mut machine: A, slot: &'static Slot<A>) -> !
where A::PageTable: Send, A::Fx: Send {
    unsafe { ON_WORKER = true; }
    PROFILE_CPU.set(slots::<A>().iter().position(|s| core::ptr::eq(s, slot)).expect("unknown worker slot"));
    slot.supply.store(machine.page_supply().expect("worker has no page reserve") as usize, Ordering::Relaxed);
    slot.state.store(IDLE, Ordering::Release);
    loop {
        if slot.state.load(Ordering::Acquire) != RUN {
            machine.arm_alarm(None);
            if slot.state.load(Ordering::Acquire) != RUN { machine.idle(); }
            continue;
        }
        machine.refresh_kernel_mappings();
        let loan = unsafe { &mut *slot.loan.get() };
        let (entry, base, limit, pages) = loan.tls;
        if entry >= 0 { machine.set_tls_entry(entry, base, limit, pages); }
        let old = machine.activate(core::mem::take(&mut loan.space), &mut loan.fx, core::ptr::null_mut());
        machine.arm_alarm(Some(loan.deadline));
        let active = ACTIVE.fetch_add(1, Ordering::AcqRel) + 1;
        PEAK.fetch_max(active, Ordering::Relaxed);
        loan.event = run_linux(&mut machine, loan, slot);
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
        machine.arm_alarm(None);
        loan.space = machine.activate(old, &mut loan.fx, core::ptr::null_mut());
        slot.state.store(DONE, Ordering::Release);
    }
}

fn run_linux<A: Arch>(machine: &mut A, loan: &mut Loan<A>, slot: &Slot<A>) -> KernelEvent {
    loop {
        if slot.cancel.load(Ordering::Acquire) { return KernelEvent::Irq; }
        machine.refresh_kernel_mappings();
        super::memory::service(machine);
        let event = machine.execute(&mut loan.regs, &arch_abi::IoPolicy::deny_all());
        if !matches!(event, KernelEvent::Syscall | KernelEvent::SoftInt(0x80) | KernelEvent::Irq) {
            return event;
        }
        let _handler = HandlerGuard::enter();
        let entered = machine.now();
        machine.refresh_kernel_mappings();
        let action = super::linux::handle_event(machine, &mut loan.kernel, &mut loan.linux, &mut loan.regs, event);
        if matches!(event, KernelEvent::Syscall | KernelEvent::SoftInt(0x80)) {
            loan.stats.syscalls += 1;
            loan.stats.handler_ns += machine.now().saturating_sub(entered);
        }
        if !matches!(action, thread::KernelAction::Done)
            || !matches!(loan.kernel.state, ThreadState::Ready | ThreadState::Running)
            || slot.cancel.load(Ordering::Acquire) || machine.now() >= loan.deadline {
            loan.kernel.pending_action = Some(action);
            return KernelEvent::Irq;
        }
    }
}

pub struct Parallel {
    next_cpu: usize,
    batches: usize,
    kernel_cycles: u64,
}
impl Default for Parallel { fn default() -> Self { Self::new() } }
impl Parallel {
    pub const fn new() -> Self { Self { next_cpu: usize::MAX, batches: 0, kernel_cycles: 0 } }
    pub fn batches(&self) -> usize { self.batches }
    /// BSP preparation and rendezvous, excluded from guest/arch execution.
    pub fn take_kernel_cycles(&mut self) -> u64 { core::mem::take(&mut self.kernel_cycles) }
    pub fn enabled<A: Arch>(&self) -> bool { slots::<A>().iter().any(|s| matches!(s.state.load(Ordering::Acquire), IDLE | RUN | DONE)) }
    fn available<A: Arch>(&self, cpu: usize) -> bool {
        cpu == 0 || slots::<A>().get(cpu).is_some_and(|s| s.state.load(Ordering::Acquire) == IDLE)
    }
    fn affinity<A: Arch>(&mut self, threads: &mut [Thread<A>], tid: usize, current: usize) -> usize {
        let owner = match &threads[tid].personality {
            thread::Personality::Linux(linux) => linux.borrowed_space_owner(), _ => None,
        };
        if let Some(owner) = owner {
            if threads[owner].kernel.execution_cpu == usize::MAX {
                threads[owner].kernel.execution_cpu = 0;
                if self.next_cpu == usize::MAX { self.next_cpu = 2; }
            }
            let cpu = threads[owner].kernel.execution_cpu;
            threads[tid].kernel.execution_cpu = cpu;
            return cpu;
        }
        if threads[tid].kernel.execution_cpu == usize::MAX {
            let count = slots::<A>().len();
            if self.next_cpu == usize::MAX && tid == current {
                threads[tid].kernel.execution_cpu = 0;
                self.next_cpu = 2;
            } else {
                for step in 0..count {
                    let cpu = (self.next_cpu + step) % count;
                    if cpu == 0 || slots::<A>().get(cpu).is_some_and(|s| matches!(s.state.load(Ordering::Acquire), IDLE | RUN | DONE)) {
                        threads[tid].kernel.execution_cpu = cpu;
                        self.next_cpu = (cpu + 1) % count;
                        break;
                    }
                }
            }
        }
        threads[tid].kernel.execution_cpu
    }
    pub fn pending<A: Arch>(threads: &[Thread<A>], current: usize) -> Option<usize> {
        if threads[current].kernel.pending_event.is_some() { return None; }
        (1..threads.len()).map(|n| (current + n) % threads.len()).find(|&tid|
            threads[tid].kernel.pending_event.is_some()
            && matches!(threads[tid].kernel.state, ThreadState::Ready | ThreadState::Running))
    }
    /// Start work on free CPUs and return only the current process's loan.
    /// Other workers keep running across event-loop and lifecycle operations.
    pub fn execute<A: Arch>(
        &mut self, machine: &mut A, threads: &mut [Thread<A>], ctx: &mut ExecutionContext<A>,
        bios: &super::bios_display::BiosDisplayWorkspace<A>, deadline: u64,
    ) -> KernelEvent {
        self.kernel_cycles = 0;
        ctx.device_cycles = 0;
        collect_finished::<A>(threads);
        let current = ctx.tid;
        if let Some(event) = threads[current].kernel.pending_event.take() { return event; }
        if !self.enabled::<A>() || !matches!(threads[current].personality, thread::Personality::Linux(_)) {
            stop_all(machine, threads);
            return ctx.run(machine, bios, &mut threads[current].personality);
        }
        let started = machine.rdtsc();
        super::memory::service(machine);
        let mut chosen = [usize::MAX; MAX_CPUS];
        let cpu = self.affinity(threads, current, current);
        if self.available::<A>(cpu) { chosen[cpu] = current; }
        let now = machine.now();
        for tid in (current + 1..threads.len()).chain(1..=current) {
            if tid == current || threads[tid].kernel.pending_event.is_some()
                || !matches!(threads[tid].kernel.state, ThreadState::Ready | ThreadState::Running)
                || !matches!(&threads[tid].personality, thread::Personality::Linux(linux)
                    if !linux.has_blocked_work() && !linux.timer_due(now))
                || super::sched::vfork_suspended(threads, tid) { continue; }
            let cpu = self.affinity(threads, tid, current);
            if self.available::<A>(cpu) && chosen[cpu] == usize::MAX { chosen[cpu] = tid; }
        }
        if chosen[0] == current && chosen.iter().skip(1).all(|&tid| tid == usize::MAX) {
            return ctx.run(machine, bios, &mut threads[current].personality);
        }
        self.batches += 1;
        let mut fx = machine.clean_fx_template();
        threads[current].kernel.vcpu.space = machine.activate(Default::default(), &mut fx, core::ptr::null_mut());
        threads[current].kernel.vcpu.regs = ctx.regs;
        // The current process can remain parked when its assigned CPU is
        // occupied by a peer. Record this save even when no loan is issued.
        threads[current].kernel.cpu_hash = thread::hash_regs(&ctx.regs);
        threads[current].kernel.fx_state = fx;
        for &tid in &chosen {
            if tid == usize::MAX { continue; }
            let task = &mut threads[tid];
            let deferred = matches!(&task.personality, thread::Personality::Linux(linux) if linux.has_deferred_resume());
            if task.kernel.tables_private && !deferred { continue; }
            let mut fx = task.kernel.fx_state;
            let empty = machine.activate(core::mem::take(&mut task.kernel.vcpu.space), &mut fx, core::ptr::null_mut());
            if !task.kernel.tables_private { super::memory::private_tables(machine); }
            task.personality.on_resume(machine);
            task.kernel.vcpu.space = machine.activate(empty, &mut fx, core::ptr::null_mut());
            task.kernel.fx_state = fx;
            task.kernel.tables_private = true;
        }
        let all = slots::<A>();
        for (cpu, &tid) in chosen.iter().enumerate().skip(1) {
            if tid == usize::MAX { continue; }
            let slot = &all[cpu];
            let supply = slot.supply.load(Ordering::Acquire) as *mut arch_abi::page_supply::PageSupply;
            unsafe { super::memory::replenish(supply); }
            let task = &mut threads[tid];
            let thread::Personality::Linux(linux) = &task.personality else { unreachable!() };
            let loan = unsafe { &mut *slot.loan.get() };
            loan.space = core::mem::take(&mut task.kernel.vcpu.space);
            loan.fx = task.kernel.fx_state;
            loan.regs = task.kernel.vcpu.regs;
            loan.deadline = deadline;
            loan.tls = (linux.tls_entry, linux.tls_base, linux.tls_limit, linux.tls_limit_in_pages);
            core::mem::swap(&mut loan.kernel, &mut task.kernel);
            let thread::Personality::Linux(linux) = &mut task.personality else { unreachable!() };
            core::mem::swap(&mut loan.linux, linux);
            loan.linux.worker_snapshot(linux);
            task.kernel.tid = loan.kernel.tid;
            task.kernel.pid = loan.kernel.pid;
            task.kernel.parent_tid = loan.kernel.parent_tid;
            task.kernel.priority = loan.kernel.priority;
            task.kernel.time = loan.kernel.time;
            task.kernel.comm = loan.kernel.comm;
            task.kernel.fds.copy_from_slice(loan.kernel.fds.as_ref());
            task.kernel.execution_cpu = cpu;
            task.kernel.state = ThreadState::OnCpu;
            slot.tid.store(tid, Ordering::Relaxed);
            slot.cancel.store(false, Ordering::Relaxed);
            slot.state.store(RUN, Ordering::Release);
            machine.interrupt_processor(slot.processor.load(Ordering::Relaxed));
        }
        let prepared = machine.rdtsc();
        if chosen[0] != usize::MAX {
            let task = &mut threads[chosen[0]];
            let mut fx = task.kernel.fx_state;
            let empty = machine.activate(core::mem::take(&mut task.kernel.vcpu.space), &mut fx, core::ptr::null_mut());
            task.personality.on_resume(machine);
            machine.arm_alarm(Some(deadline));
            machine.execution_profile_begin();
            task.kernel.pending_event = Some(machine.execute(&mut task.kernel.vcpu.regs, &arch_abi::IoPolicy::deny_all()));
            task.kernel.vcpu.space = machine.activate(empty, &mut fx, core::ptr::null_mut());
            task.kernel.fx_state = fx;
            task.kernel.cpu_hash = thread::hash_regs(&task.kernel.vcpu.regs);
        }
        let work_finished = if chosen[0] == usize::MAX { prepared } else { machine.rdtsc() };
        // A BSP task already returned an event. Dispatch it now instead of
        // waiting for the process which happened to initiate this CPU loan.
        // Linux peers share a presentation endpoint; execution can change
        // without transferring console focus or stopping the outstanding AP.
        let resume = if chosen[0] != usize::MAX { chosen[0] } else { current };
        if resume != current && threads[current].kernel.state == ThreadState::OnCpu {
            BSP_EVENTS_WITH_WORKERS.fetch_add(1, Ordering::Relaxed);
        }
        if chosen[0] == usize::MAX {
            if threads[current].kernel.state == ThreadState::OnCpu {
                wait_for_slot(machine, &all[threads[current].kernel.execution_cpu], deadline);
            } else if cpu != 0 && all[cpu].state.load(Ordering::Acquire) == RUN {
                wait_for_slot(machine, &all[cpu], deadline);
            }
        }
        collect_finished::<A>(threads);
        machine.refresh_kernel_mappings();
        if resume != current && super::focus::focused() == current {
            // Same Linux presentation: update its execution owner without a
            // framebuffer/display handoff, matching an ordinary tty switch.
            super::focus::adopt(resume);
            super::linux::foreground_console(resume);
        }
        ctx.tid = resume;
        let task = &mut threads[resume];
        let mut fx = task.kernel.fx_state;
        let _empty = machine.activate(core::mem::take(&mut task.kernel.vcpu.space), &mut fx, core::ptr::null_mut());
        task.personality.on_resume(machine);
        ctx.regs = task.kernel.vcpu.regs;
        self.kernel_cycles = prepared.wrapping_sub(started).wrapping_add(machine.rdtsc().wrapping_sub(work_finished));
        task.kernel.pending_event.take().unwrap_or(KernelEvent::Irq)
    }
}

fn wait_for_slot<A: Arch>(machine: &A, slot: &Slot<A>, deadline: u64) {
    let mut watchdog = deadline.max(machine.now()).saturating_add(1_000_000_000);
    let mut spins = 0u32;
    while slot.state.load(Ordering::Acquire) != DONE {
        core::hint::spin_loop(); spins = spins.wrapping_add(1);
        if spins.is_multiple_of(65536) {
            let now = machine.now();
            if ACTIVE_HANDLERS.load(Ordering::Acquire) != 0 { watchdog = now.saturating_add(1_000_000_000); }
            assert!(now < watchdog, "Linux worker failed to return process {}", slot.tid.load(Ordering::Relaxed));
        }
    }
}

/// Acquire completed process states. RUN loans are exclusively worker-owned;
/// their task-table rows contain only stable metadata and shared console refs.
pub(crate) fn collect_finished<A: Arch>(threads: &mut [Thread<A>]) {
    for slot in slots::<A>() {
        if slot.state.load(Ordering::Acquire) != DONE { continue; }
        let tid = slot.tid.load(Ordering::Relaxed);
        let task = &mut threads[tid];
        assert!(task.kernel.state == ThreadState::OnCpu);
        let loan = unsafe { &mut *slot.loan.get() };
        core::mem::swap(&mut loan.kernel, &mut task.kernel);
        let thread::Personality::Linux(linux) = &mut task.personality else { unreachable!() };
        core::mem::swap(&mut loan.linux, linux);
        task.kernel.vcpu.space = core::mem::take(&mut loan.space);
        task.kernel.vcpu.regs = loan.regs;
        task.kernel.fx_state = loan.fx;
        task.kernel.pending_event = Some(loan.event);
        task.kernel.cpu_hash = thread::hash_regs(&loan.regs);
        // Do not retain a phantom live task in the reusable loan.
        loan.kernel.state = ThreadState::Unused;
        slot.state.store(IDLE, Ordering::Release);
    }
}

/// Cross-process mutation acquires just its target's execution ownership.
pub(crate) fn take_process<A: Arch>(machine: &mut A, threads: &mut [Thread<A>], tid: usize) {
    if threads[tid].kernel.state != ThreadState::OnCpu { return; }
    let slot = &slots::<A>()[threads[tid].kernel.execution_cpu];
    slot.cancel.store(true, Ordering::Release);
    if slot.state.load(Ordering::Acquire) == RUN {
        machine.interrupt_processor(slot.processor.load(Ordering::Relaxed));
    }
    wait_for_slot(machine, slot, machine.now());
    collect_finished::<A>(threads);
    machine.refresh_kernel_mappings();
}
pub(crate) fn stop_all<A: Arch>(machine: &mut A, threads: &mut [Thread<A>]) {
    for tid in 1..threads.len() { take_process(machine, threads, tid); }
}

/// Lifecycle code keeps one task-table owner. Acquire only rows it can mutate;
/// unrelated processes continue user execution and kernel handlers throughout.
pub(crate) fn prepare_action<A: Arch>(machine: &mut A, threads: &mut [Thread<A>], current: usize, action: &thread::KernelAction) {
    let retiring_threads = matches!(&threads[current].personality,
        thread::Personality::Linux(linux) if linux.has_exited_threads());
    let related = retiring_threads || matches!(action, thread::KernelAction::Exit(_) | thread::KernelAction::Signal { .. } | thread::KernelAction::ThreadSignal { .. });
    for tid in 1..threads.len() {
        let selected = match action {
            thread::KernelAction::Shutdown => true,
            thread::KernelAction::Switch(target) | thread::KernelAction::WakeChild(target) => tid == *target,
            thread::KernelAction::Signal { pid, .. } => match *pid {
                0 => super::linux::process_group::group(tid as i32) == super::linux::process_group::group(current as i32),
                -1 => tid != current && tid != 1,
                n if n < -1 => n.checked_neg() == Some(super::linux::process_group::group(tid as i32)),
                n => n == tid as i32,
            },
            thread::KernelAction::ThreadSignal { group, .. } => group.is_none_or(|pid| pid == tid as i32),
            _ => false,
        } || related && (threads[tid].kernel.parent_tid == current as i32 || threads[current].kernel.parent_tid == tid as i32);
        if selected { take_process(machine, threads, tid); }
    }
    if matches!(action, thread::KernelAction::Fork { .. } | thread::KernelAction::Exec { .. }
        | thread::KernelAction::Wait { .. } | thread::KernelAction::Exit(_))
        && ACTIVE.load(Ordering::Acquire) != 0 {
        PARALLEL_LIFECYCLES.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn peak_workers() -> usize { PEAK.load(Ordering::Relaxed) }

/// BSP snapshots only. DONE/IDLE publishes the worker's completed counters;
/// never read the loan while its CPU owns RUN. Totals are since boot and are
/// separate from the BSP wall-time ledger.
pub(crate) fn worker_stats<A: Arch>() -> Vec<(usize, WorkerStats)> {
    slots::<A>().iter().enumerate().filter_map(|(cpu, slot)| {
        if !matches!(slot.state.load(Ordering::Acquire), DONE | IDLE) { return None; }
        let stats = unsafe { (*slot.loan.get()).stats };
        (stats.syscalls != 0).then_some((cpu, stats))
    }).collect()
}

/// CPUs eligible for Linux execution; the dedicated media core is excluded.
pub fn cpu_mask<A: Arch>() -> u64 {
    let mut mask = 1u64;
    for (cpu, slot) in slots::<A>().iter().enumerate().skip(1) {
        if matches!(slot.state.load(Ordering::Acquire), IDLE | RUN | DONE) { mask |= 1u64 << cpu; }
    }
    mask
}
