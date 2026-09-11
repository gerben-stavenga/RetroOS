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
static mut COUNTERS: [Counter; SLOTS] = [EMPTY; SLOTS];
static mut OVERFLOW: u64 = 0;

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
            let counter = &mut (*core::ptr::addr_of_mut!(COUNTERS))[index];
            counter.calls += 1;
            counter.run += run;
            counter.dispatch += elapsed;
            counter.max_dispatch = counter.max_dispatch.max(elapsed);
        }
    }
}

pub(super) fn reset() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(COUNTERS), [EMPTY; SLOTS]);
        OVERFLOW = 0;
    }
}

pub(super) fn print() {
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
