//! Console input routing — drained host/hardware events to their owners.
//!
//! ONE place decides where an input event goes:
//! - The F12 host monitor is intercepted first: F12 opens an on-screen menu
//!   (kill / switch / volume / trace / profile / dump), and while it is open every key
//!   drives the menu instead of the guest. See [`crate::kernel::osd`].
//! - Everything else is addressed to the console owner — `focus::focused()`,
//!   which today is also the running thread (focus implies execution until
//!   the scheduler decouples them; this router is written against the
//!   owner, so that change won't touch the routing).
//! - Keys to a *blocked* DOS owner feed the console stdin pipe (the Linux
//!   shell the DOS thread is wait4-blocked on reads them from fd 0).
//! - Keys to a running DOS owner go through its BIOS keyboard path; other
//!   IRQs (mouse packets) queue into its per-thread virtual devices.
//! - Linux owners get keys cooked into their fds; they have no virtual
//!   device bus for other IRQs.

use crate::Regs;
use crate::kernel::thread;

/// F12 scancode (press) — open the host monitor.
pub const F12_PRESS: u8 = 0x58;

/// Route already-drained input/guest events into the console owner. Kernel
/// device IRQs were consumed earlier by `irq_dispatch`.
pub fn dispatch<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    kt: &mut thread::KernelThread<A>,
    personality: &mut thread::Personality<A>,
    events: alloc::vec::Vec<crate::Irq>,
) {
    let mut guest_events = alloc::vec::Vec::with_capacity(events.len());
    for evt in events {
        if let crate::Irq::Key(sc) = evt
            && monitor_key(machine, regs, sc, personality)
        {
            continue;
        }
        guest_events.push(evt);
    }
    match personality {
        thread::Personality::Dos(dos) => {
            let blocked = kt.state == thread::ThreadState::Blocked;
            dispatch_dos(machine, regs, blocked, dos, guest_events);
        }
        thread::Personality::Linux(linux) => {
            dispatch_linux(machine, regs, kt, linux, guest_events)
        }
    }
}

/// DOS owner: `blocked` selects the stdin-pipe path (owner is wait4-parked
/// behind a foreground Linux child).
fn dispatch_dos<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    blocked: bool,
    dos: &mut thread::DosState<A>,
    events: alloc::vec::Vec<crate::Irq>,
) {
    let dp = dos as *mut thread::DosState<A>;
    {
        for evt in events {
        if let crate::Irq::Key(sc) = evt {
            if blocked {
                if crate::kernel::keyboard::update_key_state(sc) {
                    let c = crate::kernel::keyboard::scancode_to_ascii(sc);
                    if c != 0 {
                        crate::vga::putchar(c);
                        let cpipe = thread::console_pipe();
                        crate::kernel::kpipe::write(cpipe, &[c]);
                    }
                }
            } else {
                unsafe { (*dp).process_key(machine, regs, sc) };
            }
        } else {
            if !blocked {
                crate::kernel::dos::queue_irq(machine, unsafe { &mut *dp }, regs, evt);
            }
        }
    }
    }
}

/// The single host-monitor gate, tried before any owner sees the key. Returns
/// true when the key was consumed (never reaches the guest).
///
/// One door, not one chord per action: while the monitor is open it eats every
/// key; when closed, only F12 (opening it) is special.
fn monitor_key<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    sc: u8,
    personality: &mut thread::Personality<A>,
) -> bool {
    if crate::kernel::osd::is_open() {
        let dos = match &*personality {
            thread::Personality::Dos(dos) => Some(dos),
            thread::Personality::Linux(_) => None,
        };
        crate::kernel::osd::key(machine, regs, sc, dos);
        if !crate::kernel::osd::is_open() {
            let display = crate::kernel::osd::take_display();
            let native_vga =
                matches!(display, crate::kernel::platform::DisplayToken::VgaCard);
            personality.materialize(machine, display);
            if native_vga {
                crate::kernel::sound::recover_after_display_stall();
                if let thread::Personality::Dos(dos) = personality {
                    crate::kernel::dos::audio_tick(machine, dos, regs);
                }
            }
            crate::kernel::io_policy::apply(machine, personality, true);
        }
        return true;
    }
    if sc == F12_PRESS {
        let display = personality.suspend(machine);
        if matches!(display, crate::kernel::platform::DisplayToken::VgaCard) {
            crate::kernel::dos::prepare_native_osd();
        }
        crate::kernel::osd::open(display);
        crate::kernel::io_policy::apply(machine, personality, true);
        return true;
    }
    false
}

/// Linux owner: keys → cooked fd input.
fn dispatch_linux<A: crate::Arch>(
    machine: &mut A,
    _regs: &mut Regs,
    kt: &mut thread::KernelThread<A>,
    linux: &mut thread::LinuxState,
    events: alloc::vec::Vec<crate::Irq>,
) {
    let ktp = kt as *mut thread::KernelThread<A>;
    let lp = linux as *mut thread::LinuxState;
    {
        for evt in events {
        if let crate::Irq::Key(sc) = evt
        {
            unsafe { (*lp).process_key(machine, &(*ktp).fds, sc) };
        }
    }
    }
}
