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

/// Drain pending input into the console owner.
pub fn drain<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    kt: &mut thread::KernelThread<A>,
    personality: &mut thread::Personality<A>,
) {
    match personality {
        thread::Personality::Dos(dos) => {
            let blocked = kt.state == thread::ThreadState::Blocked;
            drain_dos(machine, regs, blocked, dos);
        }
        thread::Personality::Linux(linux) => drain_linux(machine, regs, kt, linux),
    }
}

/// DOS owner: `blocked` selects the stdin-pipe path (owner is wait4-parked
/// behind a foreground Linux child).
fn drain_dos<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    blocked: bool,
    dos: &mut thread::DosState<A>,
) {
    let dp = dos as *mut thread::DosState<A>;
    {
        let mut _events: alloc::vec::Vec<crate::Irq> = alloc::vec::Vec::new();
        machine.drain(&mut |evt| _events.push(evt));
        for evt in _events {
        if let crate::Irq::Key(sc) = evt {
            if monitor_key(machine, regs, sc, Some(unsafe { &*dp })) {
                continue; // eaten by the F12 monitor
            }
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
        } else if !blocked {
            crate::kernel::dos::queue_irq(machine, unsafe { &mut *dp }, regs, evt);
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
    dos: Option<&thread::DosState<A>>,
) -> bool {
    if crate::kernel::osd::is_open() {
        crate::kernel::osd::key(machine, regs, sc, dos);
        return true;
    }
    if sc == F12_PRESS {
        crate::kernel::osd::open();
        return true;
    }
    false
}

/// Linux owner: keys → cooked fd input.
fn drain_linux<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    kt: &mut thread::KernelThread<A>,
    linux: &mut thread::LinuxState,
) {
    let ktp = kt as *mut thread::KernelThread<A>;
    let lp = linux as *mut thread::LinuxState;
    {
        let mut _events: alloc::vec::Vec<crate::Irq> = alloc::vec::Vec::new();
        machine.drain(&mut |evt| _events.push(evt));
        for evt in _events {
        if let crate::Irq::Key(sc) = evt
            && !monitor_key(machine, regs, sc, None)
        {
            unsafe { (*lp).process_key(machine, &(*ktp).fds, sc) };
        }
    }
    }
}
