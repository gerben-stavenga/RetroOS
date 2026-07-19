//! Console input routing — drained host/hardware events to their owners.
//!
//! ONE place decides where an input event goes:
//! - Console-global chords are intercepted first: F10 toggles the cycle
//!   profile dump, F11 requests a focus switch, F12 dumps the interrupted
//!   thread's state.
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

/// F9 scancode (press) — blit frames to RAM instead of the framebuffer, a
/// diagnostic that freezes the screen but isolates the blit's own cost.
pub const F9_PRESS: u8 = 0x43;
/// F10 scancode (press) — toggle the cycle/event profile dump.
pub const F10_PRESS: u8 = 0x44;
/// F11 scancode (press) — focus switch.
pub const F11_PRESS: u8 = 0x57;
/// F12 scancode (press) — dump the running thread's state.
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
        if matches!(evt, crate::Irq::Key(sc)
            if console_chord(machine, regs, sc, Some(unsafe { &*dp }))) {
            // consumed by a console-global chord
        } else if blocked {
            if let crate::Irq::Key(sc) = evt
                && crate::kernel::keyboard::update_key_state(sc) {
                    let c = crate::kernel::keyboard::scancode_to_ascii(sc);
                    if c != 0 {
                        crate::vga::putchar(c);
                        let cpipe = thread::console_pipe();
                        crate::kernel::kpipe::write(cpipe, &[c]);
                    }
                }
        } else {
            if let crate::Irq::Key(sc) = evt {
                unsafe { (*dp).process_key(machine, regs, sc) };
            } else {
                crate::kernel::dos::queue_irq(machine, unsafe { &mut *dp }, regs, evt);
            }
        }
    }
    }
}

/// Console-global chords, tried before any owner sees the key. Returns true
/// when the chord was consumed.
///
/// One copy, not one per personality: DOS and Linux had identical F11/F12
/// arms, so a third chord would have been a third place to forget.
fn console_chord<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    sc: u8,
    dos: Option<&thread::DosState<A>>,
) -> bool {
    match sc {
        F9_PRESS => crate::kernel::startup::toggle_fb_to_ram(),
        F10_PRESS => crate::kernel::startup::toggle_profile(),
        F11_PRESS => thread::request_switch(),
        F12_PRESS => crate::kernel::startup::dump_interrupted_thread(machine, regs, dos),
        _ => return false,
    }
    true
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
            && !console_chord(machine, regs, sc, None)
        {
            unsafe { (*lp).process_key(machine, &(*ktp).fds, sc) };
        }
    }
    }
}
