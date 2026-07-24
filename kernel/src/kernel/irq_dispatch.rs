//! Kernel-global hardware-event dispatch.
//!
//! Device IRQs are machine events, not console input and not personality
//! property. Drain them before advancing a personality's virtual world so an
//! audio completion that woke the kernel is visible to the refill pass in the
//! same event-loop iteration. Events not claimed by a kernel driver continue
//! to console/personality routing unchanged.

/// Drain the arch event queue, service kernel-owned device interrupts, and
/// return the remaining input/guest-visible events.
pub fn drain<A: crate::Arch>(machine: &mut A) -> alloc::vec::Vec<crate::Irq> {
    let mut pending = alloc::vec::Vec::new();
    machine.drain(&mut |event| pending.push(event));

    let mut remaining = alloc::vec::Vec::with_capacity(pending.len());
    for event in pending {
        if !crate::kernel::sound::on_irq(machine, event) {
            remaining.push(event);
        }
    }
    remaining
}
