//! Drain architecture events into the kernel event loop.

/// Drain the architecture event queue for input/personality dispatch.
#[inline(never)]
pub fn drain<A: crate::Arch>(machine: &mut A) -> alloc::vec::Vec<crate::Irq> {
    let mut pending = alloc::vec::Vec::new();
    machine.drain(&mut |event| pending.push(event));
    pending
}
