//! Guest trap dispatch over canonical registers. No entry frames or kernel handoff.
use crate::{Regs, KernelEvent as KE, UserMode, X86, GuestBytes};
use crate::monitor::MonitorResult;

pub enum Outcome {
    Resume,
    ReturnToKernel(KE),
}

/// Memory mechanisms supplied by the active machine. Neither method allocates;
/// fault resolution consumes the page supply already installed by the kernel.
pub trait Machine: X86 + GuestBytes {
    fn can_fault(&self) -> bool;
    fn resolve_page_fault(&mut self, regs: &Regs, address: u64) -> bool;
}

/// Handle a guest exception or software interrupt. Platform interrupts and
/// supervisor traps must be classified by entry before calling this function.
pub fn handle(machine: &mut impl Machine, regs: &mut Regs, fault_address: u64) -> Outcome {
    let event = match regs.int_num {
        // #DB has two owners. PM clients use TF for virtual-IF learning, while
        // VM86 programs may deliberately single-step through a hooked INT 1
        // vector (ST3's packer does this). Preserve the latter as a guest CPU
        // exception so DOS can reflect it through the real-mode IVT.
        1 => {
            match regs.mode() {
                UserMode::VM86 => KE::Exception(1),
                UserMode::Mode32 => KE::DebugTrap,
                _ => {
                    regs.clear_flag32(1 << 8); // stale internal TF
                    return Outcome::Resume;
                }
            }
        }
        // The legacy sensitive-instruction decoder uses 32-bit addresses.
        // A native long-mode #GP must retain its full faulting RIP rather
        // than decoding unrelated bytes at the truncated low address.
        13 if regs.mode() == UserMode::Mode64 => KE::Exception(13),
        13 if !machine.can_fault() => KE::Irq,
        13 => {
            // VME raises #GP with VIF=1 && VIP=1 to ask the host to inject the
            // pending virtual interrupt. It normally lands on STI/POPF/IRET
            // (monitor Resume), but the STI interrupt-shadow can defer it onto
            // the *following* instruction (monitor Fault on a plain opcode —
            // e.g. the `push ds` right after `sti` in the Bochs BIOS INT 9
            // handler). Either way it's a delivery request, not an instruction
            // fault: bubble it as an IRQ and let `pick_pending_vec` choose the
            // highest-priority deliverable line. The Fault path leaves IP on
            // the (innocent) instruction, so it re-runs after the handler IRETs.
            const VIF_VIP: u32 = (1 << 19) | (1 << 20);
            let pending_virtual_irq = regs.flags32() & VIF_VIP == VIF_VIP;
            // Where this instruction lives, and whether virtual IF was on before
            // it ran: a PM CLI/STI that toggles virtual IF is a window boundary,
            // reflected to `dpmi::vif`.
            let entry_ip = regs.ip32();
            let vif_was_on = regs.flags32() & (1 << 19) != 0;
            let stepped = crate::monitor::stepping(regs);
            let user_was = regs.user_tf();
            match crate::monitor::monitor(machine, regs) {
                MonitorResult::Resume => {
                    // A PM CLI/STI toggled virtual IF: reflect the window to
                    // dpmi::vif (which owns the per-space tag/learn policy). VM86
                    // handles POPF/IRET on its own #GP (VME) and needs no tag.
                    if regs.mode() != UserMode::VM86
                        && (regs.flags32() & (1 << 19) != 0) != vif_was_on
                    {
                        let flags = regs.flags32();
                        let vif_now = flags & (1 << 19) != 0;
                        let viopl = (flags >> 12) & 3;
                        if viopl >= 2 {
                            // Repair/reference modes need the CLI boundary in
                            // ring 1 to learn or step a later POPF/IRET exit.
                            KE::VifWindow { entry_ip, vif_was_on }
                        } else if vif_now && flags & (1 << 20) != 0 {
                            // Strict mode has no learning work. Bubble out only
                            // when STI made a pending virtual IRQ deliverable.
                            KE::Irq
                        } else {
                            // CLI/STI was fully emulated in ring 0; returning a
                            // VifWindow to ring 1 would be a pure round trip.
                            return Outcome::Resume;
                        }
                    } else if regs.flags32() & VIF_VIP == VIF_VIP {
                        KE::Irq
                    } else if stepped && (regs.user_tf() || regs.forced_tf()) {
                        KE::EmulatedStep { user_was }
                    } else {
                        return Outcome::Resume;
                    }
                }
                // A real fault is reclassified as IRQ delivery only when the
                // VME pending-interrupt condition held at fault time.
                MonitorResult::Event(KE::Fault) if pending_virtual_irq => KE::Irq,
                MonitorResult::Event(e) => e,
            }
        }
        14 => {
            if !machine.can_fault() { KE::Irq }
            else if machine.resolve_page_fault(regs, fault_address) { return Outcome::Resume; }
            else { KE::PageFault { addr: fault_address } }
        }
        // Vectors 3/4 (#BP/#OF) are only reachable from user INT3/INTO, so
        // they're soft ints. Other n<32 are genuine CPU exceptions.
        3 | 4 => KE::SoftInt(regs.int_num as u8),
        0..=31 => KE::Exception(regs.int_num as u8),
        // SYSCALL instruction: `syscall_entry_64` tags it with the synthetic
        // 256, distinct from any IDT vector — keep it before the catch-all so
        // `INT 0x80` (which lands as SoftInt(0x80)) stays a different event.
        256 => KE::Syscall,
        // Direct-IDT soft interrupts: 0x30..=0xFF (plus VM86 INT3/0xCC bypass
        // of VME landing here too).
        _ => KE::SoftInt(regs.int_num as u8),
    };
    Outcome::ReturnToKernel(event)
}
