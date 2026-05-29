//! Virtual cascaded 8259 PIC (per thread).
//!
//! Modelled as one real 8259 (`Pic8259`) instantiated twice — a master and a
//! slave wired in cascade through the master's IRQ2 — instead of an ad-hoc
//! queue. Each chip keeps the three real registers (IRR / ISR / IMR) and the
//! fully-nested priority resolver lives in one place, exercised by both.
//!
//! Priority is fully-nested (lowest line = highest priority). The slave hangs
//! off master IR2, so the effective chain is
//!   IRQ0 > IRQ1 > [IRQ8..IRQ15] > IRQ3 > IRQ4 > .. > IRQ7,
//! and an in-service IRQ blocks only equal-or-lower priority — a strictly
//! higher line still preempts once the guest re-enables interrupts (the `sti`
//! mid-handler case). The master is *not* in Special-Fully-Nested-Mode, so a
//! slave line can't preempt another in-service slave line (master IR2 stays in
//! service until its EOI); only master IRQ0/IRQ1 can preempt an in-service
//! slave. All of that falls out of the master-level priority gate below.

/// Index of the lowest set bit (= highest-priority pending/in-service line),
/// or `None` if the byte is zero.
fn lowest_set(bits: u8) -> Option<u8> {
    (bits != 0).then(|| bits.trailing_zeros() as u8)
}

/// One 8259. Edge-triggered: a request latches into `irr` and stays until it
/// is acknowledged (delivered) or explicitly cleared. `vector_base` is the
/// ICW2 offset (master 0x08, slave 0x70).
#[derive(Clone, Copy)]
struct Pic8259 {
    irr: u8, // interrupt request register (pending, latched)
    isr: u8, // in-service register (delivered, awaiting EOI)
    imr: u8, // interrupt mask register (1 = masked/blocked)
    #[allow(dead_code)]
    vector_base: u8,
}

impl Pic8259 {
    const fn new(vector_base: u8) -> Self {
        Self { irr: 0, isr: 0, imr: 0, vector_base }
    }

    /// Highest-priority line that is requested, unmasked, and strictly higher
    /// priority than whatever this chip currently has in service. `None` if
    /// nothing here is deliverable. No state change.
    fn peek(&self) -> Option<u8> {
        let win = lowest_set(self.irr & !self.imr)?;
        match lowest_set(self.isr) {
            Some(svc) if win >= svc => None, // in service blocks equal-or-lower
            _ => Some(win),
        }
    }

    /// Non-specific EOI: retire the highest-priority in-service line.
    fn eoi(&mut self) {
        self.isr &= self.isr.wrapping_sub(1); // clear lowest set bit
    }
}

/// Virtual cascaded 8259 pair. External code addresses lines by *global* IRQ
/// number 0..15 (0..7 master, 8..15 slave) and never touches the chips
/// directly.
#[derive(Clone, Copy)]
pub struct VirtualPic {
    master: Pic8259,
    slave: Pic8259,
}

/// Master IR2 is the cascade input — never a real device line.
const CASCADE_LINE: u8 = 2;

impl VirtualPic {
    pub const fn new() -> Self {
        Self {
            master: Pic8259::new(0x08),
            slave: Pic8259::new(0x70),
        }
    }

    /// Raise (request) global IRQ line `irq`. Edge-triggered and idempotent —
    /// a second pulse before delivery collapses into the one latched bit
    /// (natural coalescing, e.g. timer floods).
    pub fn raise(&mut self, irq: u8) {
        if irq < 8 {
            self.master.irr |= 1 << irq;
        } else if irq < 16 {
            self.slave.irr |= 1 << (irq - 8);
        }
    }

    /// Drop a pending request without delivering it (e.g. a keyboard IRQ whose
    /// scancode turned out not to be ready). De-asserts the line.
    pub fn clear_request(&mut self, irq: u8) {
        if irq < 8 {
            self.master.irr &= !(1 << irq);
        } else if irq < 16 {
            self.slave.irr &= !(1 << (irq - 8));
        }
    }

    /// Whether line `irq` is currently requested (IRR) — used to avoid
    /// double-raising a line that's already pending.
    pub fn is_requested(&self, irq: u8) -> bool {
        if irq < 8 {
            self.master.irr & (1 << irq) != 0
        } else if irq < 16 {
            self.slave.irr & (1 << (irq - 8)) != 0
        } else {
            false
        }
    }

    /// Whether line `irq` is currently in service (ISR), i.e. delivered and
    /// awaiting its EOI.
    pub fn in_service(&self, irq: u8) -> bool {
        if irq < 8 {
            self.master.isr & (1 << irq) != 0
        } else if irq < 16 {
            self.slave.isr & (1 << (irq - 8)) != 0
        } else {
            false
        }
    }

    /// The highest-priority *deliverable* line across the cascade as a global
    /// IRQ number (0..15), honouring masks, priority, and the non-SFNM cascade
    /// rule. No state change — the caller commits with [`ack`](Self::ack).
    pub fn peek(&self) -> Option<u8> {
        // The slave's INT output drives master IR2 — but only if the slave
        // itself has a deliverable line (its own priority/in-service gate).
        let cascade = if self.slave.peek().is_some() { 1 << CASCADE_LINE } else { 0 };
        let candidates = (self.master.irr | cascade) & !self.master.imr;
        let win = lowest_set(candidates)?;
        // Strictly-higher-priority preemption against the master's in service.
        if let Some(svc) = lowest_set(self.master.isr) {
            if win >= svc {
                return None;
            }
        }
        if win == CASCADE_LINE {
            // Descend into the slave for the actual line it selected.
            self.slave.peek().map(|s| 8 + s)
        } else {
            Some(win)
        }
    }

    /// True if any line is deliverable right now (the value VIP should latch
    /// while the guest has interrupts disabled).
    pub fn has_deliverable(&self) -> bool {
        self.peek().is_some()
    }

    /// Commit delivery of global line `irq`: clear its request and set it in
    /// service. A slave line also marks master IR2 in service (cascade), which
    /// the guest retires with the second (master) EOI.
    pub fn ack(&mut self, irq: u8) {
        if irq < 8 {
            self.master.irr &= !(1 << irq);
            self.master.isr |= 1 << irq;
        } else if irq < 16 {
            self.slave.irr &= !(1 << (irq - 8));
            self.slave.isr |= 1 << (irq - 8);
            self.master.isr |= 1 << CASCADE_LINE;
        }
    }

    /// Master non-specific EOI (`out 0x20, 0x20`).
    pub fn master_eoi(&mut self) {
        self.master.eoi();
    }

    /// Slave non-specific EOI (`out 0xA0, 0x20`).
    pub fn slave_eoi(&mut self) {
        self.slave.eoi();
    }

    /// Write the master IMR (`out 0x21`).
    pub fn set_master_imr(&mut self, v: u8) {
        self.master.imr = v;
    }

    /// Write the slave IMR (`out 0xA1`).
    pub fn set_slave_imr(&mut self, v: u8) {
        self.slave.imr = v;
    }

    pub fn master_isr(&self) -> u8 {
        self.master.isr
    }
    pub fn master_imr(&self) -> u8 {
        self.master.imr
    }
    pub fn slave_isr(&self) -> u8 {
        self.slave.isr
    }
    pub fn slave_imr(&self) -> u8 {
        self.slave.imr
    }

    /// Diagnostic snapshot: `(master_irr, master_isr, master_imr, slave_irr,
    /// slave_isr, slave_imr)`.
    pub fn debug_state(&self) -> (u8, u8, u8, u8, u8, u8) {
        (
            self.master.irr, self.master.isr, self.master.imr,
            self.slave.irr, self.slave.isr, self.slave.imr,
        )
    }
}
