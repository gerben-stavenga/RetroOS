//! Virtual cascaded 8259 PIC state (per thread).

use super::*;

pub const VPIC_QUEUE_SIZE: usize = 64;

/// Virtual cascaded 8259 PIC pair (one per thread).
pub struct VirtualPic {
    pub isr: u8,       // Master In-Service Register
    pub imr: u8,       // Master Interrupt Mask Register
    pub slave_isr: u8, // Slave In-Service Register
    pub slave_imr: u8, // Slave Interrupt Mask Register
    queue: [u8; VPIC_QUEUE_SIZE],  // pending interrupt vectors
    head: usize,
    tail: usize,
}

impl VirtualPic {
    pub const fn new() -> Self {
        Self {
            isr: 0,
            imr: 0,
            slave_isr: 0,
            slave_imr: 0,
            queue: [0; VPIC_QUEUE_SIZE],
            head: 0,
            tail: 0,
        }
    }

    /// Check if there are pending interrupt vectors in the queue.
    pub fn has_pending(&self) -> bool {
        self.head != self.tail
    }

    /// Check whether a specific vector is already queued.
    pub fn has_pending_vec(&self, vec: u8) -> bool {
        let mut i = self.head;
        while i != self.tail {
            if self.queue[i] == vec {
                return true;
            }
            i = (i + 1) % VPIC_QUEUE_SIZE;
        }
        false
    }

    /// Non-specific EOI: clear highest-priority (lowest-numbered) in-service bit
    pub fn eoi(&mut self) {
        if self.isr != 0 {
            self.isr &= self.isr - 1; // clear lowest set bit
        }
    }

    /// Non-specific EOI for the slave PIC.
    pub fn slave_eoi(&mut self) {
        if self.slave_isr != 0 {
            self.slave_isr &= self.slave_isr - 1;
        }
    }

    /// Debug: copy out the pending queue (vector list in order).
    pub fn debug_queue(&self) -> ([u8; VPIC_QUEUE_SIZE], usize) {
        let mut out = [0u8; VPIC_QUEUE_SIZE];
        let mut n = 0;
        let mut i = self.head;
        while i != self.tail {
            out[n] = self.queue[i];
            n += 1;
            i = (i + 1) % VPIC_QUEUE_SIZE;
        }
        (out, n)
    }

    /// Queue a pending interrupt vector.
    /// Timer ticks (0x08) are coalesced: only one pending tick is kept.
    /// This prevents timer floods from starving keyboard and other IRQs.
    pub fn push(&mut self, vec: u8) {
        if vec == 0x08 {
            // Check if a timer tick is already queued — if so, skip
            let mut i = self.head;
            while i != self.tail {
                if self.queue[i] == 0x08 { return; }
                i = (i + 1) % VPIC_QUEUE_SIZE;
            }
        }
        let next = (self.tail + 1) % VPIC_QUEUE_SIZE;
        if next != self.head {
            self.queue[self.tail] = vec;
            self.tail = next;
        }
    }

    /// Pop next pending interrupt vector, prioritizing keyboard (0x09) over timer.
    pub fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail { return None; }
        // Scan for a keyboard IRQ and deliver it first
        let mut i = self.head;
        while i != self.tail {
            if self.queue[i] == 0x09 {
                let vec = self.queue[i];
                // Remove from queue by shifting
                let mut j = i;
                loop {
                    let next = (j + 1) % VPIC_QUEUE_SIZE;
                    if next == self.tail { break; }
                    self.queue[j] = self.queue[next];
                    j = next;
                }
                self.tail = if self.tail == 0 { VPIC_QUEUE_SIZE - 1 } else { self.tail - 1 };
                return Some(vec);
            }
            i = (i + 1) % VPIC_QUEUE_SIZE;
        }
        // No keyboard IRQ — pop normally
        let vec = self.queue[self.head];
        self.head = (self.head + 1) % VPIC_QUEUE_SIZE;
        Some(vec)
    }
}

