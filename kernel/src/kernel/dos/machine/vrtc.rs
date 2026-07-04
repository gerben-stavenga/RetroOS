//! Virtual MC146818 RTC — periodic-interrupt (IRQ8) model.
//!
//! Only the periodic-interrupt path is modelled: control register B's PIE bit
//! (bit 6) gates IRQ8 generation, register A's rate-select nibble sets the
//! frequency, and register C reports/clears the pending-flag bits the INT 70h
//! ISR reads to dispatch. The time-of-day / alarm bytes and the rest of the
//! CMOS RAM array are NOT modelled here — reads of those indices pass through
//! to the host RTC (see `emulate_inb` port 0x71), so the guest still sees real
//! wall-clock time.
//!
//! This exists because SeaBIOS's INT 15h AH=86h (WAIT) and AH=83h (event wait)
//! drive their delay off the RTC periodic tick: they enable PIE and spin on a
//! BIOS-data-area flag (40:9C count, 40:A0 active) that the INT 70h ISR
//! decrements once per IRQ8. With no IRQ8 ever generated the wait never
//! completes and the guest hangs on a black screen — this is the Monkey Island
//! / SCUMM startup-splash hang.

use arch_abi::Arch;
const HOST_TIMER_HZ: u64 = 1000;

pub struct VirtualRtc {
    /// Status register A: rate-select nibble (bits 3-0) + divider (bits 6-4).
    /// UIP (bit 7) always reads back 0 from this model (we never report a
    /// time-update in progress, so "safe to read the clock" is always true).
    reg_a: u8,
    /// Status register B: control bits. Only PIE (bit 6) is acted on; the rest
    /// are stored so read-modify-write read-back stays coherent but are
    /// otherwise inert (no AIE/UIE/SET behaviour is modelled).
    reg_b: u8,
    /// Status register C: interrupt-flag register. PF (bit 6) is latched when a
    /// periodic tick fires, IRQF (bit 7) mirrors "any flag set". Reading the
    /// register clears it, exactly as the real chip does — that read is how the
    /// ISR identifies the periodic interrupt and re-arms the next one.
    reg_c: u8,
    /// Host-tick timestamp of the last periodic accumulation.
    last_host_tick: u64,
    /// Fractional periodic-cycle accumulator, in units of `HOST_TIMER_HZ`.
    frac_accum: u64,
}

impl VirtualRtc {
    pub fn new<A: crate::Arch>(machine: &mut A) -> Self {
        Self {
            // Power-on defaults of a typical PC RTC: reg A = 0x26 (32 kHz time
            // base, 1024 Hz periodic rate), reg B = 0x02 (24-hour, BCD).
            reg_a: 0x26,
            reg_b: 0x02,
            reg_c: 0,
            last_host_tick: machine.get_ticks(),
            frac_accum: 0,
        }
    }

    /// Whether CMOS index `idx` is one of the three status registers we model
    /// (A/B/C = 0x0A/0x0B/0x0C). Every other index falls through to the host
    /// CMOS (time-of-day, century, configuration bytes).
    pub fn owns(idx: u8) -> bool {
        matches!(idx, 0x0A..=0x0C)
    }

    pub fn read(&mut self, idx: u8) -> u8 {
        match idx {
            0x0A => self.reg_a, // UIP (bit 7) reads back 0
            0x0B => self.reg_b,
            0x0C => {
                // Reading C returns the latched flags and clears them: this is
                // how the ISR decides "this was a periodic tick" and how the
                // next IRQ8 is permitted to assert.
                let v = self.reg_c;
                self.reg_c = 0;
                v
            }
            _ => 0xFF,
        }
    }

    pub fn write<A: crate::Arch>(&mut self, machine: &mut A, idx: u8, val: u8) {
        match idx {
            0x0A => self.reg_a = val & 0x7F, // UIP is read-only
            0x0B => {
                let was_pie = self.reg_b & 0x40 != 0;
                self.reg_b = val;
                let now_pie = self.reg_b & 0x40 != 0;
                // On a fresh PIE enable, reset the accumulator so the first
                // tick lands a full period later rather than immediately —
                // otherwise stale elapsed host time would fire a burst at once.
                if now_pie && !was_pie {
                    self.last_host_tick = machine.get_ticks();
                    self.frac_accum = 0;
                }
            }
            0x0C => {} // status C is read-only
            _ => {}
        }
    }

    /// Periodic rate in Hz from reg A's rate-select nibble: f = 32768 >> (RS-1)
    /// for RS in 3..=15 (RS=6 → 1024 Hz). RS=0 disables the periodic interrupt.
    /// RS 1/2 select 16384/8192 Hz on real silicon; we clamp them to the RS=3
    /// floor so the model never tries to outrun the 1 kHz host tick.
    fn rate_hz(&self) -> u64 {
        let rs = (self.reg_a & 0x0F) as u32;
        if rs == 0 {
            0
        } else {
            32768u64 >> (rs.max(3) - 1)
        }
    }

    /// Advance the periodic clock against the host timer and return how many
    /// periodic intervals elapsed since the last call. Returns 0 unless PIE is
    /// enabled. When non-zero it latches PF/IRQF for the next reg C read. Like
    /// the PIT, repeated intervals coalesce into a single edge at the vPIC — a
    /// slow guest loses intervals rather than flooding, matching real hardware.
    pub fn take_pending_irqs<A: crate::Arch>(&mut self, machine: &mut A) -> u32 {
        if self.reg_b & 0x40 == 0 {
            return 0; // PIE disabled
        }
        let hz = self.rate_hz();
        if hz == 0 {
            return 0;
        }
        let now = machine.get_ticks();
        let delta = now.saturating_sub(self.last_host_tick);
        if delta == 0 {
            return 0;
        }
        self.last_host_tick = now;
        let total = self.frac_accum.saturating_add(delta.saturating_mul(hz));
        let count = total / HOST_TIMER_HZ;
        self.frac_accum = total % HOST_TIMER_HZ;
        if count > 0 {
            self.reg_c |= 0xC0; // IRQF | PF
        }
        count as u32
    }
}
