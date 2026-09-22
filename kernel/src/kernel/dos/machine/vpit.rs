//! Virtual 8253 PIT.

// ============================================================================
// Virtual 8253 PIT
// ============================================================================

const PIT_INPUT_HZ: u64 = 1_193_182;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Clone, Copy)]
struct VirtualPitChannel {
    reload: u16,
    rw_mode: u8,
    mode: u8,
    write_lsb: Option<u8>,
    read_lsb_next: bool,
    latched: Option<u16>,
    latch_lsb_next: bool,
    start_cycle: u64,
    next_irq_cycle: u64,
    enabled: bool,
}

impl VirtualPitChannel {
    const fn new() -> Self {
        Self {
            reload: 0,
            rw_mode: 3,
            mode: 3,
            write_lsb: None,
            read_lsb_next: true,
            latched: None,
            latch_lsb_next: true,
            start_cycle: 0,
            // The default divisor must elapse before the first IRQ edge.
            next_irq_cycle: 65_536,
            enabled: true,
        }
    }

    #[inline]
    fn divisor(&self) -> u64 {
        match self.reload {
            0 => 65_536,
            v => v as u64,
        }
    }

    #[inline]
    fn current_count(&self, now: u64) -> u16 {
        if !self.enabled {
            return self.reload;
        }
        let div = self.divisor();
        let elapsed = now.saturating_sub(self.start_cycle);
        let raw = match self.mode {
            2 | 3 => {
                let pos = elapsed % div;
                let remaining = div - pos;
                if remaining == div { div } else { remaining }
            }
            _ => {
                div.saturating_sub(elapsed)
            }
        };
        raw as u16
    }

    fn latch_count(&mut self, now: u64) {
        self.latched = Some(self.current_count(now));
        self.latch_lsb_next = true;
    }

    fn read_byte(&mut self, now: u64) -> u8 {
        if let Some(latched) = self.latched {
            let byte = if self.latch_lsb_next {
                self.latch_lsb_next = false;
                latched as u8
            } else {
                self.latched = None;
                self.latch_lsb_next = true;
                (latched >> 8) as u8
            };
            return byte;
        }

        let count = self.current_count(now);
        match self.rw_mode {
            1 => count as u8,
            2 => (count >> 8) as u8,
            _ => {
                let byte = if self.read_lsb_next {
                    count as u8
                } else {
                    (count >> 8) as u8
                };
                self.read_lsb_next = !self.read_lsb_next;
                byte
            }
        }
    }

    fn load_count(&mut self, raw: u16, now: u64) {
        self.reload = raw;
        self.write_lsb = None;
        self.read_lsb_next = true;
        self.latched = None;
        self.latch_lsb_next = true;
        self.start_cycle = now;
        self.enabled = true;
        let div = self.divisor();
        self.next_irq_cycle = match self.mode {
            2 | 3 => now.saturating_add(div),
            _ => now.saturating_add(div),
        };
    }

    fn write_byte(&mut self, val: u8, now: u64) {
        match self.rw_mode {
            1 => self.load_count(val as u16, now),
            2 => self.load_count((val as u16) << 8, now),
            _ => {
                if let Some(lo) = self.write_lsb.take() {
                    self.load_count(((val as u16) << 8) | lo as u16, now);
                } else {
                    self.write_lsb = Some(val);
                }
            }
        }
    }

    fn set_command(&mut self, rw_mode: u8, mode: u8) {
        self.rw_mode = rw_mode;
        self.mode = match mode {
            6 => 2,
            7 => 3,
            v => v & 0x07,
        };
        self.write_lsb = None;
        self.read_lsb_next = true;
    }

    /// The channel's OUT line. Only channel 2's is guest-visible (port 61h
    /// bit 5), and programs poll it both as a "is there a PIT" check and as a
    /// sub-tick delay source — which is why this is derived from the real
    /// count rather than faked with a toggle-per-read like the refresh bit.
    fn output(&self, now: u64) -> bool {
        if !self.enabled {
            return true; // never programmed, or a one-shot that has expired
        }
        let div = self.divisor();
        let elapsed = now.saturating_sub(self.start_cycle);
        match self.mode {
            2 => elapsed % div != div - 1, // low for one input cycle at count 1
            3 => elapsed % div < div / 2,  // square: high for the first half
            _ => elapsed >= div,           // one-shot: low until terminal count
        }
    }

    fn take_irqs(&mut self, now: u64) -> u32 {
        if !self.enabled {
            return 0;
        }
        let div = self.divisor();
        let mut count = 0u32;
        match self.mode {
            2 | 3 => {
                while now >= self.next_irq_cycle {
                    count = count.saturating_add(1);
                    self.next_irq_cycle = self.next_irq_cycle.saturating_add(div);
                }
            }
            _ => {
                if now >= self.next_irq_cycle {
                    count = 1;
                    self.enabled = false;
                }
            }
        }
        count
    }
}

/// Channels 0 and 2 are modelled; 1 (DRAM refresh) is not — nothing reads it,
/// and port 61h bit 4 already fakes the refresh line for the games that poll
/// it (see `vkbd::read_port61`).
pub struct VirtualPit {
    last_host_ns: u64,
    frac_accum: u64,
    input_cycles: u64,
    /// The system timer: the only channel wired to an IRQ line.
    ch0: VirtualPitChannel,
    /// The speaker's tone generator. It drives no interrupt — the guest sees
    /// it only through its reload (which sets the pitch) and its OUT line at
    /// port 61h bit 5. Note the gate: on real hardware 61h bit 0 stops this
    /// counter, but the phase it resumes at is not guest-visible, so the
    /// channel free-runs here and gating lives entirely in the speaker card.
    ch2: VirtualPitChannel,
}

impl VirtualPit {
    pub(crate) fn new<A: crate::Arch>(machine: &mut A) -> Self {
        let now = machine.now();
        Self {
            last_host_ns: now,
            frac_accum: 0,
            input_cycles: 0,
            ch0: VirtualPitChannel::new(),
            ch2: VirtualPitChannel::new(),
        }
    }

    /// The modelled channels, by the index the guest addresses them with.
    fn chan(&mut self, channel: u8) -> Option<&mut VirtualPitChannel> {
        match channel {
            0 => Some(&mut self.ch0),
            2 => Some(&mut self.ch2),
            _ => None,
        }
    }

    fn sync_at(&mut self, now: u64) {
        let delta_ns = now.saturating_sub(self.last_host_ns);
        if delta_ns == 0 {
            return;
        }
        self.last_host_ns = now;
        let total = self.frac_accum.saturating_add(delta_ns.saturating_mul(PIT_INPUT_HZ));
        self.input_cycles = self.input_cycles.saturating_add(total / NANOS_PER_SECOND);
        self.frac_accum = total % NANOS_PER_SECOND;
    }

    // The machine layer advances time and raises IRQ0 before each port access.
    pub(crate) fn read_counter(&mut self, channel: u8) -> u8 {
        let now = self.input_cycles;
        self.chan(channel).map_or(0, |c| c.read_byte(now))
    }

    pub(crate) fn write_counter(&mut self, channel: u8, val: u8) {
        let now = self.input_cycles;
        if let Some(c) = self.chan(channel) {
            c.write_byte(val, now);
        }
    }

    pub(crate) fn write_command(&mut self, val: u8) {
        let now = self.input_cycles;
        let channel = (val >> 6) & 0x03;
        let rw_mode = (val >> 4) & 0x03;
        let Some(c) = self.chan(channel) else { return };
        if rw_mode == 0 {
            c.latch_count(now);
            return;
        }
        c.set_command(rw_mode, (val >> 1) & 0x07);
    }

    /// Channel 2's reload, for the speaker's pitch (0 means 65536, which the
    /// card resolves — it is the guest's value, passed through unchanged).
    pub(crate) fn ch2_reload(&self) -> u16 {
        self.ch2.reload
    }

    /// Channel 2's OUT line, as read at port 61h bit 5.
    pub(crate) fn ch2_output(&self) -> bool {
        self.ch2.output(self.input_cycles)
    }

    pub fn take_pending_irqs(&mut self, now_ns: u64) -> u32 {
        self.sync_at(now_ns);
        self.ch0.take_irqs(self.input_cycles)
    }

    /// Debug summary: (enabled, mode, reload, now, next_irq_cycle)
    pub fn debug_state(&self) -> (bool, u8, u16, u64, u64) {
        (
            self.ch0.enabled,
            self.ch0.mode,
            self.ch0.reload,
            self.input_cycles,
            self.ch0.next_irq_cycle,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{pit_io, VirtualPic};

    fn pit() -> VirtualPit {
        VirtualPit {
            last_host_ns: 0,
            frac_accum: 0,
            input_cycles: 0,
            ch0: VirtualPitChannel::new(),
            ch2: VirtualPitChannel::new(),
        }
    }

    #[test]
    fn quake_clock_stays_in_step_between_host_wakeups() {
        let mut pit = pit();
        let mut pic = VirtualPic::new();
        pit_io(&mut pit, &mut pic, 0, |pit| {
            pit.write_command(0x34); // Quake: mode 2, divisor 65536
            pit.write_counter(0, 0);
            pit.write_counter(0, 0);
        });
        let mut bios_ticks = 0u32;
        let mut previous = 1i64;
        let mut game_cycles = 0i64;
        // Poll at 10 kHz, with the ordinary host timer service at 1 kHz.
        // A wrap between wakeups must be delivered at the latch port exit.
        for sample in 1..=10_000 {
            let now = sample * 100_000;
            if sample % 10 == 0 && pit.take_pending_irqs(now) > 0 {
                pic.raise(0);
            }
            if pic.peek() == Some(0) {
                pic.ack(0);
                bios_ticks += 1;
                pic.master_ocw2(0x20);
            }
            let mut t = bios_ticks * 65_536;
            pit_io(&mut pit, &mut pic, now, |pit| pit.write_command(0));
            if pic.peek() == Some(0) {
                pic.ack(0);
                bios_ticks += 1;
                pic.master_ocw2(0x20);
            }
            let lo = pit_io(&mut pit, &mut pic, now, |pit| pit.read_counter(0));
            let hi = pit_io(&mut pit, &mut pic, now, |pit| pit.read_counter(0));
            let r = u16::from_le_bytes([lo, hi]).wrapping_sub(1) as u32;
            let tick = bios_ticks * 65_536;
            // Sys_FloatTime's rollover correction and negative-delta clamp.
            if tick != t && r & 0x8000 != 0 {
                t = tick;
            }
            let clock = i64::from(t + 65_536 - r);
            game_cycles += (clock - previous).max(0);
            previous = clock;
        }
        assert_eq!(bios_ticks, 18);
        assert_eq!(game_cycles, PIT_INPUT_HZ as i64);
    }

    #[test]
    fn pit_io_latches_masked_irq_and_does_not_repeat_it() {
        let mut pit = pit();
        let mut pic = VirtualPic::new();
        pic.set_master_imr(1);
        pit_io(&mut pit, &mut pic, 0, |pit| pit.write_command(0));
        assert!(!pic.is_requested(0), "no startup IRQ before the first period");
        pit_io(&mut pit, &mut pic, 55_000_000, |pit| pit.write_command(0));
        assert!(pic.is_requested(0));
        assert_eq!(pic.peek(), None);
        pic.set_master_imr(0);
        assert_eq!(pic.peek(), Some(0));
        pic.ack(0);
        pic.master_ocw2(0x20);
        pit_io(&mut pit, &mut pic, 55_000_000, |pit| pit.read_counter(0));
        assert!(!pic.is_requested(0));
        assert_eq!(pit.take_pending_irqs(56_000_000), 0);
    }

    #[test]
    fn reprogramming_preserves_an_elapsed_irq() {
        let mut pit = pit();
        let mut pic = VirtualPic::new();
        pit_io(&mut pit, &mut pic, 55_000_000, |pit| {
            pit.write_command(0x34);
            pit.write_counter(0, 0);
            pit.write_counter(0, 0);
        });
        assert!(pic.is_requested(0));
        assert_eq!(pit.take_pending_irqs(56_000_000), 0);
    }
}
