//! Generic virtual 8237 DMA controller.
//!
//! A DOS program programs the 8237 with a *DOS-physical* buffer address, but
//! runs paged in VM86, so the real DMA engine would fetch the wrong memory. This
//! module is the policy-free shadow: it captures every channel's programming
//! (addr/count/page/mode) and serves register reads back. It knows nothing about
//! the Sound Blaster — the card layer (`vsb.rs`) owns the SB-specific remap,
//! reading this shadow to locate and size each transfer.
//!
//! Two cascaded controllers: #1 = 8-bit channels 0-3 (ports 0x00-0x0F),
//! #2 = 16-bit channels 4-7 (ports 0xC0-0xDF, register stride ×2). Page
//! registers live in the 0x80-0x8F block. Address/count are 16-bit, loaded
//! low-then-high through a per-controller byte-pointer flip-flop.

/// A channel's captured guest programming (what we need to locate and
/// size the transfer): `addr`/`count` are in bytes for 8-bit channels,
/// in *words* for 16-bit channels (8237 quirk).
#[derive(Clone, Copy, Default)]
pub struct DmaProg {
    pub addr: u16,  // base address register (offset within its page)
    pub count: u16, // base count register (transfer length − 1)
    pub page: u8,   // page register (high address bits)
    pub mode: u8,   // mode register byte (transfer type, auto-init…)
}

/// One DMA channel. `prog` is **always present** — it mirrors the
/// 8237's base address/count/page/mode registers, which physically
/// persist across re-arms (single-cycle drivers rewrite only addr+count
/// each block, reusing mode/page). Two orthogonal control bits sit
/// beside it, exactly as on the real chip — neither discriminates
/// `prog`'s validity, and every combination is
/// physically meaningful (no illegal states):
///  - `masked` — channel masked (DRQ ignored); starts masked.
///  - `armed`  — the current programming has been handed to the real
///    QEMU-8257, which is then authoritative for *current-count* reads
///    (live decrement, natural 0xFFFF at terminal). A fresh count
///    (re)write clears it; `maybe_remap` sets it. `prog` is untouched
///    by either, so a partial re-arm keeps the prior mode/page.
#[derive(Clone, Copy, Default)]
pub struct DmaChannel {
    pub prog: DmaProg,
    pub masked: bool,
    pub armed: bool,
}

/// Generic virtual 8237 pair. Indexed by absolute channel 0..7.
#[derive(Clone, Copy)]
pub struct Dma8237 {
    pub ch: [DmaChannel; 8],
    // Byte-pointer flip-flops + the current-count read latch are `pub(super)`
    // so the card layer (`vsb.rs`) can serve live SB-channel reads (passthrough
    // or emulated) through the same flip-flop split the controller uses.
    pub(super) ff_lo: bool, // controller #1 (ch0-3) byte-pointer flip-flop
    pub(super) ff_hi: bool, // controller #2 (ch4-7) byte-pointer flip-flop
    /// Per-channel count-program generation: bumped each time the guest
    /// finishes writing a channel's 16-bit count register. This is the
    /// reliable "(re)arm a transfer" signal — a single-cycle SB driver
    /// rewrites count every block (even to the same value), auto-init
    /// writes it once. The SB-DMA layer reprograms the real 8237 when
    /// this changes, independent of mask/unmask.
    pub count_gen: [u32; 8],
    /// Transient holder for the real QEMU-8257 16-bit current-count,
    /// snapshotted at the guest's low-byte read so the lo/hi pair is
    /// consistent. Not part of the programming shadow.
    pub(super) read_latch: u16,
}

/// Standard PC/AT page-register port → absolute channel. 0x8F is the
/// refresh page (ch4 is the cascade channel, never used for transfers).
const DMA_PAGE_PORT: [(u16, usize); 7] = [
    (0x87, 0), (0x83, 1), (0x81, 2), (0x82, 3),
    (0x8B, 5), (0x89, 6), (0x8A, 7),
];

impl Dma8237 {
    pub fn new() -> Self {
        // Channels power up masked & un-armed, registers zeroed (count
        // 0 ⇒ `maybe_remap` won't act) until the guest programs them.
        let ch = [DmaChannel { prog: DmaProg::default(), masked: true, armed: false }; 8];
        Self { ch, ff_lo: false, ff_hi: false, count_gen: [0; 8], read_latch: 0 }
    }

    /// True if `port` (already 10-bit-folded) belongs to the 8237.
    pub fn owns(port: u16) -> bool {
        matches!(port, 0x00..=0x0F | 0xC0..=0xDF)
            || DMA_PAGE_PORT.iter().any(|&(p, _)| p == port)
    }

    fn ff(&mut self, hi: bool) -> &mut bool {
        if hi { &mut self.ff_hi } else { &mut self.ff_lo }
    }

    pub fn io_write<A: crate::Arch>(&mut self, _machine: &mut A, port: u16, val: u8) {
        // Page registers.
        if let Some(&(_, chan)) = DMA_PAGE_PORT.iter().find(|&&(p, _)| p == port) {
            self.ch[chan].prog.page = val;
            return;
        }
        let hi = port >= 0xC0;
        // Normalize controller #2's ×2 register stride to 0..0x0F.
        let reg = if hi { (port - 0xC0) >> 1 } else { port };
        let chan_base = if hi { 4 } else { 0 };
        match reg {
            0x00..=0x07 => {
                let chan = chan_base + (reg >> 1) as usize;
                let is_count = reg & 1 == 1;
                let ff = self.ff(hi);
                let flip = *ff;
                *ff = !*ff;
                let p = &mut self.ch[chan].prog;
                let r = if is_count { &mut p.count } else { &mut p.addr };
                if !flip { *r = (*r & 0xFF00) | val as u16; }
                else     { *r = (*r & 0x00FF) | ((val as u16) << 8); }
                if is_count {
                    // (Re)writing the count un-arms: count reads return
                    // the freshly-programmed base until `maybe_remap`
                    // re-arms onto the real chip. addr/page/mode persist.
                    self.ch[chan].armed = false;
                    if flip {
                        // High byte completes the 16-bit count: the
                        // (re)arm signal the SB-DMA layer keys off.
                        self.count_gen[chan] = self.count_gen[chan].wrapping_add(1);
                    }
                }
            }
            0x0B => { // mode: bits0-1 = channel
                let chan = chan_base + (val & 0x03) as usize;
                self.ch[chan].prog.mode = val;
            }
            0x0A => { // single mask: bits0-1 channel, bit2 = mask/unmask
                let chan = chan_base + (val & 0x03) as usize;
                self.ch[chan].masked = val & 0x04 != 0;
            }
            0x0C => { *self.ff(hi) = false; } // clear byte-pointer flip-flop
            0x0D => { // master clear: reset controller, all channels masked
                *self.ff(hi) = false;
                for c in chan_base..chan_base + 4 { self.ch[c].masked = true; }
            }
            0x0E => { for c in chan_base..chan_base + 4 { self.ch[c].masked = false; } }
            0x0F => { // write all mask bits (bits0-3 → the 4 channels)
                for i in 0..4 { self.ch[chan_base + i].masked = val & (1 << i) != 0; }
            }
            _ => {} // command/request regs: not needed by the SB path
        }
    }

    pub fn io_read<A: crate::Arch>(&mut self, _machine: &mut A, port: u16) -> u8 {
        // Page registers read back the latched value.
        if let Some(&(_, chan)) = DMA_PAGE_PORT.iter().find(|&&(p, _)| p == port) {
            return self.ch[chan].prog.page;
        }
        let hi = port >= 0xC0;
        let reg = if hi { (port - 0xC0) >> 1 } else { port };
        let chan_base = if hi { 4 } else { 0 };
        match reg {
            0x00..=0x07 => {
                let chan = chan_base + (reg >> 1) as usize;
                let is_count = reg & 1 == 1;
                // Captured guest programming (base registers). The armed
                // SB channel never reaches here for count — `dma_read`
                // intercepts and serves the live real QEMU-8257 instead.
                let p = self.ch[chan].prog;
                let v = if is_count { p.count } else { p.addr };
                let ff = self.ff(hi);
                let byte = if !*ff { v as u8 } else { (v >> 8) as u8 };
                *ff = !*ff;
                byte
            }
            0x08 => 0x00, // status: no TC, no requests pending in our model
            _ => 0xFF,
        }
    }
}
