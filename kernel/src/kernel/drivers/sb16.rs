//! Sound Blaster 16 output — a kernel device driver (not machine code).
//!
//! On a machine whose real sound hardware is a Sound Blaster 16, the emulated
//! cards (`vsb`/`vgus`/`vmpu`) produce canonical PCM and the kernel `sound`
//! layer needs somewhere to play it. This driver is that sink: `sound::play`
//! dispatches here when the platform probe found a real SB16 (`Audio::RealSb`).
//!
//! It drives the real DSP for **16-bit signed-stereo auto-init DMA** on the ISA
//! 8237 (channel 5) — the SB16's own double-buffer scheme, where each completed
//! block raises **IRQ 5**. That block-completion interrupt IS the event-driven
//! audio track's completion signal: one interrupt = one buffer drained/free, so
//! `on_irq` is a plain block counter and the driver never reads a DMA position.
//!
//! Only machine *primitives* are used — port I/O (`inb`/`outb`, for the DSP,
//! mixer, and the 8237), `dma_channel_buf` (the permanent contiguous channel-5
//! buffer, ISA-DMA-safe), and `map_phys_range` (to map it into kernel space) —
//! never any machine-side driver logic. The DMA window is shared with the
//! ac97/hda sinks (only one sink is ever active), see `ac97.rs`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::kernel::sound::Format;

// ── SB16 DSP / mixer ports (base 0x220; the card is machine-wide, so the sink
//    uses the canonical base, not a per-thread BLASTER relocation) ────────────
const BASE: u16 = 0x220;
const DSP_RESET: u16 = BASE + 0x06;
const DSP_READ: u16 = BASE + 0x0A; // read data
const DSP_WRITE: u16 = BASE + 0x0C; // write command/data; bit7 = busy
const DSP_RSTAT: u16 = BASE + 0x0E; // read-buffer status (bit7 = data ready) / 8-bit IRQ ack
const DSP_ACK16: u16 = BASE + 0x0F; // 16-bit IRQ acknowledge
const MIX_IDX: u16 = BASE + 0x04;
const MIX_DATA: u16 = BASE + 0x05;

// DSP commands.
const CMD_SPEAKER_ON: u8 = 0xD1;
const CMD_SET_RATE_OUT: u8 = 0x41; // output rate, big-endian 16-bit
const CMD_16BIT_AUTO_OUT: u8 = 0xB6; // 16-bit, auto-init, FIFO, D/A
const CMD_EXIT_AUTO_16: u8 = 0xD9; // finish the current block then stop
// Mono, signed (bit4 = signed, bit5 = stereo). QEMU's sb16 does not honour the
// DSP stereo bit on the 16-bit auto-init path — it plays the interleaved buffer
// as mono, which comes out at half speed / doubled — so the sink downmixes to
// mono and programs mono output. (Stereo out is a TODO pending the QEMU quirk.)
const MODE_SIGNED_MONO: u8 = 0x10;

// ── 8237 channel-5 (16-bit) registers ───────────────────────────────────────
const DMA_CHANNEL: usize = 5;
const DMA5_MASK: u16 = 0xD4; // write 0x05 to mask, 0x01 to unmask
const DMA5_MODE: u16 = 0xD6;
const DMA5_CLRFF: u16 = 0xD8;
const DMA5_ADDR: u16 = 0xC4; // word address (low then high)
const DMA5_COUNT: u16 = 0xC6; // word count − 1 (low then high)
const DMA5_PAGE: u16 = 0x8B;
// single(0x40) | auto-init(0x10) | read/mem→dev(0x08) | channel-local 1 (5−4).
const DMA5_MODE_AUTO_READ: u8 = 0x59;

// ── ring geometry (shares the stolen low-mem DMA window with ac97/hda) ───────
const DMA_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_0000;
const PTE_CACHE_DISABLE: u64 = 1 << 4;
/// Completion-IRQ granularity: one interrupt per buffer. ≤ half the universal
/// pipe (see `sound::min_fill`) so ≥ 2 buffers stay queued (double-buffered).
/// Mono: one 16-bit sample per mixed stereo frame, so a buffer holds
/// `BUF_BYTES/2` frames.
const BUF_BYTES: usize = 0x200; // 512 B = 256 mono samples ≈ 5.8 ms @ 44.1 kHz
/// Playback frames (= mono samples) per buffer.
const BUF_FRAMES: usize = BUF_BYTES / 2;
const NUM_BUF: usize = 32;
const RING_BYTES: usize = NUM_BUF * BUF_BYTES;
/// Prime this many buffers before starting the DSP.
const PRIME_BUFS: usize = 2;

struct Sb16 {
    dma_va: usize,
    dma_phys: u32,
    cur_buf: usize, // ring buffer currently being filled
    cur_off: usize, // byte offset within `cur_buf`
    running: bool,  // DSP auto-init playback started
    rate: u32,      // last programmed sample rate
    /// Pipe counters for [`position`], in source frames (the DAC runs at the
    /// source rate — no resampler). `written` = frames accepted by `submit`;
    /// `consumed_bufs` = buffers the DSP has finished, one per completion IRQ.
    written: u64,
    consumed_bufs: u64,
}

static SB16: Mutex<Option<Sb16>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);
/// The IRQ line the card raises on block completion (read from the mixer at
/// bring-up), so `sound::on_hw_irq` can match it. 0xFF until up.
static IRQ_LINE: AtomicU32 = AtomicU32::new(0xFF);

/// The routed completion-IRQ line, for `sound::on_hw_irq`. `None` until up.
pub fn irq_line() -> Option<u8> {
    match IRQ_LINE.load(Ordering::Relaxed) {
        0xFF => None,
        n => Some(n as u8),
    }
}

/// The sink is up and reports a play position (so `sound::min_fill` returns the
/// universal pipe depth).
pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

/// Reset the DSP and read back the 0xAA ready byte. Pure presence probe —
/// `platform::probe` uses it for the Audio decision; an absent card reads 0xFF.
pub fn scan<A: crate::Arch>(machine: &mut A) -> bool {
    dsp_reset(machine)
}

/// Bring up the SB16 the platform probe found. Driver init only.
pub fn init<A: crate::Arch>(machine: &mut A) {
    if crate::kernel::platform::get().audio != crate::kernel::platform::Audio::RealSb {
        return;
    }
    if bring_up(machine) {
        PRESENT.store(true, Ordering::Relaxed);
    }
}

/// Standard DSP reset: pulse `DSP_RESET` 1→0, wait for data-ready, read 0xAA.
fn dsp_reset<A: crate::Arch>(machine: &mut A) -> bool {
    machine.outb(DSP_RESET, 1);
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    machine.outb(DSP_RESET, 0);
    for _ in 0..100_000 {
        if machine.inb(DSP_RSTAT) & 0x80 != 0 && machine.inb(DSP_READ) == 0xAA {
            return true;
        }
    }
    false
}

/// Write one DSP command/data byte once the write buffer is ready (bit7 clear).
fn dsp_write<A: crate::Arch>(machine: &mut A, byte: u8) {
    for _ in 0..100_000 {
        if machine.inb(DSP_WRITE) & 0x80 == 0 {
            break;
        }
    }
    machine.outb(DSP_WRITE, byte);
}

/// Read the SB16 mixer's IRQ-select register (0x80) into an IRQ line. Bits:
/// 1=IRQ2, 2=IRQ5, 4=IRQ7, 8=IRQ10. Defaults to 5 if the mixer is mute (0xFF).
fn read_irq<A: crate::Arch>(machine: &mut A) -> u8 {
    machine.outb(MIX_IDX, 0x80);
    match machine.inb(MIX_DATA) {
        0xFF => 5,
        v if v & 0x04 != 0 => 7,
        v if v & 0x08 != 0 => 10,
        v if v & 0x01 != 0 => 2,
        _ => 5,
    }
}

fn bring_up<A: crate::Arch>(machine: &mut A) -> bool {
    if !dsp_reset(machine) {
        return false;
    }
    let irq = read_irq(machine);

    // Map the permanent contiguous channel-5 buffer into the stolen low-mem
    // window so the kernel can write PCM; the DSP reads it by physical address.
    let phys_page = machine.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        crate::println!("sb16: no channel-{} DMA buffer; skipping", DMA_CHANNEL);
        return false;
    }
    let pages = RING_BYTES.div_ceil(0x1000);
    machine.map_phys_range(DMA_WIN_VA >> 12, pages, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    // Start from silence so the first auto-init lap before prime isn't garbage.
    unsafe { core::ptr::write_bytes(DMA_WIN_VA as *mut u8, 0, RING_BYTES) };

    machine.outb(MIX_IDX, 0x22); // master volume index
    machine.outb(MIX_DATA, 0xFF); // full
    dsp_write(machine, CMD_SPEAKER_ON);

    *SB16.lock() = Some(Sb16 {
        dma_va: DMA_WIN_VA,
        dma_phys,
        cur_buf: 0,
        cur_off: 0,
        running: false,
        rate: 0,
        written: 0,
        consumed_bufs: 0,
    });
    IRQ_LINE.store(irq as u32, Ordering::Relaxed);
    crate::println!("sb16: {:#05x} DSP up, IRQ {}, DMA {}", BASE, irq, DMA_CHANNEL);
    true
}

impl Sb16 {
    fn buf_va(&self, i: usize) -> usize {
        self.dma_va + i * BUF_BYTES
    }

    fn set_rate<A: crate::Arch>(&mut self, machine: &mut A, rate: u32) {
        if rate != self.rate && rate != 0 {
            dsp_write(machine, CMD_SET_RATE_OUT);
            dsp_write(machine, (rate >> 8) as u8);
            dsp_write(machine, rate as u8);
            self.rate = rate;
        }
    }

    /// Program the 8237 for the whole ring in 16-bit auto-init, then start the
    /// DSP's 16-bit auto-init output with a per-buffer block length. Done once,
    /// after the first buffers are primed; the DSP then free-runs the ring and
    /// raises the completion IRQ every buffer.
    fn start<A: crate::Arch>(&mut self, machine: &mut A) {
        let word_addr = (self.dma_phys >> 1) & 0xFFFF;
        let words = (RING_BYTES / 2) as u32;
        machine.outb(DMA5_MASK, 0x05); // mask channel 5
        machine.outb(DMA5_CLRFF, 0);
        machine.outb(DMA5_MODE, DMA5_MODE_AUTO_READ);
        machine.outb(DMA5_ADDR, word_addr as u8);
        machine.outb(DMA5_ADDR, (word_addr >> 8) as u8);
        machine.outb(DMA5_PAGE, (self.dma_phys >> 16) as u8);
        machine.outb(DMA5_COUNT, (words - 1) as u8);
        machine.outb(DMA5_COUNT, ((words - 1) >> 8) as u8);
        machine.outb(DMA5_MASK, 0x01); // unmask channel 5

        // DSP block length in 16-bit samples − 1 (one buffer per IRQ). Mono, so
        // a buffer is BUF_FRAMES samples.
        let block_samples = BUF_FRAMES as u16;
        dsp_write(machine, CMD_16BIT_AUTO_OUT);
        dsp_write(machine, MODE_SIGNED_MONO);
        dsp_write(machine, (block_samples - 1) as u8);
        dsp_write(machine, ((block_samples - 1) >> 8) as u8);
        self.running = true;
    }

    /// Decode `bytes` (`fmt`) into canonical i16 stereo and stream into the ring.
    fn submit<A: crate::Arch>(&mut self, machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
        self.set_rate(machine, rate);
        let fb = fmt.frame_bytes();
        if fb == 0 {
            return;
        }
        for i in 0..bytes.len() / fb {
            let (l, r) = fmt.frame(bytes, i);
            let m = ((l as i32 + r as i32) / 2) as i16; // downmix to mono
            let p = self.buf_va(self.cur_buf) + self.cur_off;
            unsafe {
                core::ptr::write_volatile(p as *mut u16, m as u16);
            }
            self.written += 1;
            self.cur_off += 2;
            if self.cur_off >= BUF_BYTES {
                self.cur_buf = (self.cur_buf + 1) % NUM_BUF;
                self.cur_off = 0;
                if !self.running && self.cur_buf >= PRIME_BUFS {
                    self.start(machine);
                }
            }
        }
    }
}

/// Stream a block of source PCM to the SB16 (called by `sound::play`).
pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    let mut g = SB16.lock();
    if let Some(dev) = g.as_mut() {
        dev.submit(machine, rate, fmt, bytes);
    }
}

/// Service a block-completion interrupt (canonical `Irq::Hw(irq_line())` routed
/// here by `sound::on_hw_irq`). One interrupt = one buffer drained, so it just
/// advances the consumed clock and acknowledges the DSP's 16-bit IRQ latch.
/// No DMA counter is read — the interrupt itself is the completion signal.
pub fn on_irq<A: crate::Arch>(machine: &mut A) {
    let mut g = SB16.lock();
    if let Some(dev) = g.as_mut() {
        if dev.running {
            dev.consumed_bufs += 1;
        }
    }
    let _ = machine.inb(DSP_ACK16); // acknowledge the 16-bit completion IRQ
}

/// Pipe counters for `sound::position`, in source frames: `written` accepted,
/// and `consumed` = finished buffers × frames-per-buffer (from the IRQ count).
pub fn position<A: crate::Arch>(machine: &mut A) -> Option<(u64, u64)> {
    let _ = machine;
    let g = SB16.lock();
    let dev = g.as_ref()?;
    Some((dev.written, dev.consumed_bufs * BUF_FRAMES as u64))
}

/// Producer went idle. `park` ends the session: stop auto-init and reset counters.
pub fn stop<A: crate::Arch>(machine: &mut A, park: bool) {
    let mut g = SB16.lock();
    let Some(dev) = g.as_mut() else { return };
    if park && dev.running {
        dsp_write(machine, CMD_EXIT_AUTO_16);
        machine.outb(DMA5_MASK, 0x05); // mask channel 5
        dev.running = false;
        dev.cur_buf = 0;
        dev.cur_off = 0;
        dev.written = 0;
        dev.consumed_bufs = 0;
    }
}
