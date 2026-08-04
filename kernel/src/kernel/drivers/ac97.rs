//! Intel AC'97 audio output — a kernel device driver (not machine code).
//!
//! On a host with an AC'97 codec but no Sound Blaster, the emulated SB
//! (`dos/machine/vsb.rs`) produces canonical PCM and the kernel `sound` layer
//! needs somewhere to play it. This driver is that sink on metal: `sound::play`
//! dispatches here when [`init`] discovered a codec at boot (PCI class 04:01).
//! It uses only machine *primitives* — 32-bit port I/O (`inl`/`outl`, for PCI
//! config + the AC'97 bus-master registers), `dma_channel_buf` (the existing
//! contiguous DMA buffer), and `map_phys_range` (to map that buffer into kernel
//! space) — never any machine-side driver logic.
//!
//! ## DMA buffer (TEMPORARY placement — see the load-bearing note below)
//!
//! The codec bus-masters PCM out of a buffer the kernel must also be able to
//! *write*. We reuse a `dma_channel_buf` (physically contiguous, < 16 MB) and
//! map it into kernel space by **repurposing a dead slice of the low-mem
//! identity window**: the kernel maps the whole first 1 MB at `LOW_MEM_BASE`,
//! but only ever dereferences the DOS `LowMem` struct (~`0x500..0x3800`) and the
//! VGA band (`0xA0000..0xBFFFF`). The slice over the upper-memory area
//! (`0xC0000..0x100000`) is mapped-but-dead — and that phys is ROM/MMIO, never
//! real RAM — so we steal the kernel VA `LOW_MEM_BASE + 0xC0000` and point it at
//! the channel buffer's phys instead.
//!
//! **This is a stopgap.** The right fix is to stop blindly identity-mapping the
//! whole 1 MB and instead expose the freed VA as a real kernel DMA-window pool;
//! see memory `project_ac97_lowmem_dma_window_todo`. Until then, do NOT "restore"
//! the `LOW_MEM_BASE + 0xC0000` window to identity — this driver owns it.

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;


// ── PCI config space (0xCF8 address / 0xCFC data) ───────────────────────────

// ── AC'97 register offsets ──────────────────────────────────────────────────
// NAM (Native Audio Mixer, BAR0): the codec's mixer/rate registers (16-bit).
const NAM_RESET: u16 = 0x00;
const NAM_MASTER_VOL: u16 = 0x02;
const NAM_PCM_OUT_VOL: u16 = 0x18;
const NAM_EXT_CAP: u16 = 0x28; // bit0 = VRA supported
const NAM_EXT_CTRL: u16 = 0x2A; // bit0 = VRA enable
const NAM_PCM_DAC_RATE: u16 = 0x2C; // sample rate when VRA enabled

// NABM (Native Audio Bus Master, BAR1): the DMA engine. PCM-Out ("PO") channel.
const PO_BDBAR: u16 = 0x10; // 32-bit: BDL base physical address
const PO_CIV: u16 = 0x14; // 8-bit: current index value (RO)
const PO_LVI: u16 = 0x15; // 8-bit: last valid index
const PO_SR: u16 = 0x16; // 16-bit: status; bit2 LVBCI, bit3 BCIS, bit4 FIFOE (W1C)
const PO_CR: u16 = 0x1B; // 8-bit: control (bit0 run, bit1 reset, bit4 IOCE)
const GLOB_CNT: u16 = 0x2C; // 32-bit: bit1 = AC-link out of cold reset
const GLOB_STA: u16 = 0x30; // 32-bit: bit8 = primary codec ready

const PO_CR_RUN: u8 = 0x01;
const PO_CR_RESET: u8 = 0x02;
const PO_CR_IOCE: u8 = 0x10; // interrupt-on-completion enable
/// BDL entry control word bit 15: interrupt on completion of this buffer.
const BDL_IOC: u16 = 1 << 15;
/// All three PO status interrupt bits (LVBCI | BCIS | FIFOE), write-1-to-clear.
const PO_SR_INTR: u16 = 0x1C;

// ── DMA ring geometry ───────────────────────────────────────────────────────
/// Kernel VA we steal from the low-mem identity window (over phys
/// `0xC0000`, the dead upper-memory area) to map the channel buffer.
const DMA_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_0000;
/// DMA channel whose permanent contiguous buffer we borrow (16-bit channel →
/// 128 KB / 32 pages). Free on a cardless host (the SB is emulated, not
/// passed through, so it never touches the real channels).
const DMA_CHANNEL: usize = 5;
const PTE_CACHE_DISABLE: u64 = 1 << 4;

const BDL_BYTES: usize = 0x1000; // first page of the buffer holds the BDL
/// Use the FULL 32-entry BDL — one descriptor per ring block, no mirrors.
/// Geometry belongs to the sound sink; this is the count of BDL
/// entries the device programs, which must agree with it.
use crate::kernel::sound::{BUF_BYTES, NUM_BUF};

/// What only an AC'97 knows. The ring, the counters and the underrun test
/// belong to the sink engine; this is the bus-master programming and the
/// CIV bookkeeping that turns a completion into "N blocks played".
struct Ac97 {
    nam: u16,       // NAM I/O base
    nabm: u16,      // NABM I/O base
    dma_va: usize,  // kernel VA of the mapped channel buffer
    dma_phys: u32,  // its physical base address (for the codec / BDL)
    /// Last CIV seen, for accumulating block deltas across ring wraps.
    last_civ: u8,
    /// Blocks the engine has been told about, so a coalesced interrupt emits
    /// the difference rather than one event.
    reported: u64,
    played: u64,
}

static AC97: Mutex<Option<Ac97>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);
/// Private kernel MSI identity used when the controller exposes MSI.
pub const MSI_SOURCE: u8 = 1;
static MSI_ON: AtomicBool = AtomicBool::new(false);
/// The wired IRQ line the codec's INTx was routed to (from PCI config 0x3C), so
/// the canonical audio-IRQ router can match it. 0xFF until bring-up. Production
/// is always driven from this interrupt — there is no polled model.
static IRQ_LINE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0xFF);

/// The routed completion-IRQ line, for `sound::on_irq`. `None` when MSI is used
/// or until bring-up has selected the INTx fallback.
pub fn irq_line() -> Option<u8> {
    match IRQ_LINE.load(Ordering::Relaxed) {
        0xFF => None,
        n => Some(n as u8),
    }
}

pub fn msi_active() -> bool {
    MSI_ON.load(Ordering::Relaxed)
}

/// Find an AC'97 codec (class 0x04, subclass 0x01) anywhere on PCI, via the
/// shared `pci::find_class` scan. Pure presence probe — `platform::probe` uses
/// it for the Audio decision; on a no-PCI backend (the interpreter) every read
/// is 0xFFFFFFFF and nothing is found.
pub fn scan<A: crate::Arch>(machine: &mut A) -> Option<(u8, u8, u8)> {
    crate::kernel::pci::find_class(machine, 0x04, 0x01)
}

/// Bring up the codec the platform probe found. Driver init only — the
/// routing decision is `platform::Audio` (EmulatedAc97); PRESENT here means
/// "driver is actually up" and guards `play` against a failed bring-up.
pub fn init<A: crate::Arch>(machine: &mut A) {
    if crate::kernel::platform::get().audio != crate::kernel::platform::Audio::EmulatedAc97 {
        return;
    }
    let (bus, dev, func) = scan(machine).expect("platform probe saw an AC'97 codec; scan must agree");
    if bring_up(machine, bus, dev, func) {
        PRESENT.store(true, Ordering::Relaxed);
    }
}

/// Bring up the codec at `bus:dev.func`. Returns true on success.
fn bring_up<A: crate::Arch>(machine: &mut A, bus: u8, dev: u8, func: u8) -> bool {
    // Enable I/O space + bus-master in the PCI command register (low 16 bits of
    // dword 0x04). Writing 0 to the status word (high 16) is harmless (RW1C).
    let cmd = crate::kernel::pci::read32(machine, bus, dev, func, 0x04);
    crate::kernel::pci::write32(machine, bus, dev, func, 0x04, (cmd & 0xFFFF) | 0x05);

    // Prefer a namespace-safe MSI. Older AC'97 controllers commonly lack the
    // capability, so retain INTx as a fallback; that path still depends on the
    // firmware's Interrupt Line value until ACPI PCI routing is available.
    let msi = machine
        .msi_alloc(MSI_SOURCE)
        .is_some_and(|(addr, data)| {
            crate::kernel::pci::msi_enable(machine, bus, dev, func, addr, data)
        });
    if msi {
        MSI_ON.store(true, Ordering::Relaxed);
        crate::println!("ac97: {:02x}:{:02x}.{} MSI on", bus, dev, func);
    } else {
        let line =
            (crate::kernel::pci::read32(machine, bus, dev, func, 0x3C) & 0xFF) as u8;
        if !(1..=15).contains(&line) {
            crate::println!(
                "ac97: {:02x}:{:02x}.{} no MSI/INTx route; skipping",
                bus, dev, func
            );
            return false;
        }
        machine.route_device_irq(line);
        IRQ_LINE.store(line as u32, Ordering::Relaxed);
        crate::println!("ac97: {:02x}:{:02x}.{} INTx line {}", bus, dev, func, line);
    }

    let nam = (crate::kernel::pci::read32(machine, bus, dev, func, 0x10) & 0xFFFC) as u16; // BAR0
    let nabm = (crate::kernel::pci::read32(machine, bus, dev, func, 0x14) & 0xFFFC) as u16; // BAR1
    if nam == 0 || nabm == 0 {
        return false;
    }

    // Bring the AC-link out of cold reset, then wait for the primary codec.
    machine.outl(nabm + GLOB_CNT, 0x02);
    let mut ready = false;
    for _ in 0..1_000_000 {
        if machine.inl(nabm + GLOB_STA) & 0x100 != 0 {
            ready = true;
            break;
        }
    }
    if !ready {
        return false;
    }

    // Reset the mixer, unmute master + PCM-out at full volume (0 = 0 dB).
    machine.outw(nam + NAM_RESET, 0);
    machine.outw(nam + NAM_MASTER_VOL, 0x0000);
    machine.outw(nam + NAM_PCM_OUT_VOL, 0x0000);
    // Enable variable-rate audio so we can play the guest's native rate without
    // resampling (the SB emulation produces 22050/etc., not the AC'97 48 kHz).
    if machine.inw(nam + NAM_EXT_CAP) & 1 != 0 {
        let ctrl = machine.inw(nam + NAM_EXT_CTRL);
        machine.outw(nam + NAM_EXT_CTRL, ctrl | 1);
    }

    // Reset the PCM-out bus-master engine.
    machine.outb(nabm + PO_CR, PO_CR_RESET);
    for _ in 0..1_000_000 {
        if machine.inb(nabm + PO_CR) & PO_CR_RESET == 0 {
            break;
        }
    }

    // Map the channel buffer into the stolen low-mem window VA so the kernel can
    // write PCM into it; the codec reads it (and the BDL) by physical address.
    let phys_page = machine.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        return false;
    }
    let pages = (BDL_BYTES + NUM_BUF * BUF_BYTES).div_ceil(0x1000);
    machine.map_phys_range(DMA_WIN_VA >> 12, pages, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    let mut d = Ac97 {
        nam, nabm,
        dma_va: DMA_WIN_VA,
        dma_phys,
        last_civ: 0,
        reported: 0,
        played: 0,
    };
    d.build_bdl();
    machine.outl(nabm + PO_BDBAR, dma_phys); // BDL base
    *AC97.lock() = Some(d);
    true
}

impl Ac97 {
    /// Physical address of PCM ring buffer `i`.
    fn buf_phys(&self, i: usize) -> u32 {
        self.dma_phys + (BDL_BYTES + i * BUF_BYTES) as u32
    }
    /// Fill the BDL: entry i → buffer i, length in 16-bit samples. Control word
    /// carries IOC — one interrupt per completed buffer drives the event-loop
    /// audio track. NUM_BUF == 32 so every entry maps a distinct buffer — no
    /// mirrored entries to replay.
    fn build_bdl(&mut self) {
        let ctrl = BDL_IOC;
        for i in 0..NUM_BUF {
            let entry = self.dma_va + i * 8;
            let samples = (BUF_BYTES / 2) as u16; // 16-bit samples per buffer
            unsafe {
                core::ptr::write_volatile(entry as *mut u32, self.buf_phys(i));
                core::ptr::write_volatile((entry + 4) as *mut u16, samples);
                core::ptr::write_volatile((entry + 6) as *mut u16, ctrl);
            }
        }
    }

}

// ── the primitives the sink engine asks of a device ─────────────────────────

/// Where the engine writes PCM: the ring starts after the BDL page.
pub fn adopt<A: crate::Arch>(machine: &mut A) -> Option<(usize, u32)> {
    let _ = machine;
    let g = AC97.lock();
    let d = g.as_ref()?;
    Some((d.dma_va + BDL_BYTES, d.dma_phys + BDL_BYTES as u32))
}

/// Program the DAC rate. Variable-rate audio was enabled at bring-up, so the
/// codec plays the source rate directly — no resampler in this path.
pub fn set_rate(rate: u32) {
    let Some(nam) = AC97.lock().as_ref().map(|d| d.nam) else { return };
    crate::kernel::portio::outw(nam + NAM_PCM_DAC_RATE, rate as u16);
}

/// Kernel VA of the ring, for rebuilding a sink around this device.
pub fn ring_va() -> usize {
    AC97.lock().as_ref().map_or(0, |d| d.dma_va + BDL_BYTES)
}

/// Start the bus master, and give it a full ring of runway.
///
/// LVI tracks the PLAY cursor, not the producer: it is kept one block behind
/// CIV, so the engine has 31 blocks ahead of it and never arrives. That is
/// what makes an AC'97 free-run like the other devices — the hardware halts
/// when `CIV == LVI` (setting DCH/LVBCI/CELV) and only an LVI write restarts
/// it, so a trailing LVI is the difference between a continuous transfer and
/// one that stops every ring.
pub fn start() {
    use crate::kernel::portio::{inb, outb};
    let mut g = AC97.lock();
    let Some(d) = g.as_mut() else { return };
    d.last_civ = 0;
    d.reported = 0;
    d.played = 0;
    outb(d.nabm + PO_LVI, (NUM_BUF - 1) as u8);
    let cr = inb(d.nabm + PO_CR);
    outb(d.nabm + PO_CR, cr | PO_CR_RUN | PO_CR_IOCE);
    crate::println!("ac97: stream RUN lvi={} cr={:#x}", NUM_BUF - 1, inb(d.nabm + PO_CR));
}

/// Stop the bus master.
pub fn halt() {
    use crate::kernel::portio::{inb, outb};
    let mut g = AC97.lock();
    let Some(d) = g.as_mut() else { return };
    let cr = inb(d.nabm + PO_CR);
    outb(d.nabm + PO_CR, cr & !PO_CR_RUN);
}

/// Is this interrupt ours, and how many blocks played since we last said?
pub fn irq_pending() -> bool {
    use crate::kernel::portio::{inw, outw};
    let mut g = AC97.lock();
    let Some(d) = g.as_mut() else { return false };
    let status = inw(d.nabm + PO_SR);
    if status & PO_SR_INTR == 0 {
        return false;
    }
    outw(d.nabm + PO_SR, status & PO_SR_INTR);
    true
}

/// Blocks played since the last report, without requiring an interrupt.
pub fn blocks_played() -> u64 {
    let mut g = AC97.lock();
    match g.as_mut() {
        Some(d) => advance(d),
        None => 0,
    }
}

/// Read CIV, accumulate the block delta, and keep LVI one block behind it.
///
/// Bumping LVI here is also the recovery path: if we were ever late enough
/// that CIV caught LVI, the engine halted with DCH set, and this write is
/// exactly what the hardware needs to resume (`CR_RPBM && DCH` → clear DCH,
/// re-fetch the descriptor). So a late service costs a stall, never a wedge.
fn advance(d: &mut Ac97) -> u64 {
    use crate::kernel::portio::{inb, outb};
    let civ = inb(d.nabm + PO_CIV) % NUM_BUF as u8;
    let delta = (civ + NUM_BUF as u8 - d.last_civ) % NUM_BUF as u8;
    if delta != 0 {
        d.played += delta as u64;
        d.last_civ = civ;
        outb(d.nabm + PO_LVI, (civ + NUM_BUF as u8 - 1) % NUM_BUF as u8);
    }
    let fresh = d.played.saturating_sub(d.reported);
    d.reported = d.played;
    fresh
}

/// Minimum pipe fill for a position-slaved producer, in source frames: the
/// bus master only plays *completed* ring buffers (LVI gates it), so the
/// fill must always span the start prime (`PRIME_BUFS` full buffers) plus a
/// partial buffer of slack — below that the engine halts at LVI while the
/// producer waits for consumption, and the pipe deadlocks.
/// The sink is up and can use this card's completion clock for latency feedback.
/// The pipe latency itself is not this driver's to set.
pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}
