//! Intel AC'97 audio output — a kernel device driver (not machine code).
//!
//! On a host with an AC'97 codec but no Sound Blaster, the emulated SB
//! (`dos/machine/vsb.rs`) produces canonical PCM and the kernel `sound` layer
//! needs somewhere to play it. This driver is that sink on metal: `sound::play`
//! dispatches here when [`probe`] discovered a codec at boot (PCI class 04:01).
//! It uses only machine *primitives* — 32-bit port I/O (`inl`/`outl`, for PCI
//! config + the AC'97 bus-master registers), `alloc_phys_contig` (a dedicated
//! contiguous DMA buffer), and `map_phys_range` (to map that buffer into kernel
//! space) — never any machine-side driver logic.
//!
//! ## DMA buffer (TEMPORARY placement — see the load-bearing note below)
//!
//! The codec bus-masters PCM out of a buffer the kernel must also be able to
//! *write*. We allocate physically contiguous PCI DMA memory and
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

// ── PCI config space (0xCF8 address / 0xCFC data) ───────────────────────────

// ── AC'97 register offsets ──────────────────────────────────────────────────
// NAM (Native Audio Mixer, BAR0): the codec's mixer/rate registers (16-bit).
const NAM_RESET: u16 = 0x00;
const NAM_MASTER_VOL: u16 = 0x02;
const NAM_PCM_OUT_VOL: u16 = 0x18;
const NAM_EXT_CAP: u16 = 0x28; // bit0 = VRA supported
const NAM_EXT_CTRL: u16 = 0x2A; // bit0 = VRA enable

// NABM (Native Audio Bus Master, BAR1): the DMA engine. PCM-Out ("PO") channel.
const PO_BDBAR: u16 = 0x10; // 32-bit: BDL base physical address
const PO_CIV: u16 = 0x14; // 8-bit: current index value (RO)
const PO_LVI: u16 = 0x15; // 8-bit: last valid index
const PO_CR: u16 = 0x1B; // 8-bit: control (bit0 run, bit1 reset)
const PO_PICB: u16 = 0x18; // 16-bit: position in current buffer (RO)
const GLOB_CNT: u16 = 0x2C; // 32-bit: bit1 = AC-link out of cold reset
const GLOB_STA: u16 = 0x30; // 32-bit: bit8 = primary codec ready

const PO_CR_RUN: u8 = 0x01;
const PO_CR_RESET: u8 = 0x02;

// ── DMA ring geometry ───────────────────────────────────────────────────────
/// Kernel VA we steal from the low-mem identity window (over phys
/// `0xC0000`, the dead upper-memory area) to map the channel buffer.
const DMA_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_0000;
const PTE_CACHE_DISABLE: u64 = 1 << 4;

const BDL_BYTES: usize = 0x1000; // first page of the buffer holds the BDL
const NUM_BUF: usize = 32;
const BUF_BYTES: usize = 0x800;
const BUF_FRAMES: usize = BUF_BYTES / core::mem::size_of::<crate::kernel::sound::Frame>();
const RING_FRAMES: usize = NUM_BUF * BUF_FRAMES;

/// What only an AC'97 knows. The ring, the counters and the underrun test
/// belong to the sink engine; this is the bus-master programming and the
/// CIV/PICB bookkeeping that turns a cursor position into "N frames played".
pub struct Ac97 {
    nabm: u16,      // NABM I/O base
    dma_va: usize,  // kernel VA of the mapped channel buffer
    dma_phys: u32,  // its physical base address (for the codec / BDL)
    /// Last cursor position seen, in frames from the ring origin.
    last_pos_frames: u64,
    /// Frames already reported to the sink.
    reported_frames: u64,
    played_frames: u64,
}

// Written once during single-threaded boot, then reachable only through the
// unique capability returned by `probe`.
static mut AC97: Option<Ac97> = None;

/// Find an AC'97 codec (class 0x04, subclass 0x01) anywhere on PCI.
fn scan<A: crate::Arch>(machine: &mut A) -> Option<(u8, u8, u8)> {
    crate::kernel::pci::find_class(machine, 0x04, 0x01)
}

/// Bring up the selected codec and return its unique runtime capability.
pub fn probe<A: crate::Arch>(machine: &mut A) -> Option<&'static mut Ac97> {
    let (bus, dev, func) = scan(machine)?;
    let device = bring_up(machine, bus, dev, func)?;
    unsafe {
        let slot = &raw mut AC97;
        assert!((*slot).is_none(), "AC97 probed twice");
        *slot = Some(device);
        (*slot).as_mut()
    }
}

/// Bring up the codec at `bus:dev.func`.
fn bring_up<A: crate::Arch>(machine: &mut A, bus: u8, dev: u8, func: u8) -> Option<Ac97> {
    // Enable I/O space + bus-master and suppress INTx: playback progress is
    // polled from CIV/PICB, so this sink deliberately generates no interrupts.
    let cmd = crate::kernel::pci::read32(machine, bus, dev, func, 0x04);
    crate::kernel::pci::write32(
        machine,
        bus,
        dev,
        func,
        0x04,
        (cmd & 0xFFFF) | 0x05 | (1 << 10),
    );

    let nam = (crate::kernel::pci::read32(machine, bus, dev, func, 0x10) & 0xFFFC) as u16; // BAR0
    let nabm = (crate::kernel::pci::read32(machine, bus, dev, func, 0x14) & 0xFFFC) as u16; // BAR1
    if nam == 0 || nabm == 0 {
        return None;
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
        return None;
    }

    // Reset the mixer, unmute master + PCM-out at full volume (0 = 0 dB).
    machine.outw(nam + NAM_RESET, 0);
    machine.outw(nam + NAM_MASTER_VOL, 0x0000);
    machine.outw(nam + NAM_PCM_OUT_VOL, 0x0000);
    // Leave variable-rate audio DISABLED: the DAC runs at the AC'97 link's
    // fixed 48 kHz, which is this card's rate and what the mixer renders to.
    // VRA used to be enabled here so the codec could play a guest's native
    // rate directly, but rate conversion belongs to the mixer, which resamples
    // every source anyway — and a VRA rate write is silently dropped by a
    // codec that does not implement it, leaving the DAC at 48 kHz while the
    // mixer produced 44.1 kHz (everything ~8.8% sharp).
    if machine.inw(nam + NAM_EXT_CAP) & 1 != 0 {
        let ctrl = machine.inw(nam + NAM_EXT_CTRL);
        machine.outw(nam + NAM_EXT_CTRL, ctrl & !1);
    }

    // Reset the PCM-out bus-master engine.
    machine.outb(nabm + PO_CR, PO_CR_RESET);
    for _ in 0..1_000_000 {
        if machine.inb(nabm + PO_CR) & PO_CR_RESET == 0 {
            break;
        }
    }

    // Map a dedicated PCI DMA buffer into the stolen low-mem window VA so the
    // kernel can write PCM into it; the codec reads it by physical address.
    let pages = (BDL_BYTES + NUM_BUF * BUF_BYTES).div_ceil(0x1000);
    let phys_page = machine.alloc_phys_contig(pages, 0);
    if phys_page == 0 {
        return None;
    }
    machine.map_phys_range(DMA_WIN_VA >> 12, pages, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    let mut d = Ac97 {
        nabm,
        dma_va: DMA_WIN_VA,
        dma_phys,
        last_pos_frames: 0,
        reported_frames: 0,
        played_frames: 0,
    };
    d.build_bdl();
    machine.outl(nabm + PO_BDBAR, dma_phys); // BDL base
    Some(d)
}

impl Ac97 {
    /// Physical address of PCM ring buffer `i`.
    fn buf_phys(&self, i: usize) -> u32 {
        self.dma_phys + (BDL_BYTES + i * BUF_BYTES) as u32
    }
    /// Fill the BDL: entry i → buffer i, length in 16-bit samples. Progress is
    /// polled from CIV/PICB, so every control word disables completion
    /// interrupts.
    fn build_bdl(&mut self) {
        for i in 0..NUM_BUF {
            let entry = self.dma_va + i * 8;
            let samples = (BUF_BYTES / 2) as u16; // 1024 samples = 512 stereo frames
            unsafe {
                core::ptr::write_volatile(entry as *mut u32, self.buf_phys(i));
                core::ptr::write_volatile((entry + 4) as *mut u16, samples);
                core::ptr::write_volatile((entry + 6) as *mut u16, 0);
            }
        }
    }

}

// ── the primitives the sink engine asks of a device ─────────────────────────

impl Ac97 {
    pub fn ring(&mut self) -> &'static mut [crate::kernel::sound::Frame] {
        unsafe {
            core::slice::from_raw_parts_mut(
                (self.dma_va + BDL_BYTES) as *mut crate::kernel::sound::Frame,
                RING_FRAMES,
            )
        }
    }
}

impl sound::sink::Device for Ac97 {
    fn rate(&self) -> u32 {
        48_000
    }

    fn block_frames(&self) -> usize {
        BUF_FRAMES
    }

    fn start(&mut self) {
        use crate::kernel::portio::{inb, outb};
        self.last_pos_frames = 0;
        self.reported_frames = 0;
        self.played_frames = 0;
        outb(self.nabm + PO_LVI, (NUM_BUF - 1) as u8);
        let cr = inb(self.nabm + PO_CR);
        outb(self.nabm + PO_CR, (cr & !0x10) | PO_CR_RUN);
        crate::println!(
            "ac97: stream RUN lvi={} cr={:#x}",
            NUM_BUF - 1,
            inb(self.nabm + PO_CR)
        );
    }

    fn halt(&mut self) {
        use crate::kernel::portio::{inb, outb};
        let cr = inb(self.nabm + PO_CR);
        outb(self.nabm + PO_CR, cr & !PO_CR_RUN);
    }

    fn frames_played(&mut self) -> u64 {
        advance_frames(self)
    }
}

/// Read CIV/PICB, accumulate the frame delta, and keep LVI one descriptor
/// behind the current cursor.
///
/// Bumping LVI here is also the recovery path: if we were ever late enough
/// that CIV caught LVI, the engine halted with DCH set, and this write is
/// exactly what the hardware needs to resume (`CR_RPBM && DCH` → clear DCH,
/// re-fetch the descriptor). So a late service costs a stall, never a wedge.
fn advance_frames(d: &mut Ac97) -> u64 {
    use crate::kernel::portio::{inb, inw, outb};
    let (civ, pos_frames) = loop {
        let civ = inb(d.nabm + PO_CIV) % NUM_BUF as u8;
        let picb = inw(d.nabm + PO_PICB) as u64;
        if civ == inb(d.nabm + PO_CIV) % NUM_BUF as u8 {
            let remaining_frames = (picb / 2).min(BUF_FRAMES as u64);
            let pos_frames =
                (civ as u64 * BUF_FRAMES as u64) + (BUF_FRAMES as u64 - remaining_frames);
            break (civ, pos_frames % RING_FRAMES as u64);
        }
    };
    let delta = (pos_frames + RING_FRAMES as u64 - d.last_pos_frames) % RING_FRAMES as u64;
    if delta != 0 {
        d.played_frames += delta;
        d.last_pos_frames = pos_frames;
        outb(d.nabm + PO_LVI, (civ + NUM_BUF as u8 - 1) % NUM_BUF as u8);
    }
    let fresh = d.played_frames.saturating_sub(d.reported_frames);
    d.reported_frames = d.played_frames;
    fresh
}
