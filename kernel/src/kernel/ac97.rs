//! Intel AC'97 audio output — a kernel device driver (not arch code).
//!
//! On a host with an AC'97 codec but no Sound Blaster, the emulated SB
//! (`dos/machine/vsb.rs`) produces canonical PCM and the kernel `sound` layer
//! needs somewhere to play it. This driver is that sink on metal: `sound::play`
//! dispatches here when [`init`] discovered a codec at boot (PCI class 04:01).
//! It uses only arch *primitives* — 32-bit port I/O (`inl`/`outl`, for PCI
//! config + the AC'97 bus-master registers), `dma_channel_buf` (the existing
//! contiguous DMA buffer), and `map_phys_range` (to map that buffer into kernel
//! space) — never any arch-side driver logic.
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

use arch_abi::Arch;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::kernel::sound::Format;

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
const PO_CR: u16 = 0x1B; // 8-bit: control (bit0 run, bit1 reset)
const GLOB_CNT: u16 = 0x2C; // 32-bit: bit1 = AC-link out of cold reset
const GLOB_STA: u16 = 0x30; // 32-bit: bit8 = primary codec ready

const PO_CR_RUN: u8 = 0x01;
const PO_CR_RESET: u8 = 0x02;

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
/// Use the FULL 32-entry BDL. A shorter ring leaves entries 16..31 mirroring
/// 0..15, and the bus master replays them when its index runs past LVI — an
/// audible ~ring-length echo. 32 distinct buffers, no mirror.
const NUM_BUF: usize = 32;
const BUF_BYTES: usize = 0x800; // 2 KB each = 512 stereo frames ≈ 23 ms @ 22 kHz
/// Prefill this many buffers before starting the bus master — a small cushion so
/// the gate-paced producer's jitter doesn't underrun the codec (clicking).
const PRIME_BUFS: usize = 3;
/// Cap how far the producer may run ahead of the codec (`LVI − CIV`). This
/// BOUNDS LATENCY — without it, any producer/codec clock drift lets the queue
/// grow to the whole ring (~0.7 s). It also keeps LVI from lapping CIV, which
/// would make the bus master replay buffers (echo). ≈ 6 × 23 ms ≈ 140 ms.
const MAX_AHEAD: usize = 6;

struct Ac97 {
    nam: u16,       // NAM I/O base
    nabm: u16,      // NABM I/O base
    dma_va: usize,  // kernel VA of the mapped channel buffer
    dma_phys: u32,  // its physical base address (for the codec / BDL)
    cur_buf: usize, // ring buffer currently being filled
    cur_off: usize, // byte offset within `cur_buf`
    running: bool,  // bus master started
    rate: u32,      // last programmed sample rate (Hz)
}

static AC97: Mutex<Option<Ac97>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);

/// Whether a codec was discovered (fast path for `sound::play`).
pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

/// Find an AC'97 codec on PCI bus 0 (QEMU/ICH put it there), function 0.
/// Pure presence scan — `platform::probe` uses it for the Audio decision; on
/// a backend with no PCI (the interpreter) every config read is 0xFFFFFFFF
/// and nothing is found.
pub fn scan(arch: &mut crate::TheArch) -> Option<u8> {
    for dev in 0..32u8 {
        let id = crate::kernel::pci::read32(arch, 0, dev, 0, 0x00);
        if id & 0xFFFF == 0xFFFF {
            continue; // no device in this slot
        }
        let classes = crate::kernel::pci::read32(arch, 0, dev, 0, 0x08);
        let class = (classes >> 24) & 0xFF;
        let subclass = (classes >> 16) & 0xFF;
        if class == 0x04 && subclass == 0x01 {
            return Some(dev);
        }
    }
    None
}

/// Bring up the codec the platform probe found. Driver init only — the
/// routing decision is `platform::Audio` (EmulatedAc97); PRESENT here means
/// "driver is actually up" and guards `play` against a failed bring-up.
pub fn init(arch: &mut crate::TheArch) {
    if crate::kernel::platform::get().audio != crate::kernel::platform::Audio::EmulatedAc97 {
        return;
    }
    let dev = scan(arch).expect("platform probe saw an AC'97 codec; scan must agree");
    if bring_up(arch, dev) {
        PRESENT.store(true, Ordering::Relaxed);
    }
}

/// Bring up the codec at bus 0 / `dev`. Returns true on success.
fn bring_up(arch: &mut crate::TheArch, dev: u8) -> bool {
    // Enable I/O space + bus-master in the PCI command register (low 16 bits of
    // dword 0x04). Writing 0 to the status word (high 16) is harmless (RW1C).
    let cmd = crate::kernel::pci::read32(arch, 0, dev, 0, 0x04);
    crate::kernel::pci::write32(arch, 0, dev, 0, 0x04, (cmd & 0xFFFF) | 0x05);

    let nam = (crate::kernel::pci::read32(arch, 0, dev, 0, 0x10) & 0xFFFC) as u16; // BAR0
    let nabm = (crate::kernel::pci::read32(arch, 0, dev, 0, 0x14) & 0xFFFC) as u16; // BAR1
    if nam == 0 || nabm == 0 {
        return false;
    }

    // Bring the AC-link out of cold reset, then wait for the primary codec.
    arch.outl(nabm + GLOB_CNT, 0x02);
    let mut ready = false;
    for _ in 0..1_000_000 {
        if arch.inl(nabm + GLOB_STA) & 0x100 != 0 {
            ready = true;
            break;
        }
    }
    if !ready {
        return false;
    }

    // Reset the mixer, unmute master + PCM-out at full volume (0 = 0 dB).
    arch.outw(nam + NAM_RESET, 0);
    arch.outw(nam + NAM_MASTER_VOL, 0x0000);
    arch.outw(nam + NAM_PCM_OUT_VOL, 0x0000);
    // Enable variable-rate audio so we can play the guest's native rate without
    // resampling (the SB emulation produces 22050/etc., not the AC'97 48 kHz).
    if arch.inw(nam + NAM_EXT_CAP) & 1 != 0 {
        let ctrl = arch.inw(nam + NAM_EXT_CTRL);
        arch.outw(nam + NAM_EXT_CTRL, ctrl | 1);
    }

    // Reset the PCM-out bus-master engine.
    arch.outb(nabm + PO_CR, PO_CR_RESET);
    for _ in 0..1_000_000 {
        if arch.inb(nabm + PO_CR) & PO_CR_RESET == 0 {
            break;
        }
    }

    // Map the channel buffer into the stolen low-mem window VA so the kernel can
    // write PCM into it; the codec reads it (and the BDL) by physical address.
    let phys_page = arch.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        return false;
    }
    let pages = (BDL_BYTES + NUM_BUF * BUF_BYTES + 0xFFF) / 0x1000;
    arch.map_phys_range(DMA_WIN_VA >> 12, pages, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    let mut d = Ac97 {
        nam, nabm,
        dma_va: DMA_WIN_VA,
        dma_phys,
        cur_buf: 0,
        cur_off: 0,
        running: false,
        rate: 0,
    };
    d.build_bdl();
    arch.outl(nabm + PO_BDBAR, dma_phys); // BDL base
    arch.outb(nabm + PO_LVI, 0);

    *AC97.lock() = Some(d);
    true
}

impl Ac97 {
    /// Physical address of PCM ring buffer `i`.
    fn buf_phys(&self, i: usize) -> u32 {
        self.dma_phys + (BDL_BYTES + i * BUF_BYTES) as u32
    }
    /// Kernel VA of PCM ring buffer `i`.
    fn buf_va(&self, i: usize) -> usize {
        self.dma_va + BDL_BYTES + i * BUF_BYTES
    }

    /// Fill the BDL: entry i → buffer i, length in 16-bit samples, control 0
    /// (we poll CIV; no interrupt-on-completion). NUM_BUF == 32 so every entry
    /// maps a distinct buffer — no mirrored entries to replay.
    fn build_bdl(&mut self) {
        for i in 0..NUM_BUF {
            let entry = self.dma_va + i * 8;
            let samples = (BUF_BYTES / 2) as u16; // 16-bit samples per buffer
            unsafe {
                core::ptr::write_volatile(entry as *mut u32, self.buf_phys(i));
                core::ptr::write_volatile((entry + 4) as *mut u16, samples);
                core::ptr::write_volatile((entry + 6) as *mut u16, 0);
            }
        }
    }

    fn set_rate(&mut self, arch: &mut crate::TheArch, rate: u32) {
        if rate != self.rate && rate != 0 {
            arch.outw(self.nam + NAM_PCM_DAC_RATE, rate as u16);
            self.rate = rate;
        }
    }

    /// Decode `bytes` (`fmt`) into canonical i16 stereo and stream into the ring.
    fn submit(&mut self, arch: &mut crate::TheArch, rate: u32, fmt: Format, bytes: &[u8]) {
        self.set_rate(arch, rate);
        let fb = fmt.frame_bytes();
        if fb == 0 {
            return;
        }
        for i in 0..bytes.len() / fb {
            // At each buffer boundary, cap how far we run ahead of the codec.
            // Beyond MAX_AHEAD buffers we drop the rest (bounds latency; rare
            // once producer/codec are rate-matched — only drift reaches here).
            if self.cur_off == 0 && self.running {
                let civ = arch.inb(self.nabm + PO_CIV) as usize;
                let ahead = (self.cur_buf + NUM_BUF - civ) % NUM_BUF;
                if ahead >= MAX_AHEAD {
                    break;
                }
            }
            let (l, r) = fmt.frame(bytes, i);
            let p = self.buf_va(self.cur_buf) + self.cur_off;
            unsafe {
                core::ptr::write_volatile(p as *mut u16, l as u16);
                core::ptr::write_volatile((p + 2) as *mut u16, r as u16);
            }
            self.cur_off += 4;
            if self.cur_off >= BUF_BYTES {
                // Buffer complete: make it the last valid index. Start the bus
                // master once a small cushion is primed, then advance.
                arch.outb(self.nabm + PO_LVI, self.cur_buf as u8);
                if !self.running && self.cur_buf + 1 >= PRIME_BUFS {
                    let cr = arch.inb(self.nabm + PO_CR);
                    arch.outb(self.nabm + PO_CR, cr | PO_CR_RUN);
                    self.running = true;
                }
                self.cur_buf = (self.cur_buf + 1) % NUM_BUF;
                self.cur_off = 0;
            }
        }
    }
}

/// Stream a block of source PCM to the AC'97 codec (called by `sound::play` when
/// a codec was discovered).
pub fn play(arch: &mut crate::TheArch, rate: u32, fmt: Format, bytes: &[u8]) {
    let mut g = AC97.lock();
    if let Some(dev) = g.as_mut() {
        dev.submit(arch, rate, fmt, bytes);
    }
}

