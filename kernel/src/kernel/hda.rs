//! Intel High Definition Audio (HDA) output — a kernel device driver targeting
//! QEMU's `intel-hda` controller + `hda-duplex`/`hda-output` codec.
//!
//! The twin of [`ac97`](super::ac97): when the emulated SB (`dos/machine/vsb.rs`)
//! produces canonical PCM and the boot probe found an HDA controller (PCI class
//! 04:03), `sound::play` dispatches here. It differs from AC'97 in two ways:
//!
//!  * **MMIO, not port I/O.** HDA's registers live in a 64-bit *memory* BAR
//!    (BAR0), so we `map_phys_range` it present + cache-disabled (the NVMe-BAR
//!    pattern) and drive it with volatile reads/writes — the kernel never faults
//!    on it.
//!  * **A codec verb layer.** Unlike AC'97's flat mixer registers, the codec is
//!    programmed by sending *verbs* over the **CORB/RIRB** DMA rings, then a
//!    stream descriptor + BDL feed PCM exactly like AC'97's bus master.
//!
//! Everything else mirrors `ac97`: a 32-entry ring of PCM buffers in a borrowed
//! contiguous DMA buffer, primed then run, with the producer's run-ahead capped
//! by polling the hardware play position (`SDLPIB` here, `CIV` there) — no
//! interrupts.
//!
//! ## Topology
//!
//! Real laptops often expose several HDA functions: GPU HDMI/DP audio first,
//! then the internal analog codec later on a high PCI bus. We rank PCI HDA
//! candidates before bring-up, then enumerate the selected codec's widget graph
//! and choose a real output route. Pins whose default config says "not
//! connected" are ignored; internal speakers beat headphones, headphones beat
//! line-out, and digital-only paths are de-prioritized. This keeps QEMU's tiny
//! graph working while steering an AMD/Realtek laptop toward its analog speaker
//! codec instead of an HDMI function.
//!
//! ## DMA buffer placement (TEMPORARY — same stopgap as ac97)
//!
//! We borrow a `dma_channel_buf` (physically contiguous) and map it into kernel
//! space over the dead upper-memory slice of the low-mem identity window
//! (`LOW_MEM_BASE + 0xC0000..`). See `ac97`'s header and memory
//! `project_ac97_lowmem_dma_window_todo`; the proper fix is a real kernel
//! DMA-window pool. HDA and AC'97 are mutually exclusive (one `Audio` verdict),
//! so reusing the same window + DMA channel is safe.

use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::kernel::sound::Format;

const PTE_CACHE_DISABLE: u64 = 1 << 4;

// ── Stolen kernel VAs (dead UMA slice of the low-mem identity window) ─────────
/// HDA register BAR window (controller regs + stream descriptors, ≤ 16 KB).
const BAR_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_0000;
const BAR_PAGES: usize = 4;
/// DMA buffer window: CORB + RIRB + BDL + the PCM ring.
const DMA_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_8000;
/// Borrow the 16-bit ISA DMA channel's permanent contiguous buffer (128 KB / 32
/// pages). Free on an HDA host — the SB is emulated, not passed through, so the
/// real ISA channels are idle.
const DMA_CHANNEL: usize = 5;

// ── Controller registers (offsets into BAR0) ─────────────────────────────────
const GCAP: usize = 0x00; // w16: bits 8..11 ISS, 12..15 OSS
const GCTL: usize = 0x08; // d32: bit0 CRST (1 = run)
const STATESTS: usize = 0x0E; // w16: one bit per SDI link with a codec
const CORBLBASE: usize = 0x40; // d32
const CORBUBASE: usize = 0x44; // d32
const CORBWP: usize = 0x48; // w16: write pointer (entry index)
const CORBRP: usize = 0x4A; // w16: read pointer; bit15 = reset
const CORBCTL: usize = 0x4C; // b8: bit1 CORBRUN
const CORBSIZE: usize = 0x4E; // b8: bits1:0 size (0b10 = 256 entries)
const RIRBLBASE: usize = 0x50; // d32
const RIRBUBASE: usize = 0x54; // d32
const RIRBWP: usize = 0x58; // w16: write pointer; bit15 = reset
const RINTCNT: usize = 0x5A; // w16: response interrupt count
const RIRBCTL: usize = 0x5C; // b8: bit1 RIRBDMAEN
const RIRBSTS: usize = 0x5D; // b8: bit0 RINTFL (response interrupt), bit2 overrun
const RIRBSIZE: usize = 0x5E; // b8: bits1:0 size (0b10 = 256 entries)
const DPLBASE: usize = 0x70; // d32: DMA position buffer base; bit0 = enable
const DPUBASE: usize = 0x74; // d32: DMA position buffer base high

// Output stream descriptor register offsets (added to the descriptor base, which
// is 0x80 + ISS*0x20 — the first output stream sits past the input streams).
const SD_BASE: usize = 0x80;
const SD_STRIDE: usize = 0x20;
const SDCTL: usize = 0x00; // 3 bytes; bit0 SRST, bit1 RUN, bits20..23 stream tag
const SDLPIB: usize = 0x04; // d32: link position in buffer (bytes, RO)
const SDCBL: usize = 0x08; // d32: cyclic buffer length (bytes)
const SDLVI: usize = 0x0C; // w16: last valid BDL index
const SDFMT: usize = 0x12; // w16: stream format (same encoding as the codec)
const SDBDPL: usize = 0x18; // d32: BDL base low
const SDBDPU: usize = 0x1C; // d32: BDL base high

// ── CORB/RIRB/BDL/PCM layout within the borrowed DMA buffer ──────────────────
const CORB_ENTRIES: usize = 256; // 4 bytes each → 1 KB
const RIRB_ENTRIES: usize = 256; // 8 bytes each → 2 KB
const CORB_OFF: usize = 0x0000;
const RIRB_OFF: usize = 0x0400;
const BDL_OFF: usize = 0x0C00; // 128-byte aligned; NUM_BUF*16 = 512 bytes
const POS_OFF: usize = 0x0E00; // 128-byte aligned; DMA position buffer (8 strm*8)
const BUF_OFF: usize = 0x1000; // PCM ring starts on the next page
const DMA_PAGES: usize = (BUF_OFF + NUM_BUF * BUF_BYTES).div_ceil(0x1000);

// ── PCM ring geometry (mirror ac97) ──────────────────────────────────────────
const NUM_BUF: usize = 32;
const BUF_BYTES: usize = 0x800; // 2 KB = 512 stereo frames ≈ 23 ms @ 22 kHz
const PRIME_BUFS: usize = 3;
const MAX_AHEAD: usize = 6;
/// Stream tag bound between the descriptor and the DAC converter (1..15).
const STREAM_TAG: u32 = 1;
/// Boot-time bring-up diagnostics to debugcon (flip on to debug the codec).
const DEBUG: bool = false;

const MAX_HDA_CONTROLLERS: usize = 8;
const MAX_WIDGETS: usize = 64;
const MAX_CONNS: usize = 8;
const MAX_PATH: usize = 8;

const PARAM_VENDOR_ID: u32 = 0x00;
const PARAM_SUBNODE_COUNT: u32 = 0x04;
const PARAM_FUNCTION_GROUP_TYPE: u32 = 0x05;
const PARAM_AUDIO_WIDGET_CAPS: u32 = 0x09;
const PARAM_PIN_CAPS: u32 = 0x0C;
const PARAM_CONN_LIST_LEN: u32 = 0x0E;
const PARAM_OUT_AMP_CAPS: u32 = 0x12;

const VERB_GET_PARAMETER: u32 = 0xF00;
const VERB_GET_CONN_SELECT: u32 = 0xF01;
const VERB_GET_CONN_LIST_ENTRY: u32 = 0xF02;
const VERB_GET_PROC_COEF: u32 = 0xC00;
const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C;
const VERB_SET_PROC_COEF: u32 = 0x400;
const VERB_SET_COEF_INDEX: u32 = 0x500;
const VERB_SET_CONN_SELECT: u32 = 0x701;
const VERB_SET_POWER_STATE: u32 = 0x705;
const VERB_SET_CONV_STREAM_CHAN: u32 = 0x706;
const VERB_SET_PIN_WIDGET_CONTROL: u32 = 0x707;
const VERB_SET_EAPD_BTL: u32 = 0x70C;

const WTYPE_AUDIO_OUTPUT: u32 = 0x0;
const WTYPE_AUDIO_MIXER: u32 = 0x2;
const WTYPE_AUDIO_SELECTOR: u32 = 0x3;
const WTYPE_PIN_COMPLEX: u32 = 0x4;

const AW_CAP_DIGITAL: u32 = 1 << 9;
const PIN_CAP_OUT: u32 = 1 << 4;
const PIN_CTL_OUT: u32 = 0x40;
const PIN_CTL_HP: u32 = 0x80;

const DEFAULT_PORT_NONE: u32 = 0x1;
const DEFAULT_PORT_FIXED: u32 = 0x2;
const DEFAULT_DEVICE_LINE_OUT: u32 = 0x0;
const DEFAULT_DEVICE_SPEAKER: u32 = 0x1;
const DEFAULT_DEVICE_HP_OUT: u32 = 0x2;
const REALTEK_ALC298: u32 = 0x10ec_0298;
const REALTEK_VENDOR_NID: u32 = 0x20;
const REALTEK_EAPD_COEF_INDEX: u32 = 0x10;
const REALTEK_EAPD_COEF_MASK: u32 = 1 << 9;

static HDA: Mutex<Option<Hda>> = Mutex::new(None);
/// True once the controller BAR is mapped at `BAR_WIN_VA` (panic-path guard).
static BAR_MAPPED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline]
fn spin(n: usize) {
    for _ in 0..n {
        core::hint::spin_loop();
    }
}

// ── MMIO helpers (volatile, the BAR is mapped present + PCD) ──────────────────
#[inline]
fn r8(off: usize) -> u8 {
    unsafe { read_volatile((BAR_WIN_VA + off) as *const u8) }
}
#[inline]
fn r16(off: usize) -> u16 {
    unsafe { read_volatile((BAR_WIN_VA + off) as *const u16) }
}
#[inline]
fn r32(off: usize) -> u32 {
    unsafe { read_volatile((BAR_WIN_VA + off) as *const u32) }
}
#[inline]
fn w8(off: usize, v: u8) {
    unsafe { write_volatile((BAR_WIN_VA + off) as *mut u8, v) }
}
#[inline]
fn w16(off: usize, v: u16) {
    unsafe { write_volatile((BAR_WIN_VA + off) as *mut u16, v) }
}
#[inline]
fn w32(off: usize, v: u32) {
    unsafe { write_volatile((BAR_WIN_VA + off) as *mut u32, v) }
}

fn stop_controller_dma() {
    let gcap = r16(GCAP);
    let stream_count = (((gcap >> 8) & 0xF) + ((gcap >> 12) & 0xF)) as usize;
    for i in 0..stream_count {
        let sd = SD_BASE + i * SD_STRIDE;
        w8(sd + SDCTL, r8(sd + SDCTL) & !0x02);
    }
    w8(CORBCTL, 0);
    w8(RIRBCTL, 0);
    w32(DPLBASE, 0);
    w32(DPUBASE, 0);
}

struct Hda {
    dma_va: usize,
    dma_phys: u32,
    /// First output stream descriptor base (0x80 + ISS*0x20).
    sd: usize,
    /// Our private RIRB read cursor (the controller advances RIRBWP).
    rirb_rp: usize,
    /// True while CORB/RIRB DMA engines are running for codec verbs.
    rings_running: bool,
    /// True while the link is parked: controller held in reset (CRST low) so a
    /// hard power-off cannot catch the codec in an active state. Playback
    /// unparks (full controller + codec re-init) on demand.
    parked: bool,
    /// Latched when a codec verb times out; bring-up abandons this controller.
    verb_failed: bool,
    /// Codec address of the first present codec.
    cad: u32,
    /// Codec vendor/device id from node 0, e.g. 0x10ec0298 for Realtek ALC298.
    codec_vendor: u32,
    /// Audio Function Group node found during enumeration.
    afg: u32,
    /// Output DAC + output pin node IDs selected from the codec graph.
    dac: u32,
    pin: u32,
    pin_def: u32,
    path: OutputPath,
    cur_buf: usize,
    cur_off: usize,
    running: bool,
    /// Hardware stream rate currently programmed into SDFMT/the converter.
    rate: u32,
    /// Producer/source rate currently being adapted into the hardware stream.
    src_rate: u32,
    /// Output-rate accumulator for zero-order-hold resampling.
    resample_acc: u64,
    /// Sparse runtime diagnostics for real hardware bring-up.
    logged_submit: bool,
    logged_run: bool,
    diag_buffers: u8,
    diag_stalls: u8,
}

#[derive(Clone, Copy)]
struct HdaPciDevice {
    bus: u8,
    dev: u8,
    func: u8,
    score: i32,
}

impl HdaPciDevice {
    const EMPTY: Self = Self {
        bus: 0,
        dev: 0,
        func: 0,
        score: i32::MIN,
    };
}

#[derive(Clone, Copy)]
struct Widget {
    nid: u32,
    typ: u32,
    caps: u32,
    pin_caps: u32,
    def_cfg: u32,
    conn_sel: u8,
    conn_len: usize,
    conns: [u32; MAX_CONNS],
}

impl Widget {
    const EMPTY: Self = Self {
        nid: 0,
        typ: 0,
        caps: 0,
        pin_caps: 0,
        def_cfg: 0,
        conn_sel: 0,
        conn_len: 0,
        conns: [0; MAX_CONNS],
    };
}

#[derive(Clone, Copy)]
struct OutputPath {
    nodes: [u32; MAX_PATH],   // pin -> ... -> DAC
    conn_idx: [u8; MAX_PATH], // connection index from nodes[i] to nodes[i + 1]
    len: usize,
    score: i32,
}

impl OutputPath {
    const EMPTY: Self = Self {
        nodes: [0; MAX_PATH],
        conn_idx: [0; MAX_PATH],
        len: 0,
        score: i32::MIN,
    };
}

fn path_node(path: &OutputPath, i: usize) -> u32 {
    if i < path.len {
        path.nodes[i]
    } else {
        0
    }
}

fn path_conn(path: &OutputPath, i: usize) -> u8 {
    if i + 1 < path.len {
        path.conn_idx[i]
    } else {
        0
    }
}

/// Find the preferred HDA controller (class 0x04, subclass 0x03) anywhere on
/// PCI. We do not just return the first class match: real laptops often expose
/// GPU HDMI audio before the internal analog codec.
pub fn scan<A: crate::Arch>(machine: &mut A) -> Option<(u8, u8, u8)> {
    let mut devices = [HdaPciDevice::EMPTY; MAX_HDA_CONTROLLERS];
    let n = collect_hda_controllers(machine, &mut devices);
    if n == 0 {
        None
    } else {
        sort_hda_controllers(&mut devices, n);
        Some((devices[0].bus, devices[0].dev, devices[0].func))
    }
}

pub fn init<A: crate::Arch>(machine: &mut A) {
    if crate::kernel::platform::get().audio != crate::kernel::platform::Audio::EmulatedHda {
        return;
    }
    let mut devices = [HdaPciDevice::EMPTY; MAX_HDA_CONTROLLERS];
    let n = collect_hda_controllers(machine, &mut devices);
    sort_hda_controllers(&mut devices, n);
    for d in devices.iter().take(n) {
        if bring_up(machine, d.bus, d.dev, d.func) {
            return;
        }
    }
}

fn collect_hda_controllers<A: crate::Arch>(
    machine: &mut A,
    out: &mut [HdaPciDevice; MAX_HDA_CONTROLLERS],
) -> usize {
    let mut n = 0;
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let id = crate::kernel::pci::read32(machine, bus, dev, func, 0x00);
                if id & 0xFFFF == 0xFFFF {
                    if func == 0 {
                        break;
                    }
                    continue;
                }
                let classes = crate::kernel::pci::read32(machine, bus, dev, func, 0x08);
                if (classes >> 24) as u8 == 0x04 && (classes >> 16) as u8 == 0x03 && n < out.len() {
                    let vendor = (id & 0xFFFF) as u16;
                    let device = (id >> 16) as u16;
                    out[n] = HdaPciDevice {
                        bus,
                        dev,
                        func,
                        score: hda_pci_score(vendor, device),
                    };
                    n += 1;
                }
                if func == 0
                    && crate::kernel::pci::read32(machine, bus, dev, 0, 0x0C) & 0x0080_0000 == 0
                {
                    break;
                }
            }
        }
    }
    n
}

fn hda_pci_score(vendor: u16, device: u16) -> i32 {
    let mut score = 100;
    match vendor {
        0x1022 => score += 250, // AMD platform HDA, e.g. Family 17h/19h analog codec.
        0x8086 => score += 150, // Intel PCH/QEMU HDA.
        0x10de => score -= 200, // NVIDIA display audio is usually HDMI/DP only.
        0x1002 => score -= 150, // AMD/ATI GPU display audio is usually HDMI/DP only.
        _ => {}
    }
    if vendor == 0x1022 && device == 0x15e3 {
        score += 1000; // This laptop's AMD HDA controller with Realtek ALC298.
    }
    score
}

fn sort_hda_controllers(devices: &mut [HdaPciDevice; MAX_HDA_CONTROLLERS], n: usize) {
    for i in 0..n {
        let mut best = i;
        for j in i + 1..n {
            if devices[j].score > devices[best].score {
                best = j;
            }
        }
        if best != i {
            devices.swap(i, best);
        }
    }
}

/// Bounce a PCI function through D3hot → D0 via its power-management
/// capability. Unlike a CRST link reset, this cycles the codec's power
/// domain, which is what recovers a codec wedged by a hard reboot during
/// active streaming. Returns false if the function has no PM capability.
fn pci_pm_power_cycle<A: crate::Arch>(machine: &mut A, bus: u8, dev: u8, func: u8) -> bool {
    // Status register bit 4 (dword 0x04, bit 20): capability list present.
    if crate::kernel::pci::read32(machine, bus, dev, func, 0x04) & (1 << 20) == 0 {
        return false;
    }
    let mut ptr = (crate::kernel::pci::read32(machine, bus, dev, func, 0x34) & 0xFC) as u8;
    let mut pm = 0u8;
    for _ in 0..16 {
        if ptr == 0 {
            break;
        }
        let hdr = crate::kernel::pci::read32(machine, bus, dev, func, ptr);
        if hdr & 0xFF == 0x01 {
            pm = ptr;
            break;
        }
        ptr = ((hdr >> 8) & 0xFC) as u8;
    }
    if pm == 0 {
        return false;
    }
    // The function may internally reset on the D3hot → D0 edge (that is the
    // point), losing config context: save and restore what bring-up relies on.
    let cmd = crate::kernel::pci::read32(machine, bus, dev, func, 0x04);
    let bar0 = crate::kernel::pci::read32(machine, bus, dev, func, 0x10);
    let bar1 = crate::kernel::pci::read32(machine, bus, dev, func, 0x14);
    let pmcsr = crate::kernel::pci::read32(machine, bus, dev, func, pm + 4);
    crate::kernel::pci::write32(machine, bus, dev, func, pm + 4, (pmcsr & !0x3) | 0x3);
    spin(20_000_000); // ≥ 10 ms settle in each state (PCI PM spec)
    crate::kernel::pci::write32(machine, bus, dev, func, pm + 4, pmcsr & !0x3);
    spin(20_000_000);
    crate::kernel::pci::write32(machine, bus, dev, func, 0x10, bar0);
    crate::kernel::pci::write32(machine, bus, dev, func, 0x14, bar1);
    crate::kernel::pci::write32(machine, bus, dev, func, 0x04, cmd);
    true
}

/// Bring up the controller + codec output path at `bus:dev.func`. Returns true
/// on success.
fn bring_up<A: crate::Arch>(machine: &mut A, bus: u8, dev: u8, func: u8) -> bool {
    // Enable memory space + bus master in the PCI command register (bits 1, 2).
    let cmd = crate::kernel::pci::read32(machine, bus, dev, func, 0x04);
    crate::kernel::pci::write32(machine, bus, dev, func, 0x04, (cmd & 0xFFFF) | 0x06);

    // BAR0 is a memory BAR. Read the high dword only if it is actually 64-bit
    // (type bits [2:1] == 0b10); a 32-bit BAR would make 0x14 a different reg.
    let bar0 = crate::kernel::pci::read32(machine, bus, dev, func, 0x10);
    let hi = if bar0 & 0x6 == 0x4 {
        crate::kernel::pci::read32(machine, bus, dev, func, 0x14) as u64
    } else {
        0
    };
    let bar_phys = (hi << 32) | (bar0 & 0xFFFF_FFF0) as u64;
    if bar_phys == 0 {
        crate::println!("hda: {:02x}:{:02x}.{} skipped: no BAR", bus, dev, func);
        return false;
    }
    machine.map_phys_range(
        BAR_WIN_VA >> 12,
        BAR_PAGES,
        bar_phys >> 12,
        PTE_CACHE_DISABLE,
    );
    BAR_MAPPED.store(true, core::sync::atomic::Ordering::Relaxed);
    stop_controller_dma();

    // Output stream descriptor base sits past the ISS input streams.
    let gcap = r16(GCAP);
    let iss = ((gcap >> 8) & 0xF) as usize;
    let sd = SD_BASE + iss * SD_STRIDE;

    // Map the borrowed contiguous DMA buffer.
    let phys_page = machine.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        crate::println!("hda: {:02x}:{:02x}.{} failed: no DMA buffer", bus, dev, func);
        return false;
    }
    machine.map_phys_range(DMA_WIN_VA >> 12, DMA_PAGES, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    let mut d = Hda {
        dma_va: DMA_WIN_VA,
        dma_phys,
        sd,
        rirb_rp: 0,
        rings_running: false,
        parked: false,
        verb_failed: false,
        cad: 0,
        codec_vendor: 0,
        afg: 0,
        dac: 0,
        pin: 0,
        pin_def: 0,
        path: OutputPath::EMPTY,
        cur_buf: 0,
        cur_off: 0,
        running: false,
        rate: 0,
        src_rate: 0,
        resample_acc: 0,
        logged_submit: false,
        logged_run: false,
        diag_buffers: 0,
        diag_stalls: 0,
    };

    // Link reset + codec detection, with escalating recovery. A hard reboot
    // during active streaming can leave the codec wedged: it stays deaf to
    // plain CRST resets across warm reboots until its power well cycles
    // (observed on the ALC298 laptop; Linux then reports "no codecs found"
    // until a cold boot). Attempt 0 is the normal spec sequence; attempt 1
    // retries with a longer reset hold; attempt 2 first bounces the function
    // through PCI D3hot → D0, which resets the codec power domain without a
    // cold boot.
    let mut detected = false;
    for attempt in 0..3u32 {
        if attempt == 2 {
            if !pci_pm_power_cycle(machine, bus, dev, func) {
                break; // no PM capability; another link reset won't differ
            }
            stop_controller_dma();
        }
        // Clear stale STATESTS (RW1C) BEFORE asserting reset: real codecs
        // report in after CRST releases, but QEMU latches the bits at the
        // CRST=0 write itself, so clearing while in reset would wipe them.
        w16(STATESTS, 0x7FFF);
        // CRST low; hold well past the 100 µs minimum before releasing.
        w32(GCTL, 0);
        for _ in 0..1_000_000 {
            if r32(GCTL) & 1 == 0 {
                break;
            }
        }
        spin(1_000_000 << attempt);
        w32(GCTL, 1);
        let mut up = false;
        for _ in 0..1_000_000 {
            if r32(GCTL) & 1 != 0 {
                up = true;
                break;
            }
        }
        if !up {
            crate::println!(
                "hda: {:02x}:{:02x}.{} attempt {}: CRST stuck low",
                bus,
                dev,
                func,
                attempt
            );
            continue;
        }
        // Codecs need ≥ 521 µs after CRST to report in STATESTS.
        spin(1_000_000 << attempt);
        let codecs = r16(STATESTS);
        if codecs == 0 {
            crate::println!(
                "hda: {:02x}:{:02x}.{} attempt {}: statests=0, no codec responded",
                bus,
                dev,
                func,
                attempt
            );
            continue;
        }
        // A codec that reports in STATESTS can still be verb-dead; probe it.
        d.cad = codecs.trailing_zeros();
        d.verb_failed = false;
        d.setup_corb_rirb();
        d.codec_vendor = d.verb(0, (VERB_GET_PARAMETER << 8) | PARAM_VENDOR_ID);
        if d.verb_failed || d.codec_vendor == 0 || d.codec_vendor == 0xFFFF_FFFF {
            crate::println!(
                "hda: {:02x}:{:02x}.{} attempt {}: codec verb-dead (cad={} statests={:#x} vendor={:#x})",
                bus,
                dev,
                func,
                attempt,
                d.cad,
                codecs,
                d.codec_vendor
            );
            d.shutdown_controller();
            continue;
        }
        if attempt > 0 {
            crate::println!(
                "hda: {:02x}:{:02x}.{} codec recovered on attempt {}",
                bus,
                dev,
                func,
                attempt
            );
        }
        detected = true;
        break;
    }
    if !detected {
        return false;
    }
    if DEBUG {
        crate::println!(
            "hda: rings up corbctl={:#x} rirbctl={:#x} corbsz={:#x} rirbsz={:#x} corbwp={} corbrp={} rirbwp={}",
            r8(CORBCTL), r8(RIRBCTL), r8(CORBSIZE), r8(RIRBSIZE),
            r16(CORBWP), r16(CORBRP), r16(RIRBWP)
        );
        // Probe consecutive verbs: does the ring keep processing past the first?
        for p in [0x00u32, 0x02, 0x04, 0x09] {
            let r = d.verb(0, (0xF00 << 8) | p);
            if d.verb_failed {
                d.shutdown_controller();
                return false;
            }
            crate::println!(
                "hda: probe param={:#04x} -> {:#x} corbwp={} corbrp={} rirbwp={} rirbsts={:#x}",
                p,
                r,
                r16(CORBWP),
                r16(CORBRP),
                r16(RIRBWP),
                r8(RIRBSTS)
            );
        }
    }
    if !d.select_output_path() || d.verb_failed {
        crate::println!(
            "hda: {:02x}:{:02x}.{} failed: no output path (codec={:#x}, verb_failed={})",
            bus,
            dev,
            func,
            d.codec_vendor,
            d.verb_failed
        );
        d.shutdown_controller();
        return false;
    }

    d.build_bdl();
    d.program_stream();

    d.configure_path();
    if d.verb_failed {
        crate::println!(
            "hda: {:02x}:{:02x}.{} failed: configure-path verb timeout (codec={:#x})",
            bus,
            dev,
            func,
            d.codec_vendor
        );
        d.shutdown_controller();
        return false;
    }
    d.dump_output_state();

    // Park the link until something plays, and exercise one park → unpark
    // round trip now so a broken re-init path is caught at boot, loudly,
    // instead of as silence at the first playback.
    d.park();
    if !d.unpark() {
        crate::println!(
            "hda: {:02x}:{:02x}.{} failed: unpark self-test (codec={:#x})",
            bus,
            dev,
            func,
            d.codec_vendor
        );
        d.shutdown_controller();
        return false;
    }
    d.park();

    if DEBUG {
        crate::println!(
            "hda: bar={:#x} gcap={:#06x} iss={} oss={} statests={:#x} cad={} sd={:#x}",
            bar_phys,
            gcap,
            iss,
            (gcap >> 12) & 0xF,
            r16(STATESTS),
            d.cad,
            sd
        );
        crate::println!("hda: dac=nid{} pin=nid{}", d.dac, d.pin);
    }

    crate::println!(
        "hda: selected {:02x}:{:02x}.{} codec={:#x} pin=nid{} dac=nid{}",
        bus,
        dev,
        func,
        d.codec_vendor,
        d.pin,
        d.dac,
    );
    crate::println!(
        "hda: path len={} score={} nodes={:02x}>{:02x}>{:02x}>{:02x}>{:02x}>{:02x} conn={},{},{},{},{}",
        d.path.len,
        d.path.score,
        path_node(&d.path, 0),
        path_node(&d.path, 1),
        path_node(&d.path, 2),
        path_node(&d.path, 3),
        path_node(&d.path, 4),
        path_node(&d.path, 5),
        path_conn(&d.path, 0),
        path_conn(&d.path, 1),
        path_conn(&d.path, 2),
        path_conn(&d.path, 3),
        path_conn(&d.path, 4),
    );
    *HDA.lock() = Some(d);
    true
}

impl Hda {
    fn buf_phys(&self, i: usize) -> u32 {
        self.dma_phys + (BUF_OFF + i * BUF_BYTES) as u32
    }
    fn buf_va(&self, i: usize) -> usize {
        self.dma_va + BUF_OFF + i * BUF_BYTES
    }

    /// Fill the BDL: entry i → PCM buffer i. Each HDA BDL entry is 16 bytes
    /// { addr:u64, len:u32, flags:u32 }; IOC stays off (we poll `SDLPIB`).
    fn build_bdl(&mut self) {
        for i in 0..NUM_BUF {
            let entry = self.dma_va + BDL_OFF + i * 16;
            unsafe {
                write_volatile(entry as *mut u32, self.buf_phys(i)); // addr low
                write_volatile((entry + 4) as *mut u32, 0); // addr high
                write_volatile((entry + 8) as *mut u32, BUF_BYTES as u32); // length
                write_volatile((entry + 12) as *mut u32, 0); // flags (IOC off)
            }
        }
    }

    /// Initialize and start the CORB (command) and RIRB (response) DMA rings.
    fn setup_corb_rirb(&mut self) {
        // Stop both engines before reprogramming their bases.
        w8(CORBCTL, 0);
        w8(RIRBCTL, 0);

        let corb_phys = self.dma_phys + CORB_OFF as u32;
        w32(CORBLBASE, corb_phys);
        w32(CORBUBASE, 0);
        // 256-entry CORB.
        w8(CORBSIZE, 0x02);
        // Reset the read pointer: set bit15, wait for it to read back, then clear.
        w16(CORBRP, 0x8000);
        for _ in 0..100_000 {
            if r16(CORBRP) & 0x8000 != 0 {
                break;
            }
        }
        w16(CORBRP, 0);
        w16(CORBWP, 0);

        let rirb_phys = self.dma_phys + RIRB_OFF as u32;
        w32(RIRBLBASE, rirb_phys);
        w32(RIRBUBASE, 0);
        w8(RIRBSIZE, 0x02); // 256 entries
        w16(RIRBWP, 0x8000); // reset the write pointer
        w16(RINTCNT, 0xFF); // high count; we also clear RIRBSTS per verb (see verb())
        self.rirb_rp = 0;

        w8(CORBCTL, 0x02); // CORBRUN
        w8(RIRBCTL, 0x02); // RIRBDMAEN
        self.rings_running = true;
    }

    fn stop_corb_rirb(&mut self) {
        w8(CORBCTL, 0);
        w8(RIRBCTL, 0);
        self.rings_running = false;
    }

    fn stop_playback(&mut self) {
        if self.running {
            self.stop();
            self.running = false;
        }
        self.cur_buf = 0;
        self.cur_off = 0;
        self.resample_acc = 0;
        // Clear the PCM ring: the producer restarts at buffer 0, so if the
        // hardware ever runs past the freshly primed buffers (session start,
        // underrun) it must find silence, not a replay of the previous
        // session's audio.
        unsafe {
            core::ptr::write_bytes(
                (self.dma_va + BUF_OFF) as *mut u8,
                0,
                NUM_BUF * BUF_BYTES,
            );
        }
    }

    fn shutdown_controller(&mut self) {
        self.stop_playback();
        self.stop_corb_rirb();
        w32(DPLBASE, 0);
        w32(DPUBASE, 0);
    }

    /// Program the output stream descriptor: SRST pulse, position buffer, BDL
    /// base, cyclic length, stream tag. Everything here is controller register
    /// state, so it must rerun after every CRST (bring-up and unpark).
    fn program_stream(&mut self) {
        let sd = self.sd;
        // Reset the stream into a known state: assert SDCTL.SRST, wait for it
        // to read back, deassert, wait for it to clear. A stream that was
        // never reset may refuse to advance when RUN is set.
        w8(sd + SDCTL, 0x01);
        for _ in 0..100_000 {
            if r8(sd + SDCTL) & 0x01 != 0 {
                break;
            }
        }
        w8(sd + SDCTL, 0x00);
        for _ in 0..100_000 {
            if r8(sd + SDCTL) & 0x01 == 0 {
                break;
            }
        }

        // DMA position buffer (some QEMU builds advance this, not SDLPIB).
        w32(DPLBASE, (self.dma_phys + POS_OFF as u32) | 1);
        w32(DPUBASE, 0);

        // Point the stream descriptor at the BDL and cap its cyclic length.
        w32(sd + SDBDPL, self.dma_phys + BDL_OFF as u32);
        w32(sd + SDBDPU, 0);
        w32(sd + SDCBL, (NUM_BUF * BUF_BYTES) as u32);
        w16(sd + SDLVI, (NUM_BUF - 1) as u16);
        // Stream tag in the descriptor control byte (bits 20..23 of SDCTL).
        w8(sd + SDCTL + 2, (STREAM_TAG << 4) as u8);
    }

    /// Park the link: stop all DMA and hold the controller in reset (CRST
    /// low). A hard power-off while parked leaves the codec in reset — the
    /// safest state this driver can hand to the next boot (this laptop's
    /// ALC298 stays wedged across warm reboots if reset mid-activity).
    fn park(&mut self) {
        self.stop_playback();
        self.stop_corb_rirb();
        w32(DPLBASE, 0);
        w32(DPUBASE, 0);
        w32(GCTL, 0);
        self.parked = true;
        self.rate = 0; // CRST wiped SDFMT/converter state: force set_format
        self.src_rate = 0;
    }

    /// Release a parked link and rebuild everything CRST wiped: controller
    /// stream state and the codec output path. Returns false if the codec
    /// did not come back.
    fn unpark(&mut self) -> bool {
        w16(STATESTS, 0x7FFF);
        for _ in 0..1_000_000 {
            if r32(GCTL) & 1 == 0 {
                break;
            }
        }
        spin(1_000_000);
        w32(GCTL, 1);
        let mut up = false;
        for _ in 0..1_000_000 {
            if r32(GCTL) & 1 != 0 {
                up = true;
                break;
            }
        }
        if !up {
            return false;
        }
        // Codecs need ≥ 521 µs after CRST before they accept verbs.
        spin(1_000_000);
        self.verb_failed = false;
        self.setup_corb_rirb();
        self.program_stream();
        self.configure_path();
        self.stop_corb_rirb();
        if self.verb_failed {
            return false;
        }
        self.parked = false;
        true
    }

    /// Send one verb to `nid` and return the codec's 32-bit response. `verb` is
    /// the pre-packed verb+payload field (bits 19:0 of the command).
    fn verb(&mut self, nid: u32, verb: u32) -> u32 {
        if self.verb_failed {
            return 0;
        }
        if !self.rings_running {
            self.setup_corb_rirb();
        }
        let cmd = (self.cad << 28) | (nid << 20) | (verb & 0xF_FFFF);
        // Push at (CORBWP + 1) and advance the write pointer.
        let wp = (r16(CORBWP) as usize + 1) % CORB_ENTRIES;
        unsafe {
            write_volatile((self.dma_va + CORB_OFF + wp * 4) as *mut u32, cmd);
        }
        w16(CORBWP, wp as u16);

        // The response lands at our next RIRB slot; wait for RIRBWP to reach it.
        let want = (self.rirb_rp + 1) % RIRB_ENTRIES;
        let mut ready = false;
        for _ in 0..1_000_000 {
            if (r16(RIRBWP) as usize) % RIRB_ENTRIES == want {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ready {
            self.verb_failed = true;
            w8(RIRBSTS, 0x05);
            return 0;
        }
        self.rirb_rp = want;
        // RIRB entry = { response: u32, response_ex: u32 }.
        let resp = unsafe { read_volatile((self.dma_va + RIRB_OFF + want * 8) as *const u32) };
        // Clear RIRBSTS (RINTFL bit0 / OIS bit2, both RW1C). QEMU's CORB engine
        // stops processing once it has written RINTCNT responses since the count
        // was last reset; clearing RIRBSTS resets that counter, so the NEXT verb
        // actually runs. Without this, only the first verb after setup executes
        // (corbrp/rirbwp freeze at 1) and the whole codec is left unconfigured.
        w8(RIRBSTS, 0x05);
        resp
    }

    /// Walk the codec graph and choose a real analog-ish output route.
    fn select_output_path(&mut self) -> bool {
        let mut widgets = [Widget::EMPTY; MAX_WIDGETS];
        let count = self.enumerate_widgets(&mut widgets);
        let mut best = OutputPath::EMPTY;
        for i in 0..count {
            let w = widgets[i];
            if w.typ != WTYPE_PIN_COMPLEX {
                continue;
            }
            let pin_score = output_pin_score(&w);
            if pin_score <= 0 {
                continue;
            }
            let mut path = OutputPath::EMPTY;
            let mut visited = [0u32; MAX_PATH];
            dfs_output_path(
                &widgets,
                count,
                w.nid,
                pin_score,
                self.codec_vendor,
                &mut path,
                &mut visited,
                0,
                &mut best,
            );
        }
        if best.len == 0 {
            let Some(path) = fallback_output_path(&widgets, count) else {
                return false;
            };
            best = path;
        }
        self.path = best;
        self.pin = best.nodes[0];
        self.dac = best.nodes[best.len - 1];
        if let Some(pin) = find_widget(&widgets, count, self.pin) {
            self.pin_def = widgets[pin].def_cfg;
        }
        true
    }

    fn enumerate_widgets(&mut self, widgets: &mut [Widget; MAX_WIDGETS]) -> usize {
        // Root node 0 → the function groups it contains.
        let root = self.verb(0, (VERB_GET_PARAMETER << 8) | PARAM_SUBNODE_COUNT);
        let fg_start = (root >> 16) & 0xFF;
        let fg_count = root & 0xFF;
        let mut afg = 0u32;
        for n in fg_start..fg_start + fg_count {
            if self.verb(n, (VERB_GET_PARAMETER << 8) | PARAM_FUNCTION_GROUP_TYPE) & 0xFF == 0x01 {
                afg = n; // Audio Function Group
                break;
            }
        }
        if DEBUG {
            crate::println!(
                "hda: enum root={:#x} fg_start={} fg_count={} afg={}",
                root,
                fg_start,
                fg_count,
                afg
            );
        }
        if afg == 0 {
            return 0;
        }
        self.afg = afg;
        // The AFG's subnodes are the widgets.
        let sub = self.verb(afg, (VERB_GET_PARAMETER << 8) | PARAM_SUBNODE_COUNT);
        let w_start = (sub >> 16) & 0xFF;
        let w_count = sub & 0xFF;
        let mut count = 0;
        for nid in w_start..w_start + w_count {
            if count >= widgets.len() {
                break;
            }
            let caps = self.verb(nid, (VERB_GET_PARAMETER << 8) | PARAM_AUDIO_WIDGET_CAPS);
            let typ = (caps >> 20) & 0xF;
            let pin_caps = if typ == WTYPE_PIN_COMPLEX {
                self.verb(nid, (VERB_GET_PARAMETER << 8) | PARAM_PIN_CAPS)
            } else {
                0
            };
            let def_cfg = if typ == WTYPE_PIN_COMPLEX {
                self.verb(nid, VERB_GET_CONFIG_DEFAULT << 8)
            } else {
                0
            };
            let conn_sel = (self.verb(nid, VERB_GET_CONN_SELECT << 8) & 0xFF) as u8;
            let (conns, conn_len) = self.conn_list(nid);
            widgets[count] = Widget {
                nid,
                typ,
                caps,
                pin_caps,
                def_cfg,
                conn_sel,
                conn_len,
                conns,
            };
            count += 1;
            if DEBUG {
                crate::println!(
                    "hda: nid{} caps={:#x} type={}",
                    nid,
                    caps,
                    (caps >> 20) & 0xF
                );
            }
        }
        count
    }

    fn conn_list(&mut self, nid: u32) -> ([u32; MAX_CONNS], usize) {
        let param = self.verb(nid, (VERB_GET_PARAMETER << 8) | PARAM_CONN_LIST_LEN);
        let len = (param & 0x7F) as usize;
        let long = param & 0x80 != 0;
        let range_bit = if long { 0x8000 } else { 0x80 };
        let nid_mask = if long { 0x7FFF } else { 0x7F };
        let mut conns = [0u32; MAX_CONNS];
        let mut out_len = 0usize;
        let mut prev: Option<u32> = None;
        for i in 0..len {
            let group = if long { i / 2 } else { i / 4 };
            let resp = self.verb(nid, (VERB_GET_CONN_LIST_ENTRY << 8) | group as u32);
            if self.verb_failed {
                break;
            }
            let raw = if long {
                (resp >> ((i % 2) * 16)) & 0xFFFF
            } else {
                (resp >> ((i % 4) * 8)) & 0xFF
            };
            let entry = raw & nid_mask;
            if raw & range_bit != 0 {
                if let Some(start) = prev {
                    let mut n = start.saturating_add(1);
                    while n <= entry && out_len < MAX_CONNS {
                        conns[out_len] = n;
                        out_len += 1;
                        n += 1;
                    }
                }
            } else if out_len < MAX_CONNS {
                conns[out_len] = entry;
                out_len += 1;
            }
            prev = Some(entry);
        }
        (conns, out_len)
    }

    /// Program the output path: route the DAC to the pin, power both up, unmute,
    /// and bind the stream tag. Format is set later (per rate) by `set_format`.
    fn configure_path(&mut self) {
        if self.afg != 0 {
            self.verb(self.afg, VERB_SET_POWER_STATE << 8); // D0
        }
        self.configure_realtek_eapd_coef();

        for i in 0..self.path.len {
            let nid = self.path.nodes[i];
            self.verb(nid, VERB_SET_POWER_STATE << 8); // D0
            if i + 1 < self.path.len {
                self.verb(
                    nid,
                    (VERB_SET_CONN_SELECT << 8) | self.path.conn_idx[i] as u32,
                );
                self.verb(
                    nid,
                    (0x3 << 16) | 0x7000 | ((self.path.conn_idx[i] as u32) << 8),
                );
            }
        }

        let pin_ctl = if default_device(self.pin_def) == DEFAULT_DEVICE_HP_OUT {
            PIN_CTL_OUT | PIN_CTL_HP
        } else {
            PIN_CTL_OUT
        };
        self.verb(self.pin, (VERB_SET_PIN_WIDGET_CONTROL << 8) | pin_ctl);
        self.verb(self.pin, (VERB_SET_EAPD_BTL << 8) | 0x02); // external amp on, if present
        let pin_gain = self.out_amp_zero_db(self.pin);
        self.verb(self.pin, (0x3 << 16) | 0xB000 | pin_gain); // output amp unmute @ 0 dB

        self.verb(
            self.dac,
            (VERB_SET_CONV_STREAM_CHAN << 8) | (STREAM_TAG << 4),
        );
        let dac_gain = self.out_amp_zero_db(self.dac);
        self.verb(self.dac, (0x3 << 16) | 0xB000 | dac_gain); // DAC amp unmute @ 0 dB
        crate::println!("hda: amp pin gain={:#x} dac gain={:#x}", pin_gain, dac_gain);
    }

    /// 0 dB gain value for a widget's output amp: the offset field of its amp
    /// capabilities (a mute-only amp has offset 0). Widgets without their own
    /// caps inherit the AFG defaults. Writing a gain beyond the amp's range
    /// (e.g. 0x7F to pin 0x17's zero-step amp on the ALC298) is undefined and
    /// may leave the amp muted, so never blast a fixed "max" value.
    fn out_amp_zero_db(&mut self, nid: u32) -> u32 {
        let mut caps = self.verb(nid, (VERB_GET_PARAMETER << 8) | PARAM_OUT_AMP_CAPS);
        if caps == 0 {
            caps = self.verb(self.afg, (VERB_GET_PARAMETER << 8) | PARAM_OUT_AMP_CAPS);
        }
        caps & 0x7F
    }

    fn read_realtek_coef(&mut self, index: u32) -> u32 {
        self.verb(
            REALTEK_VENDOR_NID,
            (VERB_SET_COEF_INDEX << 8) | (index & 0xFF),
        );
        self.verb(REALTEK_VENDOR_NID, VERB_GET_PROC_COEF << 8) & 0xFFFF
    }

    fn write_realtek_coef(&mut self, index: u32, value: u32) {
        self.verb(
            REALTEK_VENDOR_NID,
            (VERB_SET_COEF_INDEX << 8) | (index & 0xFF),
        );
        self.verb(
            REALTEK_VENDOR_NID,
            (VERB_SET_PROC_COEF << 8) | (value & 0xFFFF),
        );
    }

    /// Read back the programmed output state + a window of Realtek COEFs so a
    /// silent boot's klog can be diffed against a working one.
    fn dump_output_state(&mut self) {
        let pinctl = self.verb(self.pin, 0xF07 << 8);
        let eapd = self.verb(self.pin, 0xF0C << 8);
        let pinamp = self.verb(self.pin, (0xB << 16) | 0x8000);
        let dacamp = self.verb(self.dac, (0xB << 16) | 0x8000);
        let pinpwr = self.verb(self.pin, 0xF05 << 8);
        let dacpwr = self.verb(self.dac, 0xF05 << 8);
        let pinsel = self.verb(self.pin, VERB_GET_CONN_SELECT << 8);
        crate::println!(
            "hda: state pinctl={:#x} eapd={:#x} pinamp={:#x} dacamp={:#x} pinpwr={:#x} dacpwr={:#x} pinsel={:#x}",
            pinctl, eapd, pinamp, dacamp, pinpwr, dacpwr, pinsel
        );
        if self.codec_vendor != REALTEK_ALC298 {
            return;
        }
        for base in (0x00..0x40u32).step_by(8) {
            let mut c = [0u32; 8];
            for (i, v) in c.iter_mut().enumerate() {
                *v = self.read_realtek_coef(base + i as u32);
            }
            crate::println!(
                "hda: coef {:02x}: {:04x} {:04x} {:04x} {:04x} {:04x} {:04x} {:04x} {:04x}",
                base, c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]
            );
        }
    }

    fn configure_realtek_eapd_coef(&mut self) {
        if self.codec_vendor != REALTEK_ALC298 {
            return;
        }
        let old = self.read_realtek_coef(REALTEK_EAPD_COEF_INDEX);
        if self.verb_failed {
            return;
        }
        let new = old & !REALTEK_EAPD_COEF_MASK;
        if new != old {
            self.write_realtek_coef(REALTEK_EAPD_COEF_INDEX, new);
        }
        crate::println!("hda: alc298 coef10 {:#06x}->{:#06x}", old, new);
    }

    /// Encode a 16-bit stereo stream format for `rate` (HDA SDFMT / converter
    /// format encoding: base 44.1/48 kHz × multiple ÷ divisor). Unknown rates
    /// fall back to 44.1 kHz (QEMU resamples internally).
    fn fmt(rate: u32) -> u16 {
        let (base, div): (u16, u16) = match rate {
            44100 => (1, 0),
            22050 => (1, 1),
            11025 => (1, 3),
            48000 => (0, 0),
            24000 => (0, 1),
            16000 => (0, 2),
            12000 => (0, 3),
            8000 => (0, 5),
            // Odd SB rates (e.g. 22222 from DSP time constant 211) → nearest
            // 44.1 kHz submultiple. divisor = round(44100/rate), field = div-1.
            _ => {
                let divisor = ((44100 + rate / 2) / rate).clamp(1, 8);
                (1, (divisor - 1) as u16)
            }
        };
        // bit14 base | bits10:8 div | bits6:4 bits(001=16) | bits3:0 chan-1(1=stereo)
        (base << 14) | (div << 8) | (0b001 << 4) | 0x0001
    }

    /// (Re)program the stream + DAC converter format for `rate`. Requires the
    /// stream to be stopped; only called from the priming path (running == false).
    fn set_format(&mut self, rate: u32) {
        let f = Self::fmt(rate);
        w16(self.sd + SDFMT, f);
        let dac = self.dac;
        self.verb(dac, (0x2 << 16) | f as u32); // Set Converter Format
        self.stop_corb_rirb();
        self.rate = rate;
        if DEBUG {
            crate::println!("hda: set_format rate={} fmt={:#06x}", rate, f);
        }
    }

    fn hardware_rate(src_rate: u32) -> u32 {
        match src_rate {
            44100 | 48000 => src_rate,
            24000 | 16000 | 12000 | 8000 => 48000,
            0 => 44100,
            _ => 44100,
        }
    }

    /// Current play position as a buffer index, from the hardware byte position.
    fn play_buf(&self) -> usize {
        (r32(self.sd + SDLPIB) as usize / BUF_BYTES) % NUM_BUF
    }

    /// Play position (bytes) from the DMA position buffer — QEMU's authoritative
    /// source on builds that don't update the SDLPIB register.
    fn dma_pos(&self) -> u32 {
        let idx = (self.sd - SD_BASE) / SD_STRIDE;
        unsafe { read_volatile((self.dma_va + POS_OFF + idx * 8) as *const u32) }
    }

    fn stop(&mut self) {
        let ctl = r8(self.sd + SDCTL);
        w8(self.sd + SDCTL, ctl & !0x02); // clear RUN
        for _ in 0..100_000 {
            if r8(self.sd + SDCTL) & 0x02 == 0 {
                break;
            }
        }
    }

    fn emit_stereo(&mut self, l: i16, r: i16) -> bool {
        // At each buffer boundary, cap how far we run ahead of the controller.
        if self.cur_off == 0 && self.running {
            let civ = self.play_buf();
            let ahead = (self.cur_buf + NUM_BUF - civ) % NUM_BUF;
            // Only throttle when genuinely AHEAD of the codec. A wrapped
            // value (>= half the ring) means the play position lapped us
            // (underrun) — feed hard to catch up, never stall.
            if (MAX_AHEAD..NUM_BUF / 2).contains(&ahead) {
                if self.diag_stalls < 3 {
                    crate::println!(
                        "hda: stall cur_buf={} play_buf={} ahead={} lpib={} pos={} sdctl={:#x} sdsts={:#x}",
                        self.cur_buf,
                        civ,
                        ahead,
                        r32(self.sd + SDLPIB),
                        self.dma_pos(),
                        r32(self.sd + SDCTL),
                        r8(self.sd + 0x03)
                    );
                    self.diag_stalls += 1;
                }
                return false;
            }
        }
        let p = self.buf_va(self.cur_buf) + self.cur_off;
        unsafe {
            write_volatile(p as *mut u16, l as u16);
            write_volatile((p + 2) as *mut u16, r as u16);
        }
        self.cur_off += 4;
        if self.cur_off >= BUF_BYTES {
            self.cur_buf = (self.cur_buf + 1) % NUM_BUF;
            self.cur_off = 0;
            // Start the stream once a small cushion is primed. Write RUN +
            // stream number as ONE dword so QEMU re-evaluates the codec<->
            // stream binding with the stream number visible (a byte-0-only
            // RUN write may not retrigger it → codec never drains the FIFO).
            if !self.running && self.cur_buf >= PRIME_BUFS {
                w32(self.sd + SDCTL, 0x02 | (STREAM_TAG << 20));
                self.running = true;
                if !self.logged_run {
                    crate::println!(
                        "hda: stream RUN sdctl={:#010x} sdsts={:#x} cbl={} lvi={} fmt={:#06x} lpib={} pos={}",
                        r32(self.sd + SDCTL),
                        r8(self.sd + 0x03),
                        r32(self.sd + SDCBL),
                        r16(self.sd + SDLVI),
                        r16(self.sd + SDFMT),
                        r32(self.sd + SDLPIB),
                        self.dma_pos(),
                    );
                    self.logged_run = true;
                }
            }
            // First few buffer boundaries: does the HW play position advance?
            if self.running && self.diag_buffers < 6 {
                crate::println!(
                    "hda: playback cur_buf={} play_buf={} pos_buf={} lpib={} pos={} sdctl={:#x} sdsts={:#x}",
                    self.cur_buf,
                    self.play_buf(),
                    (self.dma_pos() as usize / BUF_BYTES) % NUM_BUF,
                    r32(self.sd + SDLPIB),
                    self.dma_pos(),
                    r32(self.sd + SDCTL),
                    r8(self.sd + 0x03),
                );
                self.diag_buffers += 1;
            }
        }
        true
    }

    /// Decode `bytes` (`fmt`) into canonical i16 stereo and stream into the ring.
    fn submit(&mut self, rate: u32, fmt: Format, bytes: &[u8]) {
        if self.parked && !self.unpark() {
            crate::println!("hda: unpark failed, dropping playback");
            self.parked = true;
            return;
        }
        let src_rate = if rate == 0 { 44100 } else { rate };
        let hw_rate = Self::hardware_rate(src_rate);
        // A hardware-rate change needs a fresh format, which means stopping the
        // stream and re-priming. DOS playback sets one rate per session, so this
        // is rare. Source-rate changes also reset the resampler phase.
        if hw_rate != self.rate || src_rate != self.src_rate {
            if self.running {
                self.stop();
                self.running = false;
            }
            self.cur_buf = 0;
            self.cur_off = 0;
            self.set_format(hw_rate);
            self.src_rate = src_rate;
            self.resample_acc = 0;
        }
        let fb = fmt.frame_bytes();
        if fb == 0 {
            return;
        }
        if !self.logged_submit {
            crate::println!(
                "hda: pcm submit src_rate={} hw_rate={} bits={} signed={} ch={} frame_bytes={} bytes={}",
                src_rate,
                hw_rate,
                fmt.bits,
                fmt.signed,
                fmt.channels,
                fb,
                bytes.len(),
            );
            self.logged_submit = true;
        }
        for i in 0..bytes.len() / fb {
            let (l, r) = fmt.frame(bytes, i);
            if src_rate == hw_rate {
                if !self.emit_stereo(l, r) {
                    break;
                }
            } else {
                self.resample_acc += hw_rate as u64;
                while self.resample_acc >= src_rate as u64 {
                    if !self.emit_stereo(l, r) {
                        return;
                    }
                    self.resample_acc -= src_rate as u64;
                }
            }
        }
    }
}

fn find_widget(widgets: &[Widget; MAX_WIDGETS], count: usize, nid: u32) -> Option<usize> {
    (0..count).find(|&i| widgets[i].nid == nid)
}

fn default_port(def_cfg: u32) -> u32 {
    (def_cfg >> 30) & 0x3
}

fn default_device(def_cfg: u32) -> u32 {
    (def_cfg >> 20) & 0xF
}

fn output_pin_score(w: &Widget) -> i32 {
    if w.pin_caps & PIN_CAP_OUT == 0 || default_port(w.def_cfg) == DEFAULT_PORT_NONE {
        return -1;
    }
    let mut score = 100;
    match default_device(w.def_cfg) {
        DEFAULT_DEVICE_SPEAKER => score += 800,
        DEFAULT_DEVICE_HP_OUT => score += 500,
        DEFAULT_DEVICE_LINE_OUT => score += 350,
        _ => score += 100,
    }
    if default_port(w.def_cfg) == DEFAULT_PORT_FIXED {
        score += 80;
    }
    let assoc = (w.def_cfg >> 4) & 0xF;
    if assoc != 0 && assoc != 0xF {
        score += 20;
    }
    score
}

fn fallback_output_path(widgets: &[Widget; MAX_WIDGETS], count: usize) -> Option<OutputPath> {
    let mut pin = 0;
    let mut dac = 0;
    for w in widgets.iter().take(count) {
        if dac == 0 && w.typ == WTYPE_AUDIO_OUTPUT {
            dac = w.nid;
        }
        if pin == 0 && w.typ == WTYPE_PIN_COMPLEX && w.pin_caps & PIN_CAP_OUT != 0 {
            pin = w.nid;
        }
    }
    if pin == 0 || dac == 0 {
        None
    } else {
        let mut path = OutputPath::EMPTY;
        path.nodes[0] = pin;
        path.nodes[1] = dac;
        path.len = 2;
        path.score = 0;
        Some(path)
    }
}

fn path_extra_score(
    widgets: &[Widget; MAX_WIDGETS],
    count: usize,
    path: &OutputPath,
    codec_vendor: u32,
) -> i32 {
    let Some(dac_idx) = find_widget(widgets, count, path.nodes[path.len - 1]) else {
        return -1000;
    };
    let mut score = (MAX_PATH - path.len) as i32;
    if widgets[dac_idx].caps & AW_CAP_DIGITAL != 0 {
        score -= 300;
    }
    let pin_dev = find_widget(widgets, count, path.nodes[0])
        .map(|i| default_device(widgets[i].def_cfg))
        .unwrap_or(0xF);
    for i in 0..path.len.saturating_sub(1) {
        if let Some(widx) = find_widget(widgets, count, path.nodes[i])
            && widgets[widx].conn_sel == path.conn_idx[i]
        {
            score += 10;
        }
    }
    // This Razer/AMD laptop reports a Realtek ALC298. Linux routes speakers as
    // pin 0x17 -> mixer 0x0d -> DAC 0x03 and headphones as pin 0x21 -> 0x0c
    // -> DAC 0x02. Keep the rule as a topology preference, not a hard-coded
    // only path, so other codecs still use the generic graph walk.
    if codec_vendor == REALTEK_ALC298 {
        if pin_dev == DEFAULT_DEVICE_SPEAKER {
            if path.nodes[path.len - 1] == 0x03 {
                score += 80;
            }
            if path.nodes[..path.len].contains(&0x0d) {
                score += 80;
            }
        } else if pin_dev == DEFAULT_DEVICE_HP_OUT {
            if path.nodes[path.len - 1] == 0x02 {
                score += 40;
            }
            if path.nodes[..path.len].contains(&0x0c) {
                score += 40;
            }
        }
    }
    score
}

#[allow(clippy::too_many_arguments)]
fn dfs_output_path(
    widgets: &[Widget; MAX_WIDGETS],
    count: usize,
    nid: u32,
    base_score: i32,
    codec_vendor: u32,
    path: &mut OutputPath,
    visited: &mut [u32; MAX_PATH],
    depth: usize,
    best: &mut OutputPath,
) {
    if depth >= MAX_PATH || visited[..depth].contains(&nid) {
        return;
    }
    let Some(idx) = find_widget(widgets, count, nid) else {
        return;
    };
    // A pin complex can only *start* a path. Interior pins are not signal
    // routes: on the laptop's ALC298 the walk otherwise threads speaker pin
    // 0x17 through mixer 0x0c, input mixer 0x0b and mic pin 0x1a to reach
    // 0x0d/DAC 0x03, collecting the topology bonuses with a route that
    // programs the speaker to listen to the (silent) input loopback.
    if depth > 0 && widgets[idx].typ == WTYPE_PIN_COMPLEX {
        return;
    }
    path.nodes[depth] = nid;
    path.len = depth + 1;
    visited[depth] = nid;

    if widgets[idx].typ == WTYPE_AUDIO_OUTPUT {
        let mut candidate = *path;
        candidate.score = base_score + path_extra_score(widgets, count, &candidate, codec_vendor);
        if candidate.score > best.score {
            *best = candidate;
        }
        return;
    }
    if !matches!(
        widgets[idx].typ,
        WTYPE_PIN_COMPLEX | WTYPE_AUDIO_MIXER | WTYPE_AUDIO_SELECTOR
    ) {
        return;
    }
    for i in 0..widgets[idx].conn_len {
        path.conn_idx[depth] = i as u8;
        dfs_output_path(
            widgets,
            count,
            widgets[idx].conns[i],
            base_score,
            codec_vendor,
            path,
            visited,
            depth + 1,
            best,
        );
    }
}

/// Stream a block of source PCM to the HDA codec (called by `sound::play` when an
/// HDA controller was discovered).
pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    let _ = machine;
    let mut g = HDA.lock();
    if let Some(dev) = g.as_mut() {
        dev.submit(rate, fmt, bytes);
    }
}

/// Panic-path quiesce: stop all controller DMA and hold the link in reset so a
/// hard reboot from a panic doesn't leave the codec wedged (mid-stream resets
/// have left the ALC298 deaf to every OS until a cold power-off). Touches only
/// MMIO — no locks, no allocation — so it is safe from the panic handler even
/// if the HDA mutex is held.
pub fn emergency_quiesce() {
    if !BAR_MAPPED.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    stop_controller_dma();
    w32(GCTL, 0); // assert CRST: the codec rides out the reboot in reset
}

/// Stop active HDA playback DMA after the emulated producer goes idle. With
/// `park` (DSP reset / session end) the link is additionally held in reset so
/// a power-button exit cannot catch the codec active; without it (pause,
/// single-cycle block end) the configured path is kept so the producer can
/// re-prime cheaply.
pub fn stop<A: crate::Arch>(machine: &mut A, park: bool) {
    let _ = machine;
    let mut g = HDA.lock();
    if let Some(dev) = g.as_mut() {
        if park {
            dev.park();
        } else {
            dev.stop_playback();
            dev.stop_corb_rirb();
        }
    }
}
