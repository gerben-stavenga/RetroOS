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
//! Ring geometry mirrors `ac97`: a ring of small PCM buffers in a borrowed
//! contiguous DMA buffer, primed then run. The regular system tick polls
//! SDLPIB and the producer refills every completed buffer; playback requests no
//! completion interrupts.
//!
//! ## Topology
//!
//! Real laptops often expose several HDA functions: GPU HDMI/DP audio first,
//! then the internal analog codec later on a high PCI bus. We rank PCI HDA
//! candidates before bring-up, then enumerate the selected codec's widget graph
//! and choose a real output route. Pins whose default config says "not
//! connected" are ignored; valid paths are ranked by the selected output
//! preference, and digital-only paths are de-prioritized. This keeps QEMU's tiny
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
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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
const INTCTL: usize = 0x20; // d32: bit31 GIE, bit30 CIE, bits0..29 per-stream SIE
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
const BDL_OFF: usize = 0x0C00; // 128-byte aligned; NUM_BUF*16 = 1024 bytes
const BUF_OFF: usize = 0x2000; // PCM ring starts on the next page
const DMA_PAGES: usize = (BUF_OFF + NUM_BUF * BUF_BYTES).div_ceil(0x1000);

// ── PCM ring geometry ────────────────────────────────────────────────────────
// Fine descriptors make cursor accounting and latency control ~2.7 ms at
// 48 kHz. Normal accounting polls the live cursor; descriptors request no
// completion interrupts.
const NUM_BUF: usize = 64;
const BUF_BYTES: usize = 0x200;
const BUF_FRAMES: usize = BUF_BYTES / core::mem::size_of::<crate::kernel::sound::Frame>();
const RING_FRAMES: usize = NUM_BUF * BUF_FRAMES;
/// The complete SDFMT / converter-format word this stream is programmed with:
/// bit14 rate base, bits13:11 multiplier, bits10:8 divisor, bits6:4 sample
/// width and bits3:0 channels-1.
const STREAM_FMT: u16 = 0x0011;
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

// Written once during single-threaded boot, then reachable only through the
// unique capability returned by `probe`. Rust cannot express that phase
// transition, so the unsafe proof is confined to `install` below.
static mut HDA: Option<Hda> = None;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum OutputRoute {
    Speaker = 0,
    Jack = 1,
    Headphone = 2,
}

const DEFAULT_OUTPUT_ROUTE: OutputRoute = OutputRoute::Speaker;

impl OutputRoute {
    const ALL: [Self; 3] = [Self::Speaker, Self::Jack, Self::Headphone];

    fn from_raw(raw: u8) -> Self {
        Self::ALL.get(raw as usize).copied().unwrap_or(DEFAULT_OUTPUT_ROUTE)
    }

    fn label(self) -> &'static [u8] {
        match self {
            Self::Speaker => b"Speaker",
            Self::Jack => b"Jack",
            Self::Headphone => b"Headphone",
        }
    }

    fn next(self, forward: bool) -> Self {
        let current = self as usize;
        let next = if forward {
            (current + 1) % Self::ALL.len()
        } else {
            (current + Self::ALL.len() - 1) % Self::ALL.len()
        };
        Self::ALL[next]
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }

    fn next_available(self, forward: bool, available: u8) -> Self {
        let mut candidate = self;
        for _ in 0..Self::ALL.len() {
            candidate = candidate.next(forward);
            if available & candidate.bit() != 0 {
                return candidate;
            }
        }
        self
    }
}

/// Route which is known to be programmed successfully and may be displayed.
static OUTPUT_ROUTE: AtomicU8 = AtomicU8::new(DEFAULT_OUTPUT_ROUTE as u8);
/// Route requested by CONFIG.SYS or the OSD, committed only after programming.
static REQUESTED_OUTPUT_ROUTE: AtomicU8 = AtomicU8::new(DEFAULT_OUTPUT_ROUTE as u8);
/// Routes backed by a usable pin-to-DAC path on the active codec.
static AVAILABLE_OUTPUT_ROUTES: AtomicU8 = AtomicU8::new(0);
static OUTPUT_ROUTE_PENDING: AtomicBool = AtomicBool::new(false);
/// True once the controller BAR is mapped at `BAR_WIN_VA` (panic-path guard).
static BAR_MAPPED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn parse_output_route(raw: &[u8]) -> Option<OutputRoute> {
    if raw.eq_ignore_ascii_case(b"Speaker") {
        Some(OutputRoute::Speaker)
    } else if raw.eq_ignore_ascii_case(b"Jack") {
        Some(OutputRoute::Jack)
    } else if raw.eq_ignore_ascii_case(b"Headphone") {
        Some(OutputRoute::Headphone)
    } else {
        None
    }
}

fn log_available_output_routes(prefix: &str, available: u8) {
    let mut any = false;
    for route in OutputRoute::ALL {
        if available & route.bit() != 0 {
            any = true;
            crate::println!(
                "hda: {} {}",
                prefix,
                core::str::from_utf8(route.label()).unwrap_or("?")
            );
        }
    }
    if !any {
        crate::println!("hda: {} none", prefix);
    }
}

pub fn configure_output_route(raw: Option<&[u8]>) {
    let route = match raw {
        None => OutputRoute::Speaker,
        Some(value) => match parse_output_route(value) {
            Some(route) => route,
            None => {
                REQUESTED_OUTPUT_ROUTE.store(DEFAULT_OUTPUT_ROUTE as u8, Ordering::Relaxed);
                OUTPUT_ROUTE_PENDING.store(false, Ordering::Relaxed);
                crate::println!(
                    "hda: invalid HDA_OUTPUT={}",
                    core::str::from_utf8(value).unwrap_or("<non-UTF8>")
                );
                return;
            }
        },
    };
    REQUESTED_OUTPUT_ROUTE.store(route as u8, Ordering::Relaxed);
    OUTPUT_ROUTE_PENDING.store(false, Ordering::Relaxed);
}

pub fn output_route_label() -> &'static [u8] {
    // The OSD reflects the user's current selection immediately. Hardware
    // programming may be deferred until the next device service point, but
    // that must not make the control appear stuck while playback is paused.
    OutputRoute::from_raw(REQUESTED_OUTPUT_ROUTE.load(Ordering::Relaxed)).label()
}

pub fn cycle_output_route(forward: bool) {
    let current = OutputRoute::from_raw(OUTPUT_ROUTE.load(Ordering::Relaxed));
    let next = current.next_available(
        forward,
        AVAILABLE_OUTPUT_ROUTES.load(Ordering::Relaxed),
    );
    if next == current {
        return;
    }
    REQUESTED_OUTPUT_ROUTE.store(next as u8, Ordering::Relaxed);
    OUTPUT_ROUTE_PENDING.store(true, Ordering::Relaxed);
    crate::println!(
        "hda: requested output route {}",
        core::str::from_utf8(next.label()).unwrap_or("?")
    );
}

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

pub struct Hda {
    dma_va: usize,
    dma_phys: u32,
    /// First output stream descriptor base (0x80 + ISS*0x20).
    sd: usize,
    /// Our private RIRB read cursor (the controller advances RIRBWP).
    rirb_rp: usize,
    /// True while CORB/RIRB DMA engines are running for codec verbs.
    rings_running: bool,
    /// Latched when a codec verb times out; bring-up abandons this controller.
    verb_failed: bool,
    /// True once the ALC298 vendor-DSP amp sequence has been replayed this boot.
    amp_init_done: bool,
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
    output_paths: [OutputPath; OutputRoute::ALL.len()],
    output_pin_defs: [u32; OutputRoute::ALL.len()],
    output_route: OutputRoute,
    running: bool,
    /// Bytes the codec has consumed since the stream started, monotonic, and
    /// the last modular hardware position accumulated into it. This cursor
    /// delta is the authoritative amount consumed.
    consumed_hw: u64,
    last_hw_pos: u32,
    /// Frames already reported to the sink.
    reported: u64,
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

/// Find and initialize the preferred usable HDA controller. Real laptops often
/// expose GPU HDMI before their analog codec, so candidates are ranked and
/// tried in order rather than accepting the first PCI class match.
pub fn probe<A: crate::Arch>(machine: &mut A) -> Option<&'static mut Hda> {
    let mut devices = [HdaPciDevice::EMPTY; MAX_HDA_CONTROLLERS];
    let n = collect_hda_controllers(machine, &mut devices);
    sort_hda_controllers(&mut devices, n);
    for d in devices.iter().take(n) {
        if let Some(device) = bring_up(machine, d.bus, d.dev, d.func) {
            return Some(install(device));
        }
    }
    None
}

/// Publish the one device created during boot and hand out its sole mutable
/// capability. `startup` calls `probe` once before threads exist; after this
/// handoff no code names the slot again.
fn install(device: Hda) -> &'static mut Hda {
    unsafe {
        let slot = &raw mut HDA;
        assert!((*slot).is_none(), "HDA probed twice");
        *slot = Some(device);
        (*slot).as_mut().unwrap()
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
/// capability, hoping the function internally resets on the D0 edge and
/// takes the codec's power domain with it. NOTE: a function with
/// PMCSR.No_Soft_Reset=1 is spec-guaranteed to KEEP state across that
/// transition — the AMD HDA function on the ALC298 laptop sets it, so this
/// escalation cannot recover that machine's wedge (verified from Linux
/// 2026-07: only a cold power-off revives the codec; prevention via
/// quiescing the controller before power-off is the real fix). Still attempted for
/// hardware that resets anyway, with the NSR bit logged so the bring-up
/// trace is honest. Returns false if the function has no PM capability.
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
    if pmcsr & (1 << 3) != 0 {
        crate::println!(
            "hda: {:02x}:{:02x}.{} PMCSR.NSR=1: D3hot cycle will not reset this function",
            bus, dev, func
        );
    }
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
fn bring_up<A: crate::Arch>(machine: &mut A, bus: u8, dev: u8, func: u8) -> Option<Hda> {
    // Enable memory space + bus master and suppress INTx: playback progress is
    // polled from SDLPIB, so this sink deliberately generates no interrupts.
    let cmd = crate::kernel::pci::read32(machine, bus, dev, func, 0x04);
    crate::kernel::pci::write32(
        machine,
        bus,
        dev,
        func,
        0x04,
        (cmd & 0xFFFF) | 0x06 | (1 << 10),
    );

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
        return None;
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
        return None;
    }
    machine.map_phys_range(DMA_WIN_VA >> 12, DMA_PAGES, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    let mut d = Hda {
        dma_va: DMA_WIN_VA,
        dma_phys,
        sd,
        rirb_rp: 0,
        rings_running: false,
        verb_failed: false,
        amp_init_done: false,
        cad: 0,
        codec_vendor: 0,
        afg: 0,
        dac: 0,
        pin: 0,
        pin_def: 0,
        path: OutputPath::EMPTY,
        output_paths: [OutputPath::EMPTY; OutputRoute::ALL.len()],
        output_pin_defs: [0; OutputRoute::ALL.len()],
        output_route: DEFAULT_OUTPUT_ROUTE,
        running: false,
        reported: 0,
        consumed_hw: 0,
        last_hw_pos: 0,
    };

    // Link reset + codec detection, with escalating recovery. A hard reboot
    // during active streaming can leave the codec wedged: it stays deaf to
    // plain CRST resets across warm reboots until its power well cycles
    // (observed on the ALC298 laptop; Linux then reports "no codecs found"
    // until a cold boot). Attempt 0 is the normal spec sequence; attempt 1
    // retries with a longer reset hold; attempt 2 first bounces the function
    // through PCI D3hot → D0 in the hope the codec power domain resets with
    // it. That hope is dead on the ALC298 laptop itself (its HDA function
    // sets PMCSR.No_Soft_Reset — see pci_pm_power_cycle), so prevention is
    // the real defense: quiesce the link on every shutdown path.
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
        return None;
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
                return None;
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
    let requested = OutputRoute::from_raw(REQUESTED_OUTPUT_ROUTE.load(Ordering::Relaxed));
    if !d.discover_output_paths(requested) || d.verb_failed {
        crate::println!(
            "hda: {:02x}:{:02x}.{} failed: no output path (codec={:#x}, verb_failed={})",
            bus,
            dev,
            func,
            d.codec_vendor,
            d.verb_failed
        );
        d.shutdown_controller();
        return None;
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
        return None;
    }
    OUTPUT_ROUTE.store(d.output_route as u8, Ordering::Relaxed);
    REQUESTED_OUTPUT_ROUTE.store(d.output_route as u8, Ordering::Relaxed);
    OUTPUT_ROUTE_PENDING.store(false, Ordering::Relaxed);
    log_available_output_routes(
        "available output",
        AVAILABLE_OUTPUT_ROUTES.load(Ordering::Relaxed),
    );
    crate::println!(
        "hda: selected output {}",
        core::str::from_utf8(d.output_route.label()).unwrap_or("?")
    );
    d.dump_output_state();

    // The stream format is this card's own constant, so it is programmed here
    // and never again: nothing above can ask for a different rate.
    d.program_format();

    // Bring-up leaves the controller initialized and the stream stopped, with
    // codec command DMA idle until something needs a verb again.
    d.stop_corb_rirb();

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
    Some(d)
}

impl Hda {
    fn buf_phys(&self, i: usize) -> u32 {
        self.dma_phys + (BUF_OFF + i * BUF_BYTES) as u32
    }

    /// Fill the BDL: entry i → PCM buffer i. Each HDA BDL entry is 16 bytes
    /// { addr:u64, len:u32, flags:u32 }. Progress is polled from SDLPIB, so no
    /// descriptor requests an interrupt on completion.
    fn build_bdl(&mut self) {
        for i in 0..NUM_BUF {
            let entry = self.dma_va + BDL_OFF + i * 16;
            unsafe {
                write_volatile(entry as *mut u32, self.buf_phys(i)); // addr low
                write_volatile((entry + 4) as *mut u32, 0); // addr high
                write_volatile((entry + 8) as *mut u32, BUF_BYTES as u32); // length
                write_volatile((entry + 12) as *mut u32, 0); // flags: no IOC
            }
        }
    }

    /// Initialize and start the CORB (command) and RIRB (response) DMA rings.
    fn setup_corb_rirb(&mut self) {
        // Stop both engines before reprogramming their bases.
        w8(CORBCTL, 0);
        w8(RIRBCTL, 0);
        w8(RIRBSTS, 0x05);
        self.verb_failed = false;

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
        self.consumed_hw = 0;
        self.last_hw_pos = 0;
        self.reported = 0;
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

    /// Program the output stream descriptor: SRST pulse, BDL base, cyclic
    /// length and stream tag. Everything here is controller register state, so
    /// it must rerun after every CRST during bring-up.
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

        // Point the stream descriptor at the BDL and cap its cyclic length.
        w32(sd + SDBDPL, self.dma_phys + BDL_OFF as u32);
        w32(sd + SDBDPU, 0);
        w32(sd + SDCBL, (NUM_BUF * BUF_BYTES) as u32);
        w16(sd + SDLVI, (NUM_BUF - 1) as u16);
        // Stream tag in the descriptor control byte (bits 20..23 of SDCTL).
        w8(sd + SDCTL + 2, (STREAM_TAG << 4) as u8);

        w32(INTCTL, 0); // cursor polling is the only completion path
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

    /// Walk the codec graph, cache the routes which have usable paths, and
    /// choose the requested route (or the best real fallback when unavailable).
    fn discover_output_paths(&mut self, requested: OutputRoute) -> bool {
        let mut widgets = [Widget::EMPTY; MAX_WIDGETS];
        let count = self.enumerate_widgets(&mut widgets);
        let mut best_any = OutputPath::EMPTY;
        let mut best_by_route = [OutputPath::EMPTY; OutputRoute::ALL.len()];
        for &w in widgets.iter().take(count) {
            if w.typ != WTYPE_PIN_COMPLEX {
                continue;
            }
            let base_score = default_output_pin_score(&w);
            if base_score <= 0 {
                continue;
            }
            let mut path = OutputPath::EMPTY;
            let mut visited = [0u32; MAX_PATH];
            dfs_output_path(
                &widgets,
                count,
                w.nid,
                base_score,
                self.codec_vendor,
                &mut path,
                &mut visited,
                0,
                &mut best_any,
            );

            let route = output_route_for_widget(&w);
            let mut route_path = OutputPath::EMPTY;
            let mut route_visited = [0u32; MAX_PATH];
            dfs_output_path(
                &widgets,
                count,
                w.nid,
                output_pin_score(&w, route),
                self.codec_vendor,
                &mut route_path,
                &mut route_visited,
                0,
                &mut best_by_route[route as usize],
            );
        }

        let available = best_by_route
            .iter()
            .enumerate()
            .fold(0u8, |mask, (index, path)| {
                mask | u8::from(path.len != 0) << index
            });
        AVAILABLE_OUTPUT_ROUTES.store(available, Ordering::Relaxed);
        self.output_paths = best_by_route;
        self.output_pin_defs = [0; OutputRoute::ALL.len()];
        for (index, path) in best_by_route.iter().enumerate() {
            if let Some(pin) = find_widget(&widgets, count, path.nodes[0]) {
                self.output_pin_defs[index] = widgets[pin].def_cfg;
            }
        }

        let requested_path = best_by_route[requested as usize];
        let mut best = if requested_path.len != 0 {
            self.output_route = requested;
            requested_path
        } else {
            best_any
        };
        if best.len == 0 {
            let Some(path) = fallback_output_path(&widgets, count) else {
                return false;
            };
            best = path;
        }
        if requested_path.len == 0
            && let Some(pin) = find_widget(&widgets, count, best.nodes[0])
        {
            self.output_route = output_route_for_widget(&widgets[pin]);
        }
        self.path = best;
        self.pin = best.nodes[0];
        self.dac = best.nodes[best.len - 1];
        if let Some(pin) = find_widget(&widgets, count, self.pin) {
            self.pin_def = widgets[pin].def_cfg;
        }
        true
    }

    /// Select one of the paths discovered during initial codec enumeration.
    /// Runtime route changes must not re-walk the codec graph.
    fn select_cached_output_path(&mut self, requested: OutputRoute) -> bool {
        let path = self.output_paths[requested as usize];
        if path.len == 0 {
            return false;
        }
        self.output_route = requested;
        self.path = path;
        self.pin_def = self.output_pin_defs[requested as usize];
        self.pin = path.nodes[0];
        self.dac = path.nodes[path.len - 1];
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
        self.replay_alc298_amp_init();
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

    /// Program the ALC298's vendor DSP so the speaker amp actually produces
    /// sound. The laptop speaker is silent after a COLD boot without this —
    /// the tiny coef10 poke below only helps when a previous Linux boot
    /// already ran the full Windows-driver sequence and its state survived
    /// the warm reboot. The sequence is latched once per boot so any repeated
    /// path configuration does not replay its ~2000 verbs.
    fn replay_alc298_amp_init(&mut self) {
        if self.amp_init_done {
            return;
        }
        for &v in crate::kernel::drivers::alc298_amp::AMP_INIT {
            self.verb(REALTEK_VENDOR_NID, v);
            if self.verb_failed {
                crate::println!("hda: alc298 amp init aborted (codec stopped responding)");
                return;
            }
            // Pace the replay like the reference does. The oracle (Ubuntu's
            // rb_audio.sh) runs one hda-verb PROCESS per write — milliseconds
            // between verbs — while a back-to-back CORB burst gives the
            // vendor DSP microseconds. Its banked/indirect writes (the
            // 0x23/0x26 sequences) can silently drop under that pressure:
            // every CORB round-trip acks, but the DSP program comes up
            // partial — amp audible, low band buried (metal played E1M5's
            // string line at a whisper while the same PCM through Linux's
            // fully-programmed codec was loud). ~50 µs per verb costs ~100 ms
            // once per boot.
            spin(100_000);
        }
        self.amp_init_done = true;
        crate::println!(
            "hda: alc298 amp init replayed ({} verbs)",
            crate::kernel::drivers::alc298_amp::AMP_INIT.len()
        );
    }

    /// Program the stream descriptor and the DAC converter for [`STREAM_FMT`].
    /// Requires the stream to be stopped and belongs exclusively to bring-up.
    fn program_format(&mut self) {
        w16(self.sd + SDFMT, STREAM_FMT);
        let dac = self.dac;
        self.verb(dac, (0x2 << 16) | STREAM_FMT as u32); // Set Converter Format
        self.stop_corb_rirb();
        if DEBUG {
            crate::println!("hda: format fmt={:#06x}", STREAM_FMT);
        }
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

    fn apply_pending_output_route(&mut self) {
        if !OUTPUT_ROUTE_PENDING.swap(false, Ordering::Relaxed) {
            return;
        }

        let old_pin = self.pin;
        let old_dac = self.dac;
        let old_pin_def = self.pin_def;
        let old_path = self.path;
        let old_route = self.output_route;
        let old_available = AVAILABLE_OUTPUT_ROUTES.load(Ordering::Relaxed);
        let requested = OutputRoute::from_raw(REQUESTED_OUTPUT_ROUTE.load(Ordering::Relaxed));

        crate::println!(
            "hda: reprogram output {} -> {}",
            core::str::from_utf8(old_route.label()).unwrap_or("?"),
            core::str::from_utf8(requested.label()).unwrap_or("?")
        );
        log_available_output_routes("available output", old_available);

        self.setup_corb_rirb();
        if !self.select_cached_output_path(requested) || self.verb_failed {
            self.pin = old_pin;
            self.dac = old_dac;
            self.pin_def = old_pin_def;
            self.path = old_path;
            self.output_route = old_route;
            AVAILABLE_OUTPUT_ROUTES.store(old_available, Ordering::Relaxed);
            REQUESTED_OUTPUT_ROUTE.store(old_route as u8, Ordering::Relaxed);
            self.stop_corb_rirb();
            crate::println!(
                "hda: output route {} unavailable; retaining {}",
                core::str::from_utf8(requested.label()).unwrap_or("?"),
                core::str::from_utf8(old_route.label()).unwrap_or("?")
            );
            return;
        }

        if old_pin != self.pin {
            self.verb(old_pin, VERB_SET_PIN_WIDGET_CONTROL << 8);
        }
        if old_dac != self.dac {
            self.verb(old_dac, VERB_SET_CONV_STREAM_CHAN << 8);
        }
        self.configure_path();
        self.verb(self.dac, (0x2 << 16) | STREAM_FMT as u32);
        self.stop_corb_rirb();

        if self.verb_failed {
            let failed_pin = self.pin;
            let failed_dac = self.dac;
            self.pin = old_pin;
            self.dac = old_dac;
            self.pin_def = old_pin_def;
            self.path = old_path;
            self.output_route = old_route;
            AVAILABLE_OUTPUT_ROUTES.store(old_available, Ordering::Relaxed);
            REQUESTED_OUTPUT_ROUTE.store(old_route as u8, Ordering::Relaxed);

            // A timeout may be transient. Reinitialize the command rings and
            // put the last published route back before returning to playback.
            self.setup_corb_rirb();
            if failed_pin != old_pin {
                self.verb(failed_pin, VERB_SET_PIN_WIDGET_CONTROL << 8);
            }
            if failed_dac != old_dac {
                self.verb(failed_dac, VERB_SET_CONV_STREAM_CHAN << 8);
            }
            self.configure_path();
            self.verb(self.dac, (0x2 << 16) | STREAM_FMT as u32);
            self.stop_corb_rirb();
            if self.verb_failed {
                crate::println!(
                    "hda: output route {} reprogram failed; rollback failed; retaining {}",
                    core::str::from_utf8(requested.label()).unwrap_or("?"),
                    core::str::from_utf8(old_route.label()).unwrap_or("?")
                );
            } else {
                crate::println!(
                    "hda: output route {} reprogram timed out; restored {}",
                    core::str::from_utf8(requested.label()).unwrap_or("?"),
                    core::str::from_utf8(old_route.label()).unwrap_or("?")
                );
            }
        } else {
            OUTPUT_ROUTE.store(self.output_route as u8, Ordering::Relaxed);
            REQUESTED_OUTPUT_ROUTE.store(self.output_route as u8, Ordering::Relaxed);
            crate::println!(
                "hda: output route {} selected pin=nid{} dac=nid{}",
                core::str::from_utf8(self.output_route.label()).unwrap_or("?"),
                self.pin,
                self.dac
            );
        }
    }

    /// Frames the codec has played since the previous cursor poll.
    fn advance(&mut self) -> u64 {
        if !self.running {
            return 0;
        }
        let ring = (NUM_BUF * BUF_BYTES) as u32;
        let pos = r32(self.sd + SDLPIB) % ring;
        let delta = ((pos + ring - self.last_hw_pos) % ring) as u64;
        if delta != 0 {
            self.consumed_hw += delta;
            self.last_hw_pos = pos;
        }
        let played = self.consumed_hw / core::mem::size_of::<crate::kernel::sound::Frame>() as u64;
        let fresh = played.saturating_sub(self.reported);
        self.reported = played;
        fresh
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

fn output_route_for_widget(w: &Widget) -> OutputRoute {
    match default_device(w.def_cfg) {
        DEFAULT_DEVICE_SPEAKER => OutputRoute::Speaker,
        DEFAULT_DEVICE_HP_OUT => OutputRoute::Headphone,
        _ => OutputRoute::Jack,
    }
}

fn default_output_pin_score(w: &Widget) -> i32 {
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

fn output_pin_score(w: &Widget, route: OutputRoute) -> i32 {
    let mut score = default_output_pin_score(w);
    if score <= 0 || output_route_for_widget(w) != route {
        return -1;
    }
    match route {
        OutputRoute::Speaker => {
            score += 2_000;
            if default_port(w.def_cfg) == DEFAULT_PORT_FIXED {
                score += 2_000;
            }
        }
        OutputRoute::Jack => {
            if default_port(w.def_cfg) != DEFAULT_PORT_FIXED {
                score += 4_000;
            }
        }
        OutputRoute::Headphone => {
            score += 5_000;
        }
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

// ── the primitives the sink engine asks of a device ─────────────────────────

impl Hda {
    /// Split out the DMA memory capability before handing this device to the
    /// sink. The mapping is permanent and disjoint from the `Hda` object.
    pub fn ring(&mut self) -> &'static mut [crate::kernel::sound::Frame] {
        unsafe {
            core::slice::from_raw_parts_mut(
                (self.dma_va + BUF_OFF) as *mut crate::kernel::sound::Frame,
                RING_FRAMES,
            )
        }
    }
}

const fn stream_rate(fmt: u16) -> u32 {
    let base = if fmt & (1 << 14) == 0 { 48_000 } else { 44_100 };
    let multiplier = ((fmt >> 11) & 0x7) as u32 + 1;
    let divisor = ((fmt >> 8) & 0x7) as u32 + 1;
    base * multiplier / divisor
}

impl sound::sink::Device for Hda {
    fn rate(&self) -> u32 {
        stream_rate(STREAM_FMT)
    }

    fn block_frames(&self) -> usize {
        BUF_FRAMES
    }

    /// Start the stream. RUN and the stream tag go out as one dword so the
    /// controller re-evaluates the codec↔stream binding with the stream number
    /// visible.
    fn start(&mut self) {
        assert_eq!(
            r16(self.sd + SDFMT),
            STREAM_FMT,
            "HDA stream format was lost before RUN"
        );
        self.consumed_hw = 0;
        self.last_hw_pos = 0;
        self.reported = 0;
        w32(self.sd + SDCTL, 0x02 | (STREAM_TAG << 20));
        self.running = true;
        crate::println!(
            "hda: stream RUN sdctl={:#010x} cbl={} lvi={} fmt={:#06x} lpib={}",
            r32(self.sd + SDCTL), r32(self.sd + SDCBL), r16(self.sd + SDLVI),
            r16(self.sd + SDFMT), r32(self.sd + SDLPIB),
        );
    }

    fn pause(&mut self) {
        self.stop_playback();
    }

    fn service(&mut self) {
        self.apply_pending_output_route();
    }

    fn halt(&mut self) {
        self.stop_playback();
        self.stop_corb_rirb();
    }

    fn frames_played(&mut self) -> u64 {
        self.advance()
    }
}

/// Panic-path quiesce: stop all controller DMA and hold the link in reset so a
/// hard reboot from a panic doesn't leave the codec wedged (mid-stream resets
/// have left the ALC298 deaf to every OS until a cold power-off). Touches only
/// MMIO — no locks, no allocation — so it is safe from the panic handler even
/// even if normal sound code was interrupted.
pub fn emergency_quiesce() {
    if !BAR_MAPPED.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    stop_controller_dma();
    w32(GCTL, 0); // assert CRST: the codec rides out the reboot in reset
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widget(pin_caps: u32, port: u32, device: u32) -> Widget {
        Widget {
            pin_caps,
            def_cfg: (port << 30) | (device << 20),
            ..Widget::EMPTY
        }
    }

    #[test]
    fn output_route_defaults_and_labels() {
        assert_eq!(DEFAULT_OUTPUT_ROUTE, OutputRoute::Speaker);
        assert_eq!(OutputRoute::from_raw(0), OutputRoute::Speaker);
        assert_eq!(OutputRoute::from_raw(1), OutputRoute::Jack);
        assert_eq!(OutputRoute::from_raw(2), OutputRoute::Headphone);
        assert_eq!(OutputRoute::from_raw(3), OutputRoute::Speaker);
        assert_eq!(OutputRoute::Speaker.label(), b"Speaker");
        assert_eq!(OutputRoute::Jack.label(), b"Jack");
        assert_eq!(OutputRoute::Headphone.label(), b"Headphone");
    }

    #[test]
    fn output_route_cycles_in_both_directions() {
        assert_eq!(OutputRoute::Speaker.next(true), OutputRoute::Jack);
        assert_eq!(OutputRoute::Jack.next(true), OutputRoute::Headphone);
        assert_eq!(OutputRoute::Headphone.next(true), OutputRoute::Speaker);
        assert_eq!(OutputRoute::Speaker.next(false), OutputRoute::Headphone);
        assert_eq!(OutputRoute::Headphone.next(false), OutputRoute::Jack);
        assert_eq!(OutputRoute::Jack.next(false), OutputRoute::Speaker);
    }

    #[test]
    fn output_route_cycles_only_through_available_paths() {
        let speaker_and_headphone = OutputRoute::Speaker.bit() | OutputRoute::Headphone.bit();
        assert_eq!(
            OutputRoute::Speaker.next_available(true, speaker_and_headphone),
            OutputRoute::Headphone
        );
        assert_eq!(
            OutputRoute::Speaker.next_available(false, speaker_and_headphone),
            OutputRoute::Headphone
        );
        assert_eq!(
            OutputRoute::Speaker.next_available(true, OutputRoute::Speaker.bit()),
            OutputRoute::Speaker
        );
        assert_eq!(
            OutputRoute::Jack.next_available(true, 0),
            OutputRoute::Jack
        );
    }

    #[test]
    fn output_route_parser_accepts_canonical_and_mixed_case_values() {
        assert_eq!(parse_output_route(b"Speaker"), Some(OutputRoute::Speaker));
        assert_eq!(parse_output_route(b"jAcK"), Some(OutputRoute::Jack));
        assert_eq!(parse_output_route(b"HEADPHONE"), Some(OutputRoute::Headphone));
    }

    #[test]
    fn output_route_parser_rejects_non_values() {
        for value in [b"".as_slice(), b"Auto", b"1", b" Speaker", b"Jack ", b"Headphones", b"speaker=foo"] {
            assert_eq!(parse_output_route(value), None);
        }
    }

    #[test]
    fn output_pin_score_rejects_invalid_pins() {
        let no_output = widget(0, DEFAULT_PORT_FIXED, DEFAULT_DEVICE_SPEAKER);
        let disconnected = widget(PIN_CAP_OUT, DEFAULT_PORT_NONE, DEFAULT_DEVICE_SPEAKER);
        for route in OutputRoute::ALL {
            assert_eq!(output_pin_score(&no_output, route), -1);
            assert_eq!(output_pin_score(&disconnected, route), -1);
        }
    }

    #[test]
    fn output_routes_accept_only_matching_pin_classes() {
        let fixed_speaker = widget(PIN_CAP_OUT, DEFAULT_PORT_FIXED, DEFAULT_DEVICE_SPEAKER);
        let external_line = widget(PIN_CAP_OUT, 0, DEFAULT_DEVICE_LINE_OUT);
        let external_headphone = widget(PIN_CAP_OUT, 0, DEFAULT_DEVICE_HP_OUT);

        assert_eq!(output_route_for_widget(&fixed_speaker), OutputRoute::Speaker);
        assert_eq!(output_route_for_widget(&external_line), OutputRoute::Jack);
        assert_eq!(output_route_for_widget(&external_headphone), OutputRoute::Headphone);

        assert!(output_pin_score(&fixed_speaker, OutputRoute::Speaker) > 0);
        assert!(output_pin_score(&external_line, OutputRoute::Jack) > 0);
        assert!(output_pin_score(&external_headphone, OutputRoute::Headphone) > 0);
        assert_eq!(output_pin_score(&external_line, OutputRoute::Speaker), -1);
        assert_eq!(output_pin_score(&external_line, OutputRoute::Headphone), -1);
        assert_eq!(output_pin_score(&external_headphone, OutputRoute::Jack), -1);
    }
}
