//! Modern virtio-pci (1.x) transport: device discovery + capability
//! parsing.
//!
//! Virtio 1.x splits its hardware interface across four configuration
//! regions, each located via a PCI vendor-specific capability (cap ID
//! 0x09) tagged with a `cfg_type` byte:
//!
//! ```text
//!   cfg_type 1 = COMMON     device + queue control registers
//!   cfg_type 2 = NOTIFY     doorbell window (one offset per queue)
//!   cfg_type 3 = ISR        interrupt status (legacy IRQ)
//!   cfg_type 4 = DEVICE     device-class-specific config block
//!   cfg_type 5 = PCI_CFG    alternate access via PCI config space
//! ```
//!
//! Each capability descriptor (after the 2-byte cap id + next header)
//! carries: cap length, cfg_type, BAR number, padding, offset, length.
//! The NOTIFY cap has an extra `notify_off_multiplier` u32 appended.
//!
//! This module discovers virtio devices and records WHERE their config
//! regions live. It does not yet map the BARs or speak the virtio
//! protocol — that comes in the next layer.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kernel::pci::{self, Bar, PciAddr, PciDevice};
use crate::kernel::pci::{read_config_u8, read_config_u32};

/// Process-global audio sink: the initialized virtio-sound device.
/// Set once at boot in `log_device`; subsequently used by the DOS SB
/// façade to push PCM. None until init succeeds; never set back to
/// None after that.
static mut AUDIO_SINK: Option<VirtioDevice> = None;

/// Reusable phys-contig buffer for SB→virtio PCM submission. Filled
/// per call by the SB façade's format-conversion code; passed to
/// `snd_tx`. Allocated lazily on first use.
static mut PCM_OUT_VIRT: *mut u8 = core::ptr::null_mut();
static mut PCM_OUT_PHYS: u64 = 0;

/// Take an exclusive reference to the audio sink, if it's been
/// initialized. Returns `None` before virtio-sound init completes
/// (or if it failed). Safety: caller is the only one accessing the
/// device — we're single-threaded inside DOS port traps.
pub fn audio_sink() -> Option<&'static mut VirtioDevice> {
    unsafe { (*core::ptr::addr_of_mut!(AUDIO_SINK)).as_mut() }
}

/// Get (or lazily allocate) the kernel-side PCM output buffer.
/// Returns `(virt, phys)`. One 4 KB page — enough for one period of
/// S16 stereo at 44.1 kHz (1024 frames = ~23 ms).
pub fn pcm_out_buf() -> Option<(*mut u8, u64)> {
    unsafe {
        if PCM_OUT_VIRT.is_null() {
            let (v, p) = alloc_dma_page()?;
            PCM_OUT_VIRT = v;
            PCM_OUT_PHYS = p;
        }
        Some((PCM_OUT_VIRT, PCM_OUT_PHYS))
    }
}

/// Kernel device-mapping window. Lives in PDPT[6]'s dedicated PT
/// (pt_dev, 0xC0C00000-0xC0DFFFFF) — deliberately OUTSIDE pt_kernel,
/// so the kernel heap (which grows up through pt_kernel) can never
/// demand-page over a PCI BAR / DMA-buffer mapping. Used for both
/// MMIO BAR mappings (uncached) and DMA-shared kernel pages (cached).
/// Bump-allocated; never freed in this prototype.
const DEVICE_VBASE: usize = 0xC0C0_0000;
const DEVICE_PAGES: usize = 256; // 1 MB (pt_dev's range is 2 MB)
static NEXT_DEVICE_VPAGE: AtomicUsize = AtomicUsize::new(DEVICE_VBASE / 4096);

fn bump_device_vpages(num_pages: usize) -> usize {
    let start = NEXT_DEVICE_VPAGE.fetch_add(num_pages, Ordering::Relaxed);
    let limit = (DEVICE_VBASE + DEVICE_PAGES * 4096) / 4096;
    assert!(start + num_pages <= limit, "kernel device window exhausted");
    start
}

/// Map `num_pages` physical pages into the kernel device window with
/// MMIO flags (uncached, supervisor-only, writable). Returns a kernel
/// pointer to the first byte.
fn map_mmio_pages(ppage_start: u64, num_pages: usize) -> *mut u8 {
    let start = bump_device_vpages(num_pages);
    use crate::arch::page_flags::{READ_WRITE, WRITE_THROUGH, CACHE_DISABLE};
    crate::kernel::startup::arch_map_phys_range(
        start, num_pages, ppage_start,
        READ_WRITE | WRITE_THROUGH | CACHE_DISABLE,
    );
    (start * 4096) as *mut u8
}

/// Allocate one physical page from the arch allocator and map it into
/// the kernel device window with cached, supervisor-only, writable
/// flags. Returns `(kernel_virt_ptr, phys_addr_bytes)` — the phys
/// half is what gets handed to a device's DMA registers; the virt
/// half is what kernel code reads/writes. None on out-of-memory.
fn alloc_dma_page() -> Option<(*mut u8, u64)> {
    let ppage = crate::kernel::startup::arch_alloc_phys_page()?;
    let vpage = bump_device_vpages(1);
    use crate::arch::page_flags::READ_WRITE;
    crate::kernel::startup::arch_map_phys_range(
        vpage, 1, ppage as u64, READ_WRITE,
    );
    let ptr = (vpage * 4096) as *mut u8;
    // Zero the page so freshly-allocated descriptor tables / rings
    // start in a known state.
    unsafe { core::ptr::write_bytes(ptr, 0, 4096); }
    Some((ptr, (ppage as u64) * 4096))
}

const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Modern virtio device IDs sit in 0x1040..=0x107F; the low 6 bits are
/// the virtio device-type number (1=net, 2=blk, ..., 25=sound).
const VIRTIO_MODERN_BASE: u16 = 0x1040;
const VIRTIO_MODERN_END: u16 = 0x1080;

/// PCI vendor-specific capability ID — virtio caps use this with a
/// per-cap `cfg_type` discriminator at byte 3.
const PCI_CAP_VENDOR_SPECIFIC: u8 = 0x09;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VirtioCfgType {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
    PciCfg = 5,
}

impl VirtioCfgType {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Common,
            2 => Self::Notify,
            3 => Self::Isr,
            4 => Self::Device,
            5 => Self::PciCfg,
            _ => return None,
        })
    }
}

/// One discovered virtio capability region.
#[derive(Clone, Copy, Debug)]
pub struct VirtioCap {
    pub cfg_type: VirtioCfgType,
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    /// Only meaningful for `Notify`: per the spec, the doorbell address
    /// for queue Q is `cap.offset + queue_notify_off(Q) * multiplier`.
    pub notify_off_multiplier: u32,
}

/// A discovered modern virtio-pci device with its config-region map.
/// Not yet attached / initialized — just a parsed descriptor.
pub struct VirtioPciDevice {
    pub addr: PciAddr,
    pub device_id: u16,
    pub caps: Vec<VirtioCap>,
}

impl VirtioPciDevice {
    /// Virtio device-type number (1=net, 2=blk, ..., 25=sound) derived
    /// from the modern device-id encoding.
    pub fn device_type(&self) -> u16 {
        self.device_id.wrapping_sub(VIRTIO_MODERN_BASE)
    }

    pub fn find_cap(&self, cfg_type: VirtioCfgType) -> Option<&VirtioCap> {
        self.caps.iter().find(|c| c.cfg_type == cfg_type)
    }

    /// Map a capability region into kernel MMIO space and return a
    /// pointer to its first byte. Returns None if the cap isn't present
    /// or its BAR isn't memory-mapped.
    pub fn map_cap(&self, cfg_type: VirtioCfgType) -> Option<*mut u8> {
        let cap = self.find_cap(cfg_type)?;
        let bar_base = bar_phys_base(self.addr, cap.bar)?;
        let region_phys = bar_base.wrapping_add(cap.offset as u64);
        let first_page = region_phys & !((crate::arch::PAGE_SIZE as u64) - 1);
        let intra_off = (region_phys - first_page) as usize;
        let span = intra_off + cap.length as usize;
        let pages = span.div_ceil(crate::arch::PAGE_SIZE);
        let base_va = map_mmio_pages(first_page >> 12, pages);
        Some(unsafe { base_va.add(intra_off) })
    }
}

fn bar_phys_base(addr: PciAddr, bar_idx: u8) -> Option<u64> {
    match pci::read_bar(addr, bar_idx)?.0 {
        Bar::Mem32 { base, .. } => Some(base as u64),
        Bar::Mem64 { base, .. } => Some(base),
        Bar::Io { .. } => None,
    }
}

/// Common configuration block (virtio 1.x §4.1.4.3). The first region
/// every virtio driver consults: feature bits, queue count, device
/// status, plus per-queue control via the `queue_select` window.
///
/// All accesses must be volatile — the device updates fields between
/// our reads, and our writes are commands.
#[repr(C)]
pub struct CommonCfg {
    pub device_feature_select: u32,
    pub device_feature: u32,
    pub driver_feature_select: u32,
    pub driver_feature: u32,
    pub msix_config: u16,
    pub num_queues: u16,
    pub device_status: u8,
    pub config_generation: u8,
    pub queue_select: u16,
    pub queue_size: u16,
    pub queue_msix_vector: u16,
    pub queue_enable: u16,
    pub queue_notify_off: u16,
    pub queue_desc: u64,
    pub queue_driver: u64,
    pub queue_device: u64,
}

// =============================================================================
// Virtqueue (virtio 1.x §2.6)
// =============================================================================
//
// Each virtqueue is three shared-memory areas:
//
//   1. Descriptor table: array of (phys_addr, len, flags, next).
//   2. Available ring:   driver→device "process these descriptor heads".
//   3. Used ring:        device→driver "I'm done with these heads".
//
// We pack all three into a single 4 KB phys-contig page for queue
// sizes up to ~128 entries (4 KB / (16+2+8) ≈ 156). Layout within
// the page (queue_size = N):
//
//   offset 0                  desc table:  N * 16 = up to 2048 B
//   offset 0x800              avail ring:  6 + 2N + 2  bytes
//   offset 0xC00              used ring:   6 + 8N + 2 bytes
//
// All three structures need natural alignment; 16/0x800/0xC00 are
// generously aligned for the sizes we use.

const QUEUE_SIZE: u16 = 64;

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
#[allow(dead_code)] const DESC_F_INDIRECT: u16 = 4;

const AVAIL_OFFSET: usize = 0x800;
const USED_OFFSET: usize = 0xC00;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE as usize],
    pub used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE as usize],
    pub avail_event: u16,
}

/// One allocated virtqueue (descriptor table + avail + used) in a
/// single phys-contig 4 KB page.
pub struct Virtqueue {
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    /// Physical address of the descriptor table (= page base; avail
    /// and used are at fixed offsets above this).
    pub desc_phys: u64,
    /// Driver-side index of the next position to fill in the avail
    /// ring and the next used-elem we haven't yet processed.
    next_avail: u16,
    last_used: u16,
}

impl Virtqueue {
    pub const SIZE: u16 = QUEUE_SIZE;

    /// Allocate a fresh virtqueue page and lay out the three rings in
    /// it. Returns None if phys allocation fails.
    pub fn new() -> Option<Self> {
        let (virt, phys) = alloc_dma_page()?;
        let desc = virt as *mut VirtqDesc;
        let avail = unsafe { virt.add(AVAIL_OFFSET) as *mut VirtqAvail };
        let used = unsafe { virt.add(USED_OFFSET) as *mut VirtqUsed };
        Some(Self {
            desc, avail, used,
            desc_phys: phys,
            next_avail: 0,
            last_used: 0,
        })
    }

    pub fn avail_phys(&self) -> u64 { self.desc_phys + AVAIL_OFFSET as u64 }
    pub fn used_phys(&self) -> u64 { self.desc_phys + USED_OFFSET as u64 }

    /// Write a single descriptor (one-buffer transfer, no chaining).
    /// `idx` is the slot in the descriptor table (caller's choice;
    /// for simple cases, just `next_avail`).
    pub fn write_desc(&mut self, idx: u16, addr: u64, len: u32, write: bool) {
        let d = VirtqDesc {
            addr, len,
            flags: if write { DESC_F_WRITE } else { 0 },
            next: 0,
        };
        unsafe { write_volatile(self.desc.add(idx as usize), d); }
    }

    /// Add descriptor head `idx` to the avail ring and bump the
    /// driver-visible avail index. Doesn't notify the device.
    pub fn publish_avail(&mut self, idx: u16) {
        unsafe {
            let slot = self.next_avail % QUEUE_SIZE;
            write_volatile(
                core::ptr::addr_of_mut!((*self.avail).ring[slot as usize]),
                idx,
            );
            self.next_avail = self.next_avail.wrapping_add(1);
            // Memory barrier: the device must see the ring entry
            // before it sees the bumped idx. On x86 plain stores are
            // already store-ordered, but emit a compiler fence to
            // keep the optimizer from reordering across the bump.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            write_volatile(
                core::ptr::addr_of_mut!((*self.avail).idx),
                self.next_avail,
            );
        }
    }

    /// Read the device-published used-ring head index. Returns the
    /// next used-elem if there's one we haven't processed yet, else
    /// None.
    pub fn pop_used(&mut self) -> Option<VirtqUsedElem> {
        let device_idx = unsafe {
            read_volatile(core::ptr::addr_of!((*self.used).idx))
        };
        if device_idx == self.last_used {
            return None;
        }
        let slot = self.last_used % QUEUE_SIZE;
        let elem = unsafe {
            read_volatile(core::ptr::addr_of!((*self.used).ring[slot as usize]))
        };
        self.last_used = self.last_used.wrapping_add(1);
        Some(elem)
    }
}

// =============================================================================
// Common config (virtio 1.x §4.1.4.3)
// =============================================================================

// Device status bits (virtio 1.x §2.1).
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const STATUS_FAILED: u8 = 128;

// Transport feature bits we care about.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Volatile-read wrapper around a mapped CommonCfg pointer.
pub struct CommonCfgRegs(*mut CommonCfg);

impl CommonCfgRegs {
    pub fn from_ptr(p: *mut u8) -> Self {
        Self(p as *mut CommonCfg)
    }

    pub fn num_queues(&self) -> u16 {
        unsafe { read_volatile(core::ptr::addr_of!((*self.0).num_queues)) }
    }

    pub fn device_status(&self) -> u8 {
        unsafe { read_volatile(core::ptr::addr_of!((*self.0).device_status)) }
    }

    pub fn set_device_status(&self, v: u8) {
        unsafe { write_volatile(core::ptr::addr_of_mut!((*self.0).device_status), v) }
    }

    pub fn config_generation(&self) -> u8 {
        unsafe { read_volatile(core::ptr::addr_of!((*self.0).config_generation)) }
    }

    /// Read the device-advertised feature bits for word `select`
    /// (0 = features 0..32, 1 = features 32..64).
    pub fn read_device_features(&self, select: u32) -> u32 {
        unsafe {
            write_volatile(core::ptr::addr_of_mut!((*self.0).device_feature_select), select);
            read_volatile(core::ptr::addr_of!((*self.0).device_feature))
        }
    }

    /// Write the driver's chosen feature bits for word `select`.
    pub fn write_driver_features(&self, select: u32, value: u32) {
        unsafe {
            write_volatile(core::ptr::addr_of_mut!((*self.0).driver_feature_select), select);
            write_volatile(core::ptr::addr_of_mut!((*self.0).driver_feature), value);
        }
    }

    /// Select a virtqueue for subsequent per-queue register accesses.
    pub fn select_queue(&self, q: u16) {
        unsafe {
            write_volatile(core::ptr::addr_of_mut!((*self.0).queue_select), q);
        }
    }

    /// Read the selected queue's max supported size (= device's
    /// suggestion; we can shrink by writing a smaller value back).
    pub fn queue_size(&self) -> u16 {
        unsafe { read_volatile(core::ptr::addr_of!((*self.0).queue_size)) }
    }

    pub fn set_queue_size(&self, n: u16) {
        unsafe { write_volatile(core::ptr::addr_of_mut!((*self.0).queue_size), n); }
    }

    /// Read the per-queue notify offset used for doorbell address
    /// computation (`notify_base + notify_off * multiplier`).
    pub fn queue_notify_off(&self) -> u16 {
        unsafe { read_volatile(core::ptr::addr_of!((*self.0).queue_notify_off)) }
    }

    pub fn set_queue_addrs(&self, desc: u64, driver: u64, device: u64) {
        unsafe {
            write_volatile(core::ptr::addr_of_mut!((*self.0).queue_desc), desc);
            write_volatile(core::ptr::addr_of_mut!((*self.0).queue_driver), driver);
            write_volatile(core::ptr::addr_of_mut!((*self.0).queue_device), device);
        }
    }

    pub fn enable_queue(&self) {
        unsafe { write_volatile(core::ptr::addr_of_mut!((*self.0).queue_enable), 1); }
    }
}

/// A virtio device that has completed the init handshake. Holds its
/// common-config window, the notify region, one virtqueue per
/// declared queue index, and per-queue notify offsets.
pub struct VirtioDevice {
    pub cfg: CommonCfgRegs,
    pub queues: Vec<Virtqueue>,
    notify_base: *mut u8,
    notify_off_mult: u32,
    /// Per-queue `queue_notify_off`, captured at init while we held
    /// the queue selection. Doorbell address for queue Q is
    /// `notify_base + queue_notify_off[Q] * notify_off_mult`.
    queue_notify_off: Vec<u16>,
}

impl VirtioDevice {
    /// Ring the doorbell for queue `q`. Writes the queue index as a
    /// u16 to the queue's notify slot (per virtio 1.x §4.1.5.2; since
    /// we didn't negotiate VIRTIO_F_NOTIFICATION_DATA, the value is
    /// just the queue index).
    pub fn notify(&self, q: u16) {
        let offset = self.queue_notify_off[q as usize] as u32 * self.notify_off_mult;
        let addr = unsafe { self.notify_base.add(offset as usize) as *mut u16 };
        unsafe { write_volatile(addr, q); }
    }
}

/// Run the virtio 1.x init protocol: reset → ACKNOWLEDGE → DRIVER →
/// negotiate features (we require VIRTIO_F_VERSION_1, reject all
/// else) → FEATURES_OK → allocate every advertised queue and write
/// its phys addresses → enable queues → DRIVER_OK.
///
/// Returns the live device on success. On any failure, sets STATUS_
/// FAILED on the device and returns None — the device will need a
/// fresh reset before another attempt.
pub fn init_device(d: &VirtioPciDevice) -> Option<VirtioDevice> {
    let common_ptr = d.map_cap(VirtioCfgType::Common)?;
    let cfg = CommonCfgRegs::from_ptr(common_ptr);

    // (1) reset
    cfg.set_device_status(0);
    while cfg.device_status() != 0 {}

    // (2,3) acknowledge + driver
    cfg.set_device_status(STATUS_ACKNOWLEDGE);
    cfg.set_device_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // (4,5) negotiate features. We require VERSION_1 (bit 32) and
    // explicitly accept *only* that bit. Everything else (event-idx,
    // packed-ring, indirect-desc, etc.) is left disabled for
    // simplicity in this first cut.
    let dev_lo = cfg.read_device_features(0);
    let dev_hi = cfg.read_device_features(1);
    if dev_hi & (1 << 0) == 0 {
        crate::println!("virtio: device doesn't advertise VERSION_1 — bailing");
        cfg.set_device_status(STATUS_FAILED);
        return None;
    }
    cfg.write_driver_features(0, 0);
    cfg.write_driver_features(1, 1); // just VIRTIO_F_VERSION_1

    // (6,7) features_ok + verify
    cfg.set_device_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if cfg.device_status() & STATUS_FEATURES_OK == 0 {
        crate::println!("virtio: FEATURES_OK rejected (device wanted features we declined)");
        cfg.set_device_status(STATUS_FAILED);
        return None;
    }
    let _ = (dev_lo, dev_hi); // for logging if we want it later

    // Notify region — needed for doorbells. Map alongside common.
    let notify_base = d.map_cap(VirtioCfgType::Notify)?;
    let notify_off_mult = d.find_cap(VirtioCfgType::Notify)?.notify_off_multiplier;

    // (8) allocate queues. virtio-sound has 4: control, event, TX, RX.
    let nq = cfg.num_queues();
    let mut queues = Vec::with_capacity(nq as usize);
    let mut queue_notify_off = Vec::with_capacity(nq as usize);
    for q in 0..nq {
        cfg.select_queue(q);
        let dev_max = cfg.queue_size();
        let our_size = QUEUE_SIZE.min(dev_max);
        cfg.set_queue_size(our_size);
        let vq = Virtqueue::new()?;
        cfg.set_queue_addrs(vq.desc_phys, vq.avail_phys(), vq.used_phys());
        queue_notify_off.push(cfg.queue_notify_off());
        cfg.enable_queue();
        queues.push(vq);
    }

    // (9) driver_ok — device is live.
    cfg.set_device_status(
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );

    Some(VirtioDevice { cfg, queues, notify_base, notify_off_mult, queue_notify_off })
}

/// Try to recognize a PCI device as a modern virtio device and parse
/// its capability list. Returns None for non-virtio devices or for
/// transitional/legacy virtio (device IDs 0x1000-0x103F).
pub fn try_attach(pci: &PciDevice) -> Option<VirtioPciDevice> {
    if pci.vendor != VIRTIO_VENDOR {
        return None;
    }
    if pci.device < VIRTIO_MODERN_BASE || pci.device >= VIRTIO_MODERN_END {
        return None;
    }
    let mut caps = Vec::new();
    for cap_off in pci::capabilities(pci.addr) {
        let cap_id = read_config_u8(pci.addr, cap_off);
        if cap_id != PCI_CAP_VENDOR_SPECIFIC {
            continue;
        }
        // Cap layout (per virtio 1.x §4.1.4.1):
        //   +0 cap_vndr (0x09)
        //   +1 cap_next
        //   +2 cap_len
        //   +3 cfg_type
        //   +4 bar
        //   +5..+8 padding / id
        //   +8 offset (u32)
        //   +12 length (u32)
        //   +16 notify_off_multiplier (u32, NOTIFY only)
        let cfg_byte = read_config_u8(pci.addr, cap_off + 3);
        let Some(cfg_type) = VirtioCfgType::from_byte(cfg_byte) else { continue };
        let bar = read_config_u8(pci.addr, cap_off + 4);
        let offset = read_config_u32(pci.addr, cap_off + 8);
        let length = read_config_u32(pci.addr, cap_off + 12);
        let notify_off_multiplier = if cfg_type == VirtioCfgType::Notify {
            read_config_u32(pci.addr, cap_off + 16)
        } else {
            0
        };
        caps.push(VirtioCap { cfg_type, bar, offset, length, notify_off_multiplier });
    }
    Some(VirtioPciDevice { addr: pci.addr, device_id: pci.device, caps })
}

/// Debugcon dump of a discovered virtio device's capability map and
/// BAR layout. For diagnostic logging at boot.
pub fn log_device(d: &VirtioPciDevice) {
    let kind = device_kind_name(d.device_type());
    crate::println!(
        "  virtio {:02x}:{:02x}.{}  device_id={:04x} ({}, type {})  caps={}",
        d.addr.bus, d.addr.device, d.addr.function,
        d.device_id, kind, d.device_type(), d.caps.len(),
    );
    for cap in &d.caps {
        let suffix = if cap.cfg_type == VirtioCfgType::Notify {
            alloc::format!(" notify_mult={}", cap.notify_off_multiplier)
        } else {
            alloc::string::String::new()
        };
        crate::println!(
            "    {:?} bar{} offset={:#x} length={:#x}{}",
            cap.cfg_type, cap.bar, cap.offset, cap.length, suffix,
        );
    }
    let mut idx = 0u8;
    while idx < 6 {
        match pci::read_bar(d.addr, idx) {
            None => {
                idx += 1;
            }
            Some((bar, consumed)) => {
                match bar {
                    Bar::Mem32 { base, prefetchable } => crate::println!(
                        "    bar{}: mem32 base={:#010x}{}",
                        idx, base, if prefetchable { " (prefetch)" } else { "" },
                    ),
                    Bar::Mem64 { base, prefetchable } => crate::println!(
                        "    bar{}: mem64 base={:#x}{}",
                        idx, base, if prefetchable { " (prefetch)" } else { "" },
                    ),
                    Bar::Io { port } => crate::println!(
                        "    bar{}: io port={:#x}", idx, port,
                    ),
                }
                idx += consumed;
            }
        }
    }
    // Map COMMON cfg and dump the registers the driver will care about.
    if let Some(p) = d.map_cap(VirtioCfgType::Common) {
        let cfg = CommonCfgRegs::from_ptr(p);
        let feat_lo = cfg.read_device_features(0);
        let feat_hi = cfg.read_device_features(1);
        crate::println!(
            "    common: num_queues={} device_status={:#x} config_gen={} features={:08x}_{:08x}",
            cfg.num_queues(), cfg.device_status(), cfg.config_generation(),
            feat_hi, feat_lo,
        );
    }

    // Only the virtio-sound device becomes the audio sink. (Future:
    // dispatch by device_type when we add virtio-net etc.)
    if d.device_type() != 25 {
        return;
    }
    // Drive the init handshake. After this completes, device_status
    // should read 0xF (ACK|DRIVER|FEATURES_OK|DRIVER_OK).
    if let Some(mut dev) = init_device(d) {
        crate::println!(
            "    init: OK — device_status={:#x}, {} queues attached",
            dev.cfg.device_status(), dev.queues.len(),
        );
        // Try the control-queue protocol on stream 0 (the first PCM
        // output). 44.1 kHz, signed 16-bit stereo — QEMU's
        // virtio-sound rejects U8/mono with "Stream format is not
        // supported" so we use the format most virtual audio backends
        // do support. 4 KB single-period for now.
        let set_ok = dev.snd_set_params(0, 4096, 4096, 2, SND_PCM_FMT_S16, SND_PCM_RATE_44100);
        let prep_ok = if set_ok { dev.snd_prepare(0) } else { false };
        let start_ok = if prep_ok { dev.snd_start(0) } else { false };
        crate::println!(
            "    snd ctl: SET_PARAMS={} PREPARE={} START={}",
            set_ok, prep_ok, start_ok,
        );
        // If the stream is running, push one period (~23 ms) of a
        // 440 Hz square wave so something audible comes out of the
        // host audio backend.
        if start_ok {
            if let Some((buf_virt, buf_phys)) = alloc_dma_page() {
                const PERIOD_BYTES: u32 = 4096;
                const FRAMES: usize = (PERIOD_BYTES as usize) / 4;
                const SAMPLE_RATE: usize = 44100;
                const FREQ: usize = 440;
                const HALF_PERIOD: usize = SAMPLE_RATE / (2 * FREQ); // ≈ 50 samples
                const AMPLITUDE: i16 = 8000;
                let samples = buf_virt as *mut i16;
                unsafe {
                    for i in 0..FRAMES {
                        let val = if (i / HALF_PERIOD) & 1 == 0 { AMPLITUDE } else { -AMPLITUDE };
                        core::ptr::write_volatile(samples.add(2 * i), val);     // L
                        core::ptr::write_volatile(samples.add(2 * i + 1), val); // R
                    }
                }
                match dev.snd_tx(0, buf_phys, PERIOD_BYTES) {
                    Some(s) => crate::println!("    snd tx: status={:#x}", s),
                    None => crate::println!("    snd tx: dma alloc failed"),
                }
            }
        }
        // Stash for the SB façade to push PCM into later.
        unsafe { AUDIO_SINK = Some(dev); }
    } else {
        crate::println!("    init: FAILED");
    }
}

// =============================================================================
// virtio-sound protocol (subset enough for one-stream playback)
// =============================================================================

// Queue indices per virtio-sound spec §5.14.2.
pub const SND_Q_CTL: usize = 0;
#[allow(dead_code)] pub const SND_Q_EVT: usize = 1;
pub const SND_Q_TX: usize = 2;
#[allow(dead_code)] pub const SND_Q_RX: usize = 3;

// Control-queue request codes (subset).
const SND_R_PCM_INFO: u32 = 0x0100;
const SND_R_PCM_SET_PARAMS: u32 = 0x0101;
const SND_R_PCM_PREPARE: u32 = 0x0102;
#[allow(dead_code)] const SND_R_PCM_RELEASE: u32 = 0x0103;
const SND_R_PCM_START: u32 = 0x0104;
#[allow(dead_code)] const SND_R_PCM_STOP: u32 = 0x0105;

// Response status codes.
const SND_S_OK: u32 = 0x8000;

// Format codes for SET_PARAMS.
const SND_PCM_FMT_U8: u8 = 1;
#[allow(dead_code)] const SND_PCM_FMT_S16: u8 = 5;

// Rate codes for SET_PARAMS.
#[allow(dead_code)] const SND_PCM_RATE_8000: u8 = 0;
const SND_PCM_RATE_22050: u8 = 4;
#[allow(dead_code)] const SND_PCM_RATE_44100: u8 = 6;
#[allow(dead_code)] const SND_PCM_RATE_48000: u8 = 7;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SndHdr { code: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SndPcmHdr { hdr: SndHdr, stream_id: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SndPcmSetParams {
    pcm_hdr: SndPcmHdr,
    buffer_bytes: u32,
    period_bytes: u32,
    features: u32,
    channels: u8,
    format: u8,
    rate: u8,
    padding: u8,
}

impl VirtioDevice {
    /// Submit one request → response on the control queue, polling
    /// the used ring until the device completes. Both buffers live
    /// in a freshly-allocated DMA page; the page is leaked (one per
    /// command) since this is one-shot init-time work.
    ///
    /// Returns the device's reply status code (`SND_S_OK` on success).
    fn ctl_submit<Req: Copy>(&mut self, req: &Req) -> Option<u32> {
        let req_size = core::mem::size_of::<Req>() as u32;
        let resp_size = core::mem::size_of::<SndHdr>() as u32;
        let (buf_virt, buf_phys) = alloc_dma_page()?;
        unsafe {
            // Write request at offset 0, zero response slot at +req_size.
            core::ptr::write_volatile(buf_virt as *mut Req, *req);
            core::ptr::write_volatile(
                buf_virt.add(req_size as usize) as *mut SndHdr,
                SndHdr { code: 0 },
            );
        }
        // Two-descriptor chain: [0]=read req, [1]=write response.
        let q = &mut self.queues[SND_Q_CTL];
        q.write_desc(0, buf_phys, req_size, false);
        // For chaining, desc 0 needs NEXT flag pointing at desc 1.
        // Rewrite slot 0 with NEXT|next=1, then write slot 1.
        unsafe {
            write_volatile(q.desc.add(0), VirtqDesc {
                addr: buf_phys, len: req_size,
                flags: DESC_F_NEXT, next: 1,
            });
            write_volatile(q.desc.add(1), VirtqDesc {
                addr: buf_phys + req_size as u64, len: resp_size,
                flags: DESC_F_WRITE, next: 0,
            });
        }
        q.publish_avail(0);
        self.notify(SND_Q_CTL as u16);
        // Poll until completion. No timeout for now — if the device
        // never replies we'd hang here; acceptable for a first cut.
        loop {
            if let Some(elem) = self.queues[SND_Q_CTL].pop_used() {
                let _ = elem;
                let resp = unsafe {
                    read_volatile(buf_virt.add(req_size as usize) as *const SndHdr)
                };
                return Some(resp.code);
            }
        }
    }

    /// Issue `SET_PARAMS` for `stream_id`. Returns true on OK.
    pub fn snd_set_params(
        &mut self, stream_id: u32,
        buffer_bytes: u32, period_bytes: u32,
        channels: u8, format: u8, rate: u8,
    ) -> bool {
        let req = SndPcmSetParams {
            pcm_hdr: SndPcmHdr {
                hdr: SndHdr { code: SND_R_PCM_SET_PARAMS },
                stream_id,
            },
            buffer_bytes, period_bytes,
            features: 0,
            channels, format, rate, padding: 0,
        };
        self.ctl_submit(&req).map_or(false, |s| s == SND_S_OK)
    }

    /// Issue `PCM_PREPARE` for `stream_id`.
    pub fn snd_prepare(&mut self, stream_id: u32) -> bool {
        let req = SndPcmHdr { hdr: SndHdr { code: SND_R_PCM_PREPARE }, stream_id };
        self.ctl_submit(&req).map_or(false, |s| s == SND_S_OK)
    }

    /// Issue `PCM_START` for `stream_id`.
    pub fn snd_start(&mut self, stream_id: u32) -> bool {
        let req = SndPcmHdr { hdr: SndHdr { code: SND_R_PCM_START }, stream_id };
        self.ctl_submit(&req).map_or(false, |s| s == SND_S_OK)
    }

    /// Submit one period of PCM samples on the TX queue and poll
    /// for completion. The buffer is read by the device and dropped
    /// once the period has been consumed by the audio backend.
    ///
    /// `audio_phys` must be a phys-contig region of `audio_len`
    /// bytes that the device can DMA from. The caller fills it with
    /// `period_bytes` worth of samples in the format set up by
    /// `snd_set_params` (S16 LE, channel-interleaved).
    pub fn snd_tx(&mut self, stream_id: u32, audio_phys: u64, audio_len: u32) -> Option<u32> {
        // Scratch page for xfer header (at offset 0) and pcm_status
        // (at offset 64). 64-byte separation is generous; only the
        // first 4 + 8 bytes are touched but having them in distinct
        // cachelines avoids any false-sharing fuss.
        let (hdr_virt, hdr_phys) = alloc_dma_page()?;
        const STATUS_OFF: usize = 64;
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct SndPcmXfer { stream_id: u32 }
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct SndPcmStatus { status: u32, latency_bytes: u32 }
        unsafe {
            write_volatile(hdr_virt as *mut SndPcmXfer, SndPcmXfer { stream_id });
            write_volatile(
                hdr_virt.add(STATUS_OFF) as *mut SndPcmStatus,
                SndPcmStatus { status: 0, latency_bytes: 0 },
            );
        }
        let q = &mut self.queues[SND_Q_TX];
        unsafe {
            // desc[0]: xfer header (read by device, has NEXT).
            write_volatile(q.desc.add(0), VirtqDesc {
                addr: hdr_phys,
                len: core::mem::size_of::<SndPcmXfer>() as u32,
                flags: DESC_F_NEXT, next: 1,
            });
            // desc[1]: audio data (read by device, has NEXT).
            write_volatile(q.desc.add(1), VirtqDesc {
                addr: audio_phys,
                len: audio_len,
                flags: DESC_F_NEXT, next: 2,
            });
            // desc[2]: pcm_status (written by device, last in chain).
            write_volatile(q.desc.add(2), VirtqDesc {
                addr: hdr_phys + STATUS_OFF as u64,
                len: core::mem::size_of::<SndPcmStatus>() as u32,
                flags: DESC_F_WRITE, next: 0,
            });
        }
        q.publish_avail(0);
        self.notify(SND_Q_TX as u16);
        // Poll TX used ring. Device completes after consuming the
        // period (or on stop/error).
        loop {
            if let Some(_elem) = self.queues[SND_Q_TX].pop_used() {
                let st = unsafe {
                    read_volatile(hdr_virt.add(STATUS_OFF) as *const SndPcmStatus)
                };
                return Some(st.status);
            }
        }
    }
}

/// Map of modern virtio device-type numbers to short names. Only the
/// ones we might plausibly encounter on QEMU.
fn device_kind_name(t: u16) -> &'static str {
    match t {
        1 => "net",
        2 => "blk",
        3 => "console",
        4 => "rng",
        5 => "balloon",
        9 => "9p",
        16 => "gpu",
        18 => "input",
        19 => "vsock",
        25 => "sound",
        _ => "?",
    }
}
