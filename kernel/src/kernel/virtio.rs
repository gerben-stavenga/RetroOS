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

/// Kernel device-mapping window. Sits at the top of pt_kernel's pre-
/// mapped 2 MB range (0xC0A00000-0xC0BFFFFF), leaving ~30 pages below
/// for kernel image growth. Used for both MMIO BAR mappings
/// (uncached) and DMA-shared kernel pages (cached). Bump-allocated;
/// never freed in this prototype.
const DEVICE_VBASE: usize = 0xC0BF_0000;
const DEVICE_PAGES: usize = 16; // 64 KB
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
