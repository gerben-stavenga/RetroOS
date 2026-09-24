//! Compact xHCI USB host-controller driver for USB-HID keyboard and mouse input.
//! Each controller retains at most two addressed root-port devices and two
//! interrupt-IN endpoints: a keyboard and mouse on separate ports or on one
//! composite device. Reports feed the same `irq::QUEUE` as i8042 input, so
//! nothing above the arch boundary depends on the physical input bus.

use crate::x86::{inl, outl};

// ── PCI config space, legacy 0xCF8/0xCFC mechanism ─────────────────────────
// q35 (and real chipsets) route this for every bus, so it reaches a controller
// on a high bus too (the Razer's xHCI is at bus 0x65).

fn cfg_addr(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC)
}

fn cfg_read(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    outl(0xCF8, cfg_addr(bus, dev, func, off));
    inl(0xCFC)
}

fn cfg_write(bus: u8, dev: u8, func: u8, off: u8, val: u32) {
    outl(0xCF8, cfg_addr(bus, dev, func, off));
    outl(0xCFC, val);
}

/// Scan PCI config space for every xHCI controller — class 0x0C (serial bus),
/// subclass 0x03 (USB), prog-IF 0x30 (xHCI). Brute-force over all 256 buses is
/// fine for a one-shot boot probe and finds a controller on any bus.
fn for_each_xhci(mut found: impl FnMut(u8, u8, u8)) {
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                if cfg_read(bus, dev, func, 0x00) & 0xFFFF == 0xFFFF {
                    if func == 0 {
                        break; // function 0 absent ⇒ no device in this slot
                    }
                    continue;
                }
                // class(31:24) | subclass(23:16) | prog-if(15:8) after >>8.
                if cfg_read(bus, dev, func, 0x08) >> 8 == 0x0C_0330 {
                    found(bus, dev, func);
                }
                // Only probe funcs 1-7 on a multi-function device.
                if func == 0 && cfg_read(bus, dev, 0, 0x0C) & 0x0080_0000 == 0 {
                    break;
                }
            }
        }
    }
}

// ── Controller MMIO ────────────────────────────────────────────────────────
// Four disjoint windows above the framebuffer and LAPIC/HPET/IOAPIC mappings.
// Each reserves 64 KiB MMIO + 64 KiB DMA + one scratchpad mapping page.
// The 192 KiB stride leaves space between controllers and below the VA ceiling.
const MMIO_BASE: usize = 0xFFF1_0000;
const CONTROLLER_STRIDE: usize = 0x30000;
const MAX_CONTROLLERS: usize = 4;

// ── DMA region: DCBAA + command ring + event ring + ERST in one contiguous
// block, mapped at a fixed VA, cache-disabled (simple + coherent, as NVMe does).

mod dma;
use dma::*;
const RING_TRBS: usize = 256;
const DEVICE_LANES: usize = 2;

fn device_context_off(lane: usize) -> usize {
    match lane {
        0 => DEVCTX0_OFF,
        1 => DEVCTX1_OFF,
        _ => unreachable!(),
    }
}

fn ep0_off(lane: usize) -> usize {
    match lane {
        0 => EP0_0_OFF,
        1 => EP0_1_OFF,
        _ => unreachable!(),
    }
}

fn interrupt_off(pipe: usize) -> usize {
    match pipe {
        0 => INT0_OFF,
        1 => INT1_OFF,
        _ => unreachable!(),
    }
}

fn report_off(pipe: usize) -> usize {
    match pipe {
        0 => REPORT0_OFF,
        1 => REPORT1_OFF,
        _ => unreachable!(),
    }
}

// Operational/runtime register offsets, relative to their region base.
const OP_USBCMD: usize = 0x00;
const OP_USBSTS: usize = 0x04;
const OP_CRCR: usize = 0x18;
const OP_DCBAAP: usize = 0x30;
const OP_CONFIG: usize = 0x38;
const OP_PORTSC: usize = 0x400; // port 1; +0x10 per port
const IR0_ERSTSZ: usize = 0x20 + 0x08; // interrupter 0 within runtime regs
const IR0_ERSTBA: usize = 0x20 + 0x10;
const IR0_ERDP: usize = 0x20 + 0x18;

const USBCMD_RS: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBSTS_HCH: u32 = 1 << 0;
const USBSTS_CNR: u32 = 1 << 11;

/// Spin until `cond` (bounded — a wedged controller must not hang the boot).
fn wait(cond: impl Fn() -> bool) -> bool {
    for _ in 0..50_000_000u64 {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

// HID usage id → AT scancode set 1 (make code; break = make | 0x80). 0 = key
// we don't translate (extended/navigation keys need an E0 prefix — later).
#[rustfmt::skip]
const HID_SC: [u8; 0x68] = [
    0,0,0,0,                                              // 00-03
    0x1E,0x30,0x2E,0x20,0x12,0x21,0x22,0x23,0x17,0x24,    // 04-0D a-j
    0x25,0x26,0x32,0x31,0x18,0x19,0x10,0x13,0x1F,0x14,    // 0E-17 k-t
    0x16,0x2F,0x11,0x2D,0x15,0x2C,                        // 18-1D u-z
    0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,    // 1E-27 1-0
    0x1C,0x01,0x0E,0x0F,0x39,0x0C,0x0D,0x1A,0x1B,0x2B,    // 28-31 Enter Esc BS Tab Sp - = [ ] \
    0x2B,0x27,0x28,0x29,0x33,0x34,0x35,0x3A,              // 32-39 #  ; ' ` , . / Caps
    0x3B,0x3C,0x3D,0x3E,0x3F,0x40,0x41,0x42,0x43,0x44,    // 3A-43 F1-F10
    0x57,0x58,                                            // 44-45 F11 F12
    0,0x46,0,0,0,0,0,0,0,0,                               // 46-4F PrtSc ScrLk Pause Ins Home PgUp Del End PgDn Right
    0,0,0,0x45,0,0x37,0x4A,0x4E,0,0x4F,                   // 50-59 Left Down Up NumLk KP/ KP* KP- KP+ KPEnt KP1
    0x50,0x51,0x4B,0x4C,0x4D,0x47,0x48,0x49,0x52,0x53,    // 5A-63 KP2-9 KP0 KP.
    0,0,0,0,                                              // 64-67
];

// Modifier byte bits → scancode (LCtrl/LShift/LAlt/LGui, RCtrl/RShift/RAlt/RGui).
// Right-side Ctrl/Alt collapse to the base code (E0 prefix omitted); GUI keys
// dropped for now.
const MOD_SC: [u8; 8] = [0x1D, 0x2A, 0x38, 0, 0x1D, 0x36, 0x38, 0];

#[derive(Clone, Copy)]
struct HidPipe {
    ready: bool,
    slot: u32,
    dci: u32,
    pipe: usize,
    report_len: usize,
    enq: usize,
    cycle: u32,
}

impl HidPipe {
    const fn empty(pipe: usize) -> Self {
        Self {
            ready: false,
            slot: 0,
            dci: 0,
            pipe,
            report_len: 0,
            enq: 0,
            cycle: 1,
        }
    }
}

/// Translate a HID usage to its AT set-1 scancode and whether it's an extended
/// (E0-prefixed) key. Arrows / navigation / keypad-Enter|slash are extended;
/// everything else comes from `HID_SC`.
fn hid_to_scancode(usage: u8) -> Option<(u8, bool)> {
    let u = usage as usize;
    if u < HID_SC.len() && HID_SC[u] != 0 {
        return Some((HID_SC[u], false));
    }
    let ext = match usage {
        0x49 => 0x52, // Insert
        0x4A => 0x47, // Home
        0x4B => 0x49, // PageUp
        0x4C => 0x53, // Delete
        0x4D => 0x4F, // End
        0x4E => 0x51, // PageDown
        0x4F => 0x4D, // Right
        0x50 => 0x4B, // Left
        0x51 => 0x50, // Down
        0x52 => 0x48, // Up
        0x54 => 0x35, // Keypad /
        0x58 => 0x1C, // Keypad Enter
        _ => return None,
    };
    Some((ext, true))
}

/// Push one key event: an extended key gets the 0xE0 prefix byte first, then
/// the make (or `| 0x80` break) code — exactly what a PS/2 keyboard sends.
fn emit_key(sc: u8, extended: bool, release: bool) {
    if extended {
        crate::irq::push_key(0xE0);
    }
    crate::irq::push_key(if release { sc | 0x80 } else { sc });
}

/// Decode the HID boot-mouse prefix: buttons, signed X, signed Y. HID mouse Y
/// is already positive toward the bottom of the screen, matching `Irq::Mouse`.
fn process_mouse_report(r: &[u8; 16], len: usize) {
    if let Some((dx, dy, buttons)) = decode_mouse_report(r, len) {
        crate::irq::push_mouse(dx, dy, buttons);
    }
}

fn decode_mouse_report(r: &[u8; 16], len: usize) -> Option<(i16, i16, u8)> {
    (len >= 3).then_some((r[1] as i8 as i16, r[2] as i8 as i16, r[0] & 0x07))
}

/// One enumerated interrupt-IN endpoint (a HID role's report pipe).
#[derive(Clone, Copy)]
struct EpInfo {
    iface: u32,
    ep: u32,
    mps: u32,
    interval: u32,
}

/// Classification of one connected root-hub port, built once during init. The
/// inventory separates enumeration (what's on each port) from role selection
/// (which device drives the keyboard and mouse), so each root port is probed
/// only once.
#[derive(Clone, Copy)]
struct PortDevice {
    lane: usize,
    port: u32,
    speed: u32,
    dev_class: u32,           // bDeviceClass (0xE0 = Bluetooth, 0 = composite, …)
    cfg_value: u32,           // bConfigurationValue for SET_CONFIGURATION
    keyboard: Option<EpInfo>, // HID boot-keyboard interrupt-IN endpoint, if any
    mouse: Option<EpInfo>,    // HID mouse interrupt-IN endpoint, if any
}

#[cfg(test)]
mod tests {
    use super::decode_mouse_report;

    #[test]
    fn boot_mouse_report_preserves_signed_motion_and_buttons() {
        let mut report = [0u8; 16];
        report[..4].copy_from_slice(&[0b101, 0xfe, 0x7f, 1]);
        assert_eq!(decode_mouse_report(&report, 4), Some((-2, 127, 0b101)));
        assert_eq!(decode_mouse_report(&report, 2), None);
    }
}

#[derive(Clone, Copy)]
enum HidRole {
    Keyboard,
    Mouse,
}

/// All register mappings, DMA rings, and HID state belong to one PCI function.
struct Controller {
    pci: (u8, u8, u8),
    mmio_va: usize,
    dma_va: usize,
    rt: usize,
    db: usize,
    dma_phys: u64,
    cmd_enq: usize,
    cmd_cycle: u32,
    evt_deq: usize,
    evt_cycle: u32,
    ep0_enq: [usize; DEVICE_LANES],
    ep0_cycle: [u32; DEVICE_LANES],
    pipes: [HidPipe; 2],
    prev: [u8; 16],
}

impl Controller {
    const fn new(index: usize, pci: (u8, u8, u8)) -> Self {
        Self {
            pci,
            mmio_va: MMIO_BASE + index * CONTROLLER_STRIDE,
            dma_va: MMIO_BASE + index * CONTROLLER_STRIDE + 0x10000,
            rt: 0,
            db: 0,
            dma_phys: 0,
            cmd_enq: 0,
            cmd_cycle: 1,
            evt_deq: 0,
            evt_cycle: 1,
            ep0_enq: [0; DEVICE_LANES],
            ep0_cycle: [1; DEVICE_LANES],
            pipes: [HidPipe::empty(0), HidPipe::empty(1)],
            prev: [0; 16],
        }
    }
    fn map_mmio(&self, phys: u64, pages: usize) {
        for i in 0..pages {
            crate::paging2::map_user_page_phys(
                self.mmio_va / crate::paging2::PAGE_SIZE + i,
                phys / crate::paging2::PAGE_SIZE as u64 + i as u64,
                crate::paging2::flags::CACHE_DISABLE,
            );
        }
    }

    fn r32(&self, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_va + off) as *const u32) }
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { core::ptr::write_volatile((self.mmio_va + off) as *mut u32, v) }
    }

    /// 64-bit controller registers: write low then high dword (always safe; some
    /// don't allow a single qword access).
    fn w64(&self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }

    /// Enqueue a TRB on the command ring and ring doorbell 0. `control` carries the
    /// TRB type (`<<10`) plus any command-specific fields (e.g. slot id in 31:24);
    /// the cycle bit is added here. At the ring's last slot (the Link TRB) we flip
    /// its cycle bit, wrap, and toggle our cycle.
    fn ring_cmd(&mut self, param: u64, status: u32, control: u32) {
        unsafe {
            let trb = (self.dma_va + CMD_OFF + self.cmd_enq * 16) as *mut u32;
            core::ptr::write_volatile(trb as *mut u64, param);
            core::ptr::write_volatile(trb.add(2), status);
            core::ptr::write_volatile(trb.add(3), control | self.cmd_cycle);
            self.cmd_enq += 1;
            if self.cmd_enq == RING_TRBS - 1 {
                let link = (self.dma_va + CMD_OFF + (RING_TRBS - 1) * 16) as *mut u32;
                let c = core::ptr::read_volatile(link.add(3)) & !1;
                core::ptr::write_volatile(link.add(3), c | self.cmd_cycle);
                self.cmd_enq = 0;
                self.cmd_cycle ^= 1;
            }
            self.w32(self.db, 0); // doorbell 0 (at self.mmio_va + self.db) = command ring
        }
    }

    /// Non-blocking: if an event TRB is ready, dequeue it (advancing ERDP) and
    /// return (trb_type, completion_code, slot_id, endpoint_id); else None.
    fn try_event(&mut self) -> Option<(u32, u32, u32, u32)> {
        unsafe {
            let trb = (self.dma_va + EVT_OFF + self.evt_deq * 16) as *const u32;
            let ctrl = core::ptr::read_volatile(trb.add(3));
            if ctrl & 1 != self.evt_cycle {
                return None;
            }
            let ttype = (ctrl >> 10) & 0x3F;
            let cc = core::ptr::read_volatile(trb.add(2)) >> 24;
            let slot = ctrl >> 24;
            let endpoint = (ctrl >> 16) & 0x1f;
            self.evt_deq += 1;
            if self.evt_deq == RING_TRBS {
                self.evt_deq = 0;
                self.evt_cycle ^= 1;
            }
            // Advance ERDP (bits 4:63) and clear the Event-Handler-Busy bit.
            self.w64(
                self.rt + IR0_ERDP,
                (self.dma_phys + (EVT_OFF + self.evt_deq * 16) as u64) | (1 << 3),
            );
            Some((ttype, cc, slot, endpoint))
        }
    }

    /// Dequeue one event TRB (bounded wait). None on timeout.
    fn poll_event(&mut self) -> Option<(u32, u32, u32, u32)> {
        for _ in 0..50_000_000u64 {
            if let Some(e) = self.try_event() {
                return Some(e);
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Wait for the next event of TRB type `want` (33=Command Completion,
    /// 32=Transfer), skipping unrelated events queued ahead of it (e.g. a Port
    /// Status Change from a reset). Returns (completion_code, slot_id).
    fn wait_event(&mut self, want: u32) -> Option<(u32, u32)> {
        for _ in 0..64 {
            let (ttype, cc, slot, _) = self.poll_event()?;
            if ttype == want {
                return Some((cc, slot));
            }
        }
        None
    }

    /// Enable Slot (TRB type 9) → a Command Completion Event carries the assigned
    /// slot id. Returns it on success (completion code 1).
    fn enable_slot(&mut self) -> Option<u32> {
        // Enable interrupter 0 (IMAN.IE) — some controllers only post events to the
        // ring once the interrupter is enabled, even for a polling driver.
        self.w32(self.rt + 0x20, self.r32(self.rt + 0x20) | 0x2);
        self.ring_cmd(0, 0, 9 << 10); // TRB type 9 = Enable Slot
        match self.wait_event(33)? {
            (1, slot) => Some(slot),
            _ => None,
        }
    }

    /// Enqueue a TRB on the EP0 transfer ring (no doorbell — the caller rings it
    /// once per transfer descriptor). Handles the Link TRB wrap like the cmd ring.
    fn ep0_trb(&mut self, lane: usize, param: u64, status: u32, control: u32) {
        unsafe {
            let ring = ep0_off(lane);
            let trb = (self.dma_va + ring + self.ep0_enq[lane] * 16) as *mut u32;
            core::ptr::write_volatile(trb as *mut u64, param);
            core::ptr::write_volatile(trb.add(2), status);
            core::ptr::write_volatile(trb.add(3), control | self.ep0_cycle[lane]);
            self.ep0_enq[lane] += 1;
            if self.ep0_enq[lane] == RING_TRBS - 1 {
                let link = (self.dma_va + ring + (RING_TRBS - 1) * 16) as *mut u32;
                let c = core::ptr::read_volatile(link.add(3)) & !1;
                core::ptr::write_volatile(link.add(3), c | self.ep0_cycle[lane]);
                self.ep0_enq[lane] = 0;
                self.ep0_cycle[lane] ^= 1;
            }
        }
    }

    /// Issue a control transfer on EP0: Setup → (Data) → Status stages, ring the
    /// slot's doorbell (DCI 1 = control EP), wait for the Transfer Event. IN data
    /// (if any) lands in the XFER buffer. Returns true on Success/Short-Packet.
    #[allow(clippy::too_many_arguments)] // EP0 target plus the USB setup packet fields.
    fn control(
        &mut self,
        slot: u32,
        lane: usize,
        bm_req: u32,
        b_req: u32,
        w_value: u32,
        w_index: u32,
        w_len: u32,
    ) -> bool {
        let dir_in = bm_req & 0x80 != 0;
        // Setup Stage (immediate data, IDT=1): the 8-byte SETUP packet in `param`.
        let setup = (bm_req | (b_req << 8) | (w_value << 16)) as u64
            | ((w_index | (w_len << 16)) as u64) << 32;
        let trt = if w_len == 0 {
            0
        } else if dir_in {
            3
        } else {
            2
        };
        self.ep0_trb(lane, setup, 8, (1 << 6) | (2 << 10) | (trt << 16)); // IDT, type 2, TRT
        if w_len > 0 {
            let buf = self.dma_phys + XFER_OFF as u64;
            self.ep0_trb(lane, buf, w_len, (3 << 10) | ((dir_in as u32) << 16)); // type 3, DIR
        }
        // Status Stage: opposite direction, Interrupt-On-Completion so we get an event.
        let status_dir = if dir_in && w_len > 0 { 0 } else { 1 };
        self.ep0_trb(lane, 0, 0, (1 << 5) | (4 << 10) | (status_dir << 16)); // IOC, type 4, DIR
        let db = self.db;
        self.w32(db + slot as usize * 4, 1); // ring slot doorbell, DCI 1 (EP0)
        matches!(self.wait_event(32), Some((1, _)) | Some((13, _))) // Success or Short Packet
    }

    /// Reset the controller, stand up the DCBAA + command/event rings, and run it.
    /// Returns false (without hanging) if it never comes ready.
    fn bringup(&mut self, op: usize, rt: usize, max_slots: u32) -> bool {
        // Wait until the controller is ready, halt it, then host-controller reset.
        if !wait(|| self.r32(op + OP_USBSTS) & USBSTS_CNR == 0) {
            return false;
        }
        self.w32(op + OP_USBCMD, self.r32(op + OP_USBCMD) & !USBCMD_RS);
        if !wait(|| self.r32(op + OP_USBSTS) & USBSTS_HCH != 0) {
            return false;
        }
        self.w32(op + OP_USBCMD, USBCMD_HCRST);
        if !wait(|| self.r32(op + OP_USBCMD) & USBCMD_HCRST == 0)
            || !wait(|| self.r32(op + OP_USBSTS) & USBSTS_CNR == 0)
        {
            return false;
        }

        // This driver uses 4 KiB pages. Refuse unsupported controllers while
        // halted, before publishing any DMA pointers.
        if self.r32(op + 8) & 1 == 0 {
            lib::compact_println!("xHCI: 4 KiB pages unsupported - skipping");
            return false;
        }
        let Some(page) = crate::phys_mm::alloc_contig(DMA_PAGES) else {
            lib::compact_println!("xHCI: DMA allocation failed - skipping");
            return false;
        };
        let phys = page * 0x1000;
        self.map_dma(phys, DMA_PAGES);
        unsafe {
            core::ptr::write_bytes(self.dma_va as *mut u8, 0, DMA_PAGES * 0x1000);
            self.dma_phys = phys;
        }

        // Allocate the full hardware-requested count, not a fixed pool. Only the
        // pointer array is contiguous; one temporary VA zeros each separate page.
        // All pages remain reserved for the boot lifetime, including on failure.
        let array = unsafe {
            core::slice::from_raw_parts_mut(
                (self.dma_va + SCRATCH_OFF) as *mut u64,
                (DMA_PAGES * 0x1000 - SCRATCH_OFF) / 8,
            )
        };
        let scratch = dma::scratchpads(self.r32(0x08), array, || {
            let page = crate::phys_mm::alloc_contig(1)?;
            let temporary = self.dma_va + DMA_PAGES * 0x1000;
            crate::paging2::map_user_page_phys(
                temporary / 0x1000,
                page,
                crate::paging2::flags::CACHE_DISABLE,
            );
            unsafe {
                core::ptr::write_bytes(temporary as *mut u8, 0, 0x1000);
            }
            Some(page * 0x1000)
        });
        let Some(scratch) = scratch else {
            lib::compact_println!("xHCI: scratchpad allocation failed - skipping");
            return false;
        };
        lib::compact_println!("xHCI: scratchpad buffers allocated: {}", scratch);
        if scratch != 0 {
            unsafe {
                core::ptr::write_volatile(
                    (self.dma_va + DCBAA_OFF) as *mut u64,
                    phys + SCRATCH_OFF as u64,
                );
            }
        }
        // Publish only after every scratchpad and its pointer have been initialized.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.w32(op + OP_CONFIG, max_slots);
        self.w64(op + OP_DCBAAP, phys + DCBAA_OFF as u64);

        // Command ring: a Link TRB at the end loops back to the start (TRB type 6,
        // Toggle-Cycle set). CRCR points at it with Ring-Cycle-State = 1.
        let link = (self.dma_va + CMD_OFF + (RING_TRBS - 1) * 16) as *mut u32;
        unsafe {
            core::ptr::write_volatile(link as *mut u64, phys + CMD_OFF as u64);
            core::ptr::write_volatile(link.add(3), (6 << 10) | (1 << 1));
        }
        self.w64(op + OP_CRCR, (phys + CMD_OFF as u64) | 1);

        // Event ring: one ERST segment describing the event-ring buffer.
        unsafe {
            let erst = self.dma_va + ERST_OFF;
            core::ptr::write_volatile(erst as *mut u64, phys + EVT_OFF as u64);
            core::ptr::write_volatile((erst + 8) as *mut u32, RING_TRBS as u32);
        }
        self.w32(rt + IR0_ERSTSZ, 1);
        self.w64(rt + IR0_ERDP, phys + EVT_OFF as u64);
        self.w64(rt + IR0_ERSTBA, phys + ERST_OFF as u64);

        // Run.
        self.w32(op + OP_USBCMD, self.r32(op + OP_USBCMD) | USBCMD_RS);
        wait(|| self.r32(op + OP_USBSTS) & USBSTS_HCH == 0)
    }

    fn map_dma(&self, phys: u64, pages: usize) {
        for i in 0..pages {
            crate::paging2::map_user_page_phys(
                self.dma_va / crate::paging2::PAGE_SIZE + i,
                phys / crate::paging2::PAGE_SIZE as u64 + i as u64,
                crate::paging2::flags::CACHE_DISABLE,
            );
        }
    }

    /// Reset a root-hub port so the attached device enters the Default state and
    /// the port enables (USB2 needs the reset; USB3 auto-enables, but it's
    /// harmless). Preserves the port's RW1C change bits. The controller owns the
    /// reset timing and signals completion via Port-Enabled — we just wait.
    fn reset_port(&self, op: usize, port: u32) {
        let off = op + OP_PORTSC + (port as usize - 1) * 0x10;
        let rw1c = 0x00FE_0000; // CSC/PEC/WRC/OCC/PRC/PLC/CEC — write-1-to-clear
        self.w32(off, (self.r32(off) & !rw1c) | (1 << 4)); // PR = Port Reset
        wait(|| self.r32(off) & (1 << 1) != 0); // PED (Port Enabled)
    }

    /// Initialise the default-control-endpoint (EP0) transfer ring: zeroed, with a
    /// Link TRB at the end looping to the start (Toggle Cycle set).
    fn init_ep0_ring(&mut self, lane: usize) {
        unsafe {
            let ring = ep0_off(lane);
            core::ptr::write_bytes((self.dma_va + ring) as *mut u8, 0, 0x1000);
            let link = (self.dma_va + ring + (RING_TRBS - 1) * 16) as *mut u32;
            core::ptr::write_volatile(link as *mut u64, self.dma_phys + ring as u64);
            core::ptr::write_volatile(link.add(3), (6 << 10) | (1 << 1));
            // Reset the producer cursor to match the fresh ring: Address Device sets
            // the new slot's EP0 TR-dequeue pointer to offset 0 with DCS=1, so
            // self.control() must enqueue from offset 0 with cycle 1. Without this, a
            // SECOND device (cursor left advanced by the first) enqueues where the
            // controller isn't reading, and every control transfer times out.
            self.ep0_enq[lane] = 0;
            self.ep0_cycle[lane] = 1;
        }
    }

    /// Build the input context (Slot + EP0) and issue Address Device, moving the
    /// device to the Addressed state (the controller performs SET_ADDRESS on the
    /// wire). `stride` is the context size (32 or 64 bytes per HCCPARAMS1.CSZ).
    fn address_device(
        &mut self,
        slot: u32,
        lane: usize,
        port: u32,
        speed: u32,
        stride: usize,
    ) -> bool {
        self.init_ep0_ring(lane);
        unsafe {
            let inctx = self.dma_va + INCTX_OFF;
            core::ptr::write_bytes(inctx as *mut u8, 0, 0x1000);
            // Input Control Context: Add Slot (bit 0) + EP0 (bit 1).
            core::ptr::write_volatile((inctx + 4) as *mut u32, 0x3);
            // Slot Context: Context Entries = 1 (27:31), Speed (20:23); Root-Hub
            // Port Number (16:23 of dword 1).
            let slotc = inctx + stride;
            core::ptr::write_volatile(slotc as *mut u32, (1 << 27) | (speed << 20));
            core::ptr::write_volatile((slotc + 4) as *mut u32, port << 16);
            // EP0 Context: EP Type = Control (4) at 3:5, Max Packet Size at 16:31,
            // CErr = 3 at 1:2; TR Dequeue Pointer (64-bit) with DCS = 1.
            let mps: u32 = match speed {
                4 => 512,
                3 => 64,
                _ => 8,
            };
            let ep0 = inctx + 2 * stride;
            core::ptr::write_volatile((ep0 + 4) as *mut u32, (mps << 16) | (4 << 3) | (3 << 1));
            core::ptr::write_volatile(
                (ep0 + 8) as *mut u64,
                (self.dma_phys + ep0_off(lane) as u64) | 1,
            );
            // DCBAA[slot] → device (output) context.
            core::ptr::write_volatile(
                (self.dma_va + DCBAA_OFF + slot as usize * 8) as *mut u64,
                self.dma_phys + device_context_off(lane) as u64,
            );
        }
        // Address Device (TRB type 11): input-context pointer, slot id in 31:24.
        let inctx_phys = self.dma_phys + INCTX_OFF as u64;
        self.ring_cmd(inctx_phys, 0, (11 << 10) | (slot << 24));
        matches!(self.wait_event(33), Some((1, _)))
    }

    /// Initialise the interrupt-IN endpoint transfer ring (Link TRB at end).
    fn init_int_ring(&mut self, pipe: usize) {
        unsafe {
            let ring = interrupt_off(pipe);
            core::ptr::write_bytes((self.dma_va + ring) as *mut u8, 0, 0x1000);
            let link = (self.dma_va + ring + (RING_TRBS - 1) * 16) as *mut u32;
            core::ptr::write_volatile(link as *mut u64, self.dma_phys + ring as u64);
            core::ptr::write_volatile(link.add(3), (6 << 10) | (1 << 1));
        }
    }

    /// Configure Endpoint (TRB type 12): add the interrupt-IN endpoint (DCI =
    /// ep*2+1) to the device so the controller polls it into our transfer ring.
    fn configure_endpoint(
        &mut self,
        slot: u32,
        lane: usize,
        pipe: usize,
        ep: EpInfo,
        interval: u32,
        stride: usize,
    ) -> bool {
        self.init_int_ring(pipe);
        let mps = ep.mps;
        let dci = ep.ep * 2 + 1; // IN
        unsafe {
            let inctx = self.dma_va + INCTX_OFF;
            core::ptr::write_bytes(inctx as *mut u8, 0, 0x1000);
            // Input Control Context: add Slot (bit 0) + this endpoint (bit dci).
            core::ptr::write_volatile((inctx + 4) as *mut u32, 1 | (1 << dci));
            // Slot Context: COPY the controller's live output slot context, then only
            // bump Context Entries to the new highest DCI. Address Device fills in
            // derived fields (TT hub/port, routing, speed) needed to run split
            // transactions to a full-speed device on the high-speed root hub; a fresh
            // slot context (speed/port only) zeroes those, and the re-evaluation then
            // leaves the endpoint "Running" but never polled — no transfers at all.
            let slotc = inctx + stride;
            core::ptr::copy_nonoverlapping(
                (self.dma_va + device_context_off(lane)) as *const u8,
                slotc as *mut u8,
                stride,
            );
            let current_entries = core::ptr::read_volatile(slotc as *const u32) >> 27;
            let dw0 = core::ptr::read_volatile(slotc as *const u32) & !(0x1F << 27);
            core::ptr::write_volatile(slotc as *mut u32, dw0 | (current_entries.max(dci) << 27));
            // Endpoint Context at (1 + dci) * stride: Interval (16:23); EP Type =
            // Interrupt IN (7) at 3:5, Max Packet Size (16:31), CErr = 3 (1:2); TR
            // Dequeue Pointer with DCS = 1.
            let epc = inctx + (1 + dci as usize) * stride;
            core::ptr::write_volatile(epc as *mut u32, interval << 16);
            core::ptr::write_volatile((epc + 4) as *mut u32, (mps << 16) | (7 << 3) | (3 << 1));
            core::ptr::write_volatile(
                (epc + 8) as *mut u64,
                (self.dma_phys + interrupt_off(pipe) as u64) | 1,
            );
            // DW4: Average TRB Length (0:15) + Max ESIT Payload (16:31). A real
            // xHCI uses Max ESIT Payload to reserve periodic-schedule bandwidth for
            // an interrupt endpoint; left 0, an Intel/AMD controller *accepts*
            // Configure Endpoint (so we print "keyboard ready") but allocates zero
            // bandwidth and never services the endpoint — reports never arrive.
            // QEMU doesn't model periodic scheduling, which is why high-speed worked
            // with this field missing. For a boot keyboard both equal the report
            // size (Max ESIT Payload = MPS × (MaxBurst+1) = mps × 1).
            core::ptr::write_volatile((epc + 16) as *mut u32, (mps << 16) | mps);
        }
        let inctx_phys = self.dma_phys + INCTX_OFF as u64;
        self.ring_cmd(inctx_phys, 0, (12 << 10) | (slot << 24));
        matches!(self.wait_event(33), Some((1, _)))
    }

    /// Evaluate Context (TRB type 13): update EP0's Max Packet Size in the device
    /// context. Full-speed devices vary (8/16/32/64); we address with the safe
    /// minimum 8, then correct it once the device descriptor reveals the real value
    /// — otherwise larger control transfers babble. (High-speed is always 64, so
    /// this is a no-op there.)
    fn evaluate_ep0_mps(&mut self, slot: u32, lane: usize, mps: u32, stride: usize) -> bool {
        unsafe {
            let inctx = self.dma_va + INCTX_OFF;
            core::ptr::write_bytes(inctx as *mut u8, 0, 0x1000);
            // Copy the controller's live Slot + EP0 output contexts into the input
            // context before patching MPS. A real xHCI requires a valid input Slot
            // Context for Evaluate Context (matches Linux xhci_check_maxpacket) —
            // zeroing it made the command a silent no-op on the laptop, so the
            // config descriptor read still ran at the addressed MPS 8 and babbled.
            core::ptr::copy_nonoverlapping(
                (self.dma_va + device_context_off(lane)) as *const u8,
                (inctx + stride) as *mut u8,
                2 * stride,
            );
            // Input Control Context: add EP0 (bit 1) only.
            core::ptr::write_volatile((inctx + 4) as *mut u32, 0x2);
            // EP0 Context (DCI 1, at 2*stride): patch only Max Packet Size (16:31),
            // preserving the copied EP type / CErr / TR Dequeue Pointer.
            let ep0 = inctx + 2 * stride;
            let dw1 = core::ptr::read_volatile((ep0 + 4) as *const u32) & 0x0000_FFFF;
            core::ptr::write_volatile((ep0 + 4) as *mut u32, (mps << 16) | dw1);
        }
        let inctx_phys = self.dma_phys + INCTX_OFF as u64;
        self.ring_cmd(inctx_phys, 0, (13 << 10) | (slot << 24));
        matches!(self.wait_event(33), Some((1, _)))
    }

    /// Queue one Normal TRB on a HID interrupt-IN ring and ring that endpoint's
    /// doorbell so the controller polls it once.
    fn arm_report(&mut self, index: usize) {
        unsafe {
            let pipe = &mut self.pipes[index];
            let ring = interrupt_off(pipe.pipe);
            let report = report_off(pipe.pipe);
            core::ptr::write_bytes((self.dma_va + report) as *mut u8, 0, pipe.report_len);
            let trb = (self.dma_va + ring + pipe.enq * 16) as *mut u32;
            core::ptr::write_volatile(trb as *mut u64, self.dma_phys + report as u64);
            core::ptr::write_volatile(trb.add(2), pipe.report_len as u32);
            core::ptr::write_volatile(trb.add(3), (1 << 5) | (1 << 10) | pipe.cycle); // IOC, Normal
            pipe.enq += 1;
            if pipe.enq == RING_TRBS - 1 {
                let link = (self.dma_va + ring + (RING_TRBS - 1) * 16) as *mut u32;
                let c = core::ptr::read_volatile(link.add(3)) & !1;
                core::ptr::write_volatile(link.add(3), c | pipe.cycle);
                pipe.enq = 0;
                pipe.cycle ^= 1;
            }
            let (slot, dci) = (pipe.slot, pipe.dci);
            self.w32(self.db + slot as usize * 4, dci);
        }
    }

    /// Diff a HID keyboard report against the previous one and push make/break
    /// scancodes into the shared IRQ queue, just like the i8042 IRQ1 handler.
    ///
    /// Two layouts, distinguished by `len`:
    ///   - 8 (boot keyboard): `[mods, reserved, k1..k6]` — modifiers at byte 0.
    ///   - \>8 (report-ID keyboard, e.g. the Razer's interface 1, 16 bytes):
    ///     `[report-id, mods, k1..k14]` — report id at byte 0 (only id 1 is the
    ///     keyboard; consumer/system reports share the endpoint), modifiers at
    ///     byte 1. In both, the keycode array starts at byte 2.
    fn process_keyboard_report(&mut self, r: &[u8; 16], len: usize) {
        let id_prefixed = len > 8;
        if id_prefixed && r[0] != 1 {
            return; // not the keyboard report (consumer control, etc.)
        }
        let mod_off = if id_prefixed { 1 } else { 0 };
        let prev = self.prev;
        let keys = &r[2..len];
        let prev_keys = &prev[2..len];
        // Modifier keys: one make/break per changed bit.
        for (b, &sc) in MOD_SC.iter().enumerate() {
            let (now, was) = (r[mod_off] & (1 << b), prev[mod_off] & (1 << b));
            if now != was && sc != 0 {
                crate::irq::push_key(if now != 0 { sc } else { sc | 0x80 });
            }
        }
        // Regular keys: newly present → make; newly absent → break.
        for &k in keys {
            if k >= 4
                && !prev_keys.contains(&k)
                && let Some((sc, ext)) = hid_to_scancode(k)
            {
                emit_key(sc, ext, false);
            }
        }
        for &k in prev_keys {
            if k >= 4
                && !keys.contains(&k)
                && let Some((sc, ext)) = hid_to_scancode(k)
            {
                emit_key(sc, ext, true);
            }
        }
        self.prev = *r;
    }

    fn read_report(&self, index: usize) -> ([u8; 16], usize) {
        unsafe {
            let pipe = &self.pipes[index];
            let mut report = [0u8; 16];
            for (i, byte) in report.iter_mut().take(pipe.report_len).enumerate() {
                *byte = core::ptr::read_volatile(
                    (self.dma_va + report_off(pipe.pipe) + i) as *const u8,
                );
            }
            (report, pipe.report_len)
        }
    }

    /// Called from the timer IRQ: dispatch completed keyboard/mouse reports and
    /// re-arm their pipes. Cheap when idle (one event-ring cycle-bit check).
    fn poll(&mut self) {
        if !self.pipes.iter().any(|pipe| pipe.ready) {
            return;
        }
        // Bound IRQ work per controller so one busy ring cannot starve the others.
        for _ in 0..RING_TRBS {
            let Some((ttype, cc, slot, dci)) = self.try_event() else {
                break;
            };
            if ttype != 32 {
                continue;
            }
            for index in 0..2 {
                let pipe = &self.pipes[index];
                if !pipe.ready || pipe.slot != slot || pipe.dci != dci {
                    continue;
                }
                if cc == 1 || cc == 13 {
                    let (report, len) = self.read_report(index);
                    if index == 0 {
                        self.process_keyboard_report(&report, len);
                    } else {
                        process_mouse_report(&report, len);
                    }
                }
                self.arm_report(index);
                break;
            }
        }
    }

    /// Disable Slot (TRB type 10): release a slot so the device on its port is no
    /// longer bound to it. Non-input devices are released after classification so
    /// their probe lane can be reused by the next root port.
    fn disable_slot(&mut self, slot: u32) {
        self.ring_cmd(0, 0, (10 << 10) | (slot << 24));
        self.wait_event(33);
    }

    /// Reset the port, enable a slot, address the device, and correct EP0's max
    /// packet size for full-speed devices. Returns the slot id, or None on failure.
    fn address_port(
        &mut self,
        op: usize,
        lane: usize,
        port: u32,
        speed: u32,
        stride: usize,
    ) -> Option<u32> {
        self.reset_port(op, port);
        let slot = self.enable_slot()?;
        if !self.address_device(slot, lane, port, speed, stride) {
            self.disable_slot(slot);
            return None;
        }
        // We address with the safe minimum MPS 8; read bMaxPacketSize0 (fits one
        // 8-byte packet) and, if larger, update EP0 before any bigger transfer or a
        // full-speed config read babbles. High-speed is always 64.
        if !self.control(slot, lane, 0x80, 0x06, 0x0100, 0, 8) {
            self.disable_slot(slot);
            return None;
        }
        let mps0 =
            unsafe { core::ptr::read_volatile((self.dma_va + XFER_OFF + 7) as *const u8) } as u32;
        if mps0 > 8 && !self.evaluate_ep0_mps(slot, lane, mps0, stride) {
            self.disable_slot(slot);
            return None;
        }
        Some(slot)
    }

    /// Read the configuration descriptor of an ALREADY-ADDRESSED device (its slot
    /// still live, the 8-byte device descriptor still in XFER) and record which HID
    /// roles (boot keyboard / mouse) it exposes and on which endpoints. The slot is
    /// left addressed so the caller can arm it in place — no re-address, which on a
    /// full-speed device can leave it configured-but-silent.
    fn classify_addressed(&mut self, slot: u32, lane: usize, port: u32, speed: u32) -> PortDevice {
        let xfer = self.dma_va + XFER_OFF;
        let rd = |o: usize| unsafe { core::ptr::read_volatile((xfer + o) as *const u8) as u32 };
        let dev_class = rd(4); // bDeviceClass from the 8-byte device descriptor
        let mut dev = PortDevice {
            lane,
            port,
            speed,
            dev_class,
            cfg_value: 0,
            keyboard: None,
            mouse: None,
        };
        // Read the WHOLE config descriptor (wTotalLength can exceed 64 on a
        // composite device) and walk its interface / endpoint descriptors.
        if self.control(slot, lane, 0x80, 0x06, 0x0200, 0, 255) {
            dev.cfg_value = rd(5);
            let total = ((rd(2) | (rd(3) << 8)) as usize).min(255);
            let (mut cur_iface, mut is_kbd, mut is_mouse) = (0u32, false, false);
            let mut i = rd(0) as usize;
            while i + 2 <= total {
                let (blen, btype) = (rd(i) as usize, rd(i + 1));
                if blen < 2 || i + blen > total {
                    break;
                }
                if btype == 4 {
                    if blen < 9 {
                        break;
                    }
                    // interface: HID(3)/keyboard(proto 1) vs HID(3)/mouse(proto 2).
                    // A composite keyboard has both a boot interface (subclass 1,
                    // small report) and the real keyboard (subclass 0, larger
                    // report). We accept any keyboard-protocol interface and below
                    // keep the one with the LARGEST report — the real keyboard,
                    // which is the one the device actually reports keys on. (The
                    // boot interface sits idle outside boot protocol.)
                    cur_iface = rd(i + 2);
                    let (cls, subclass, proto) = (rd(i + 5), rd(i + 6), rd(i + 7));
                    is_kbd = cls == 3 && proto == 1;
                    is_mouse = cls == 3 && subclass == 1 && proto == 2;
                } else if btype == 5 && blen >= 7 && rd(i + 2) & 0x80 != 0 && rd(i + 3) & 0x3 == 3 {
                    // interrupt-IN endpoint — attribute it to the current role
                    let ep = EpInfo {
                        iface: cur_iface,
                        ep: rd(i + 2) & 0x0F,
                        mps: rd(i + 4) | (rd(i + 5) << 8),
                        interval: rd(i + 6),
                    };
                    if is_kbd && dev.keyboard.is_none_or(|k: EpInfo| ep.mps > k.mps) {
                        dev.keyboard = Some(ep);
                    }
                    if is_mouse && dev.mouse.is_none() {
                        dev.mouse = Some(ep);
                    }
                }
                i += blen;
            }
        }
        dev
    }

    /// Configure one HID interrupt endpoint on an already-addressed slot. Reports
    /// are armed only after every retained endpoint is configured, so transfer
    /// events cannot be consumed by the synchronous command wait path.
    fn configure_hid(
        &mut self,
        slot: u32,
        dev: &PortDevice,
        ep: EpInfo,
        role: HidRole,
        pipe: usize,
        stride: usize,
    ) -> bool {
        if matches!(role, HidRole::Mouse) {
            // A protocol-2 HID interface guarantees the standard boot report only
            // after SET_PROTOCOL(boot). Report-protocol mice may prepend an ID or
            // use wider axes that the compact decoder intentionally does not parse.
            if !self.control(slot, dev.lane, 0x21, 0x0B, 0, ep.iface, 0) {
                return false;
            }
        }
        // Do not force boot protocol for keyboards: some gaming keyboards expose a
        // boot-class interface but go silent when switched out of report protocol.
        self.control(slot, dev.lane, 0x21, 0x0A, 0, ep.iface, 0); // SET_IDLE = 0
        // xHCI Interval (period = 2^Interval × 125µs). High/super speed: the
        // descriptor's bInterval is already the exponent+1. Full/low speed: bInterval
        // is in 1ms frames, so the exponent = 3 + floor(log2(bInterval)) (bInterval 1
        // → 3 = 1ms). A wrong full-speed interval keeps the controller from
        // scheduling the endpoint at all (QEMU ignored it; real silicon doesn't).
        let interval = if dev.speed >= 3 {
            ep.interval.saturating_sub(1).clamp(3, 15)
        } else {
            (3 + (31 - ep.interval.max(1).leading_zeros())).clamp(3, 10)
        };
        if !self.configure_endpoint(slot, dev.lane, pipe, ep, interval, stride) {
            return false;
        }
        {
            let state = &mut self.pipes[pipe];
            state.slot = slot;
            state.dci = ep.ep * 2 + 1;
            state.pipe = pipe;
            state.report_len = match role {
                HidRole::Keyboard => (ep.mps as usize).clamp(8, 16),
                HidRole::Mouse => (ep.mps as usize).clamp(3, 16),
            };
            state.enq = 0;
            state.cycle = 1;
        }
        true
    }

    fn start_pipe(&mut self, index: usize) {
        self.pipes[index].ready = true;
        self.arm_report(index);
    }

    /// Probe for an xHCI controller, retain at most one keyboard and one mouse,
    /// configure their interrupt endpoints, and arm their first reports. `self.poll()`
    /// (driven by the timer IRQ) then streams input into the shared IRQ queue.
    fn init(&mut self) {
        let (bus, dev, func) = self.pci;
        lib::compact_println!("xHCI: probing {:02x}:{:02x}.{}", bus, dev, func);
        let cmd = cfg_read(bus, dev, func, 0x04);
        cfg_write(bus, dev, func, 0x04, (cmd & 0xFFFF) | 0x06);

        let bar0 = cfg_read(bus, dev, func, 0x10);
        if bar0 & 1 != 0 {
            lib::compact_println!("xHCI: BAR0 is I/O space (unexpected) - skipping");
            return;
        }
        let bar_hi = if (bar0 >> 1) & 3 == 2 {
            cfg_read(bus, dev, func, 0x14)
        } else {
            0
        };
        let bar = ((bar_hi as u64) << 32) | (bar0 & 0xFFFF_FFF0) as u64;
        if bar == 0 || bar & 0xFFF != 0 || bar0 == u32::MAX {
            lib::compact_println!("xHCI: invalid or unaligned BAR - skipping");
            return;
        }
        self.map_mmio(bar, 16);

        let cap0 = self.r32(0x00);
        let caplen = (cap0 & 0xFF) as usize;
        let hcs1 = self.r32(0x04);
        let max_slots = hcs1 & 0xFF;
        let max_ports = (hcs1 >> 24) & 0xFF;
        let op = caplen;
        let rt = (self.r32(0x18) & !0x1F) as usize; // RTSOFF
        let db = (self.r32(0x14) & !0x3) as usize; // DBOFF
        let stride = if (self.r32(0x10) >> 2) & 1 == 1 {
            64
        } else {
            32
        }; // HCCPARAMS1.CSZ
        // The fixed MMIO window is 64 KiB. Never let capability offsets address
        // the adjacent DMA region or wrap around the top of the address space.
        if caplen < 0x20
            || !caplen.is_multiple_of(4)
            || max_slots == 0
            || max_ports == 0
            || op + OP_PORTSC + max_ports as usize * 16 > 0x10000
            || !(0x20..=0x10000 - (IR0_ERDP + 8)).contains(&rt)
            || db < 0x20
            || db > 0x10000 - (max_slots as usize + 1) * 4
        {
            lib::compact_println!("xHCI: unsupported register layout - skipping");
            return;
        }
        self.rt = rt;
        self.db = db;

        if !self.bringup(op, rt, max_slots) {
            let _ = compact_fmt::writeln!(
                &mut lib::log::DebugCon,
                "xHCI: controller bringup failed (usbsts={:#x})",
                self.r32(op + OP_USBSTS)
            );
            return;
        }
        lib::compact_println!(
            "xHCI: running (slots={} ports={}) at {:02x}:{:02x}.{}",
            max_slots,
            max_ports,
            bus,
            dev,
            func
        );

        // Enumerate root ports once. A device that supplies either still-missing HID
        // role retains its slot and one of our two independent device lanes. Other
        // devices are disabled and the current probe lane is reused.
        let mut keyboard: Option<(u32, PortDevice, EpInfo)> = None;
        let mut mouse: Option<(u32, PortDevice, EpInfo)> = None;
        let mut retained_lanes = 0usize;
        for p in 1..=max_ports {
            let portsc = self.r32(op + OP_PORTSC + (p as usize - 1) * 0x10);
            if portsc & 1 == 0 {
                continue; // CCS = 0: nothing connected
            }
            let speed = (portsc >> 10) & 0xF; // 1=full 2=low 3=high 4=super
            if retained_lanes == DEVICE_LANES {
                break;
            }
            let lane = retained_lanes;
            let Some(slot) = self.address_port(op, lane, p, speed, stride) else {
                continue;
            };
            let dev = self.classify_addressed(slot, lane, p, speed);
            let _ = compact_fmt::writeln!(
                &mut lib::log::DebugCon,
                "xHCI: port {} speed {} class {} keyboard={} mouse={}",
                p,
                speed,
                dev.dev_class,
                dev.keyboard.is_some(),
                dev.mouse.is_some()
            );
            let mut retained = false;
            if keyboard.is_none()
                && let Some(ep) = dev.keyboard
            {
                keyboard = Some((slot, dev, ep));
                retained = true;
            }
            if mouse.is_none()
                && let Some(ep) = dev.mouse
            {
                mouse = Some((slot, dev, ep));
                retained = true;
            }
            if retained {
                retained_lanes += 1;
            } else {
                self.disable_slot(slot);
            }
            if keyboard.is_some() && mouse.is_some() {
                break;
            }
        }

        // Configure each distinct USB device once before adding either xHCI
        // interrupt endpoint. This also handles a composite keyboard+mouse without
        // resetting its first interface while the second is being prepared.
        let keyboard_device_ready = keyboard.is_some_and(|(slot, dev, _)| {
            self.control(slot, dev.lane, 0x00, 0x09, dev.cfg_value, 0, 0)
        });
        let mouse_device_ready = mouse.is_some_and(|(slot, dev, _)| {
            if keyboard.is_some_and(|(keyboard_slot, _, _)| keyboard_slot == slot) {
                keyboard_device_ready
            } else {
                self.control(slot, dev.lane, 0x00, 0x09, dev.cfg_value, 0, 0)
            }
        });

        let keyboard_ready = keyboard_device_ready
            && keyboard.is_some_and(|(slot, dev, ep)| {
                self.configure_hid(slot, &dev, ep, HidRole::Keyboard, 0, stride)
            });
        let mouse_ready = mouse_device_ready
            && mouse.is_some_and(|(slot, dev, ep)| {
                self.configure_hid(slot, &dev, ep, HidRole::Mouse, 1, stride)
            });

        if keyboard_ready && let Some((slot, dev, ep)) = keyboard {
            self.start_pipe(0);
            let _ = compact_fmt::writeln!(
                &mut lib::log::DebugCon,
                "xHCI: keyboard ready (slot {} port {} ep {} mps {}) at {:02x}:{:02x}.{}",
                slot,
                dev.port,
                ep.ep,
                ep.mps,
                self.pci.0,
                self.pci.1,
                self.pci.2
            );
        } else {
            lib::compact_println!("xHCI: no keyboard found");
        }
        if mouse_ready && let Some((slot, dev, ep)) = mouse {
            self.start_pipe(1);
            let _ = compact_fmt::writeln!(
                &mut lib::log::DebugCon,
                "xHCI: mouse ready (slot {} port {} ep {} mps {}) at {:02x}:{:02x}.{}",
                slot,
                dev.port,
                ep.ep,
                ep.mps,
                self.pci.0,
                self.pci.1,
                self.pci.2
            );
        } else {
            lib::compact_println!("xHCI: no mouse found");
        }
    }
}

// Boot initializes with interrupts disabled. Afterwards only the timer IRQ
// mutates these instances; no controller is moved or reinitialized at runtime.
static mut CONTROLLERS: [Controller; MAX_CONTROLLERS] =
    [const { Controller::new(0, (0, 0, 0)) }; MAX_CONTROLLERS];
static mut CONTROLLER_COUNT: usize = 0;

pub fn init() {
    debug_assert!(!crate::x86::interrupts_enabled());
    for_each_xhci(|bus, dev, func| unsafe {
        let index = CONTROLLER_COUNT;
        if index == MAX_CONTROLLERS {
            lib::compact_println!(
                "xHCI: controller limit reached, skipping {:02x}:{:02x}.{}",
                bus,
                dev,
                func
            );
            return;
        }
        let controller = &mut *(&raw mut CONTROLLERS).cast::<Controller>().add(index);
        *controller = Controller::new(index, (bus, dev, func));
        controller.init();
        CONTROLLER_COUNT += 1;
    });
    if unsafe { CONTROLLER_COUNT } == 0 {
        lib::compact_println!("xHCI: none found");
    }
}

pub fn poll() {
    // Called with interrupts disabled on the boot CPU, never during init.
    unsafe {
        for index in 0..CONTROLLER_COUNT {
            (&mut *(&raw mut CONTROLLERS).cast::<Controller>().add(index)).poll();
        }
    }
}
