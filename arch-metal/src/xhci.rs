//! xHCI USB host-controller driver — just enough to read a USB-HID *boot*
//! keyboard on a legacy-free machine (no i8042). Modern laptops (e.g. the Razer
//! Blade) hang the internal keyboard off the chipset's xHCI controller, so this
//! is the only way to get keystrokes there. When complete it feeds the same
//! `irq::QUEUE` (Irq::Key scancodes) the i8042 path does, so nothing above the
//! arch boundary changes — the kernel still just drains key events.
//!
//! WIP — milestone 1: find the controller on PCI and map its register set.
//! Still to come: reset + ring setup, port/device enumeration, SET_PROTOCOL
//! (boot), the interrupt-IN report read, and HID-usage → scancode translation.

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

/// Scan PCI config space for an xHCI controller — class 0x0C (serial bus),
/// subclass 0x03 (USB), prog-IF 0x30 (xHCI). Brute-force over all 256 buses is
/// fine for a one-shot boot probe and finds a controller on any bus.
fn find_xhci() -> Option<(u8, u8, u8)> {
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
                    return Some((bus, dev, func));
                }
                // Only probe funcs 1-7 on a multi-function device.
                if func == 0 && cfg_read(bus, dev, 0, 0x0C) & 0x0080_0000 == 0 {
                    break;
                }
            }
        }
    }
    None
}

// ── Controller MMIO ────────────────────────────────────────────────────────
// One 64 KiB window after the LAPIC (F0000) / HPET (F1000) / IOAPIC (F2000)
// mappings — covers the capability, operational, runtime and doorbell regions.
const MMIO_VA: usize = 0xFFF1_0000;

fn map_mmio(phys: u64, pages: usize) {
    for i in 0..pages {
        crate::paging2::map_user_page_phys(
            MMIO_VA / crate::paging2::PAGE_SIZE + i,
            phys / crate::paging2::PAGE_SIZE as u64 + i as u64,
            crate::paging2::flags::CACHE_DISABLE,
        );
    }
}

fn r32(off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((MMIO_VA + off) as *const u32) }
}
fn w32(off: usize, v: u32) {
    unsafe { core::ptr::write_volatile((MMIO_VA + off) as *mut u32, v) }
}
/// 64-bit controller registers: write low then high dword (always safe; some
/// don't allow a single qword access).
fn w64(off: usize, v: u64) {
    w32(off, v as u32);
    w32(off + 4, (v >> 32) as u32);
}

// ── DMA region: DCBAA + command ring + event ring + ERST in one contiguous
// block, mapped at a fixed VA, cache-disabled (simple + coherent, as NVMe does).
const DMA_VA: usize = 0xFFF2_0000;
const DCBAA_OFF: usize = 0x0000; // device-context base address array
const CMD_OFF: usize = 0x1000; // command ring (256 TRBs)
const EVT_OFF: usize = 0x2000; // event ring (256 TRBs)
const ERST_OFF: usize = 0x3000; // event ring segment table (1 entry)
const INCTX_OFF: usize = 0x4000; // input context (Address Device / Configure EP)
const DEVCTX_OFF: usize = 0x5000; // device (output) context, in DCBAA[slot]
const EP0_OFF: usize = 0x6000; // default control endpoint transfer ring
const XFER_OFF: usize = 0x7000; // control-transfer data buffer (descriptors)
const DMA_PAGES: usize = 8;
const RING_TRBS: usize = 256;

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

// Controller layout, resolved once in init(): region bases (from MMIO_VA) and
// the DMA physical base. Single controller, single-threaded boot.
static mut OP: usize = 0;
static mut RT: usize = 0; // runtime regs (interrupter 0 / event ring)
static mut DB: usize = 0; // doorbell array
static mut DMA_PHYS: u64 = 0;
// Producer/consumer cursors for the command ring (we enqueue) and event ring
// (the controller enqueues, we dequeue). Each carries its cycle bit.
static mut CMD_ENQ: usize = 0;
static mut CMD_CYCLE: u32 = 1;
static mut EVT_DEQ: usize = 0;
static mut EVT_CYCLE: u32 = 1;

/// Enqueue a TRB on the command ring and ring doorbell 0. `control` carries the
/// TRB type (`<<10`) plus any command-specific fields (e.g. slot id in 31:24);
/// the cycle bit is added here. At the ring's last slot (the Link TRB) we flip
/// its cycle bit, wrap, and toggle our cycle.
fn ring_cmd(param: u64, status: u32, control: u32) {
    unsafe {
        let trb = (DMA_VA + CMD_OFF + CMD_ENQ * 16) as *mut u32;
        core::ptr::write_volatile(trb as *mut u64, param);
        core::ptr::write_volatile(trb.add(2), status);
        core::ptr::write_volatile(trb.add(3), control | CMD_CYCLE);
        CMD_ENQ += 1;
        if CMD_ENQ == RING_TRBS - 1 {
            let link = (DMA_VA + CMD_OFF + (RING_TRBS - 1) * 16) as *mut u32;
            let c = core::ptr::read_volatile(link.add(3)) & !1;
            core::ptr::write_volatile(link.add(3), c | CMD_CYCLE);
            CMD_ENQ = 0;
            CMD_CYCLE ^= 1;
        }
        w32(DB, 0); // doorbell 0 (at MMIO_VA + DB) = command ring
    }
}

/// Dequeue one event TRB (bounded wait). Returns (trb_type, completion_code,
/// slot_id) and advances ERDP. None on timeout.
fn poll_event() -> Option<(u32, u32, u32)> {
    for _ in 0..50_000_000u64 {
        unsafe {
            let trb = (DMA_VA + EVT_OFF + EVT_DEQ * 16) as *const u32;
            let ctrl = core::ptr::read_volatile(trb.add(3));
            if ctrl & 1 == EVT_CYCLE {
                let ttype = (ctrl >> 10) & 0x3F;
                let cc = core::ptr::read_volatile(trb.add(2)) >> 24;
                let slot = ctrl >> 24;
                EVT_DEQ += 1;
                if EVT_DEQ == RING_TRBS {
                    EVT_DEQ = 0;
                    EVT_CYCLE ^= 1;
                }
                // Advance ERDP (bits 4:63) and clear the Event-Handler-Busy bit.
                w64(RT + IR0_ERDP, (DMA_PHYS + (EVT_OFF + EVT_DEQ * 16) as u64) | (1 << 3));
                return Some((ttype, cc, slot));
            }
        }
        core::hint::spin_loop();
    }
    None
}

/// Wait for the next event of TRB type `want` (33=Command Completion,
/// 32=Transfer), skipping unrelated events queued ahead of it (e.g. a Port
/// Status Change from a reset). Returns (completion_code, slot_id).
fn wait_event(want: u32) -> Option<(u32, u32)> {
    for _ in 0..64 {
        let (ttype, cc, slot) = poll_event()?;
        if ttype == want {
            return Some((cc, slot));
        }
    }
    None
}

/// Enable Slot (TRB type 9) → a Command Completion Event carries the assigned
/// slot id. Returns it on success (completion code 1).
fn enable_slot() -> Option<u32> {
    // Enable interrupter 0 (IMAN.IE) — some controllers only post events to the
    // ring once the interrupter is enabled, even for a polling driver.
    unsafe { w32(RT + 0x20, r32(RT + 0x20) | 0x2) };
    ring_cmd(0, 0, 9 << 10); // TRB type 9 = Enable Slot
    match wait_event(33)? {
        (1, slot) => Some(slot),
        _ => None,
    }
}

// EP0 (default control endpoint) transfer-ring cursor.
static mut EP0_ENQ: usize = 0;
static mut EP0_CYCLE: u32 = 1;

/// Enqueue a TRB on the EP0 transfer ring (no doorbell — the caller rings it
/// once per transfer descriptor). Handles the Link TRB wrap like the cmd ring.
fn ep0_trb(param: u64, status: u32, control: u32) {
    unsafe {
        let trb = (DMA_VA + EP0_OFF + EP0_ENQ * 16) as *mut u32;
        core::ptr::write_volatile(trb as *mut u64, param);
        core::ptr::write_volatile(trb.add(2), status);
        core::ptr::write_volatile(trb.add(3), control | EP0_CYCLE);
        EP0_ENQ += 1;
        if EP0_ENQ == RING_TRBS - 1 {
            let link = (DMA_VA + EP0_OFF + (RING_TRBS - 1) * 16) as *mut u32;
            let c = core::ptr::read_volatile(link.add(3)) & !1;
            core::ptr::write_volatile(link.add(3), c | EP0_CYCLE);
            EP0_ENQ = 0;
            EP0_CYCLE ^= 1;
        }
    }
}

/// Issue a control transfer on EP0: Setup → (Data) → Status stages, ring the
/// slot's doorbell (DCI 1 = control EP), wait for the Transfer Event. IN data
/// (if any) lands in the XFER buffer. Returns true on Success/Short-Packet.
fn control(slot: u32, bm_req: u32, b_req: u32, w_value: u32, w_index: u32, w_len: u32) -> bool {
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
    ep0_trb(setup, 8, (1 << 6) | (2 << 10) | (trt << 16)); // IDT, type 2, TRT
    if w_len > 0 {
        let buf = unsafe { DMA_PHYS } + XFER_OFF as u64;
        ep0_trb(buf, w_len, (3 << 10) | ((dir_in as u32) << 16)); // type 3, DIR
    }
    // Status Stage: opposite direction, Interrupt-On-Completion so we get an event.
    let status_dir = if dir_in && w_len > 0 { 0 } else { 1 };
    ep0_trb(0, 0, (1 << 5) | (4 << 10) | (status_dir << 16)); // IOC, type 4, DIR
    let db = unsafe { DB };
    w32(db + slot as usize * 4, 1); // ring slot doorbell, DCI 1 (EP0)
    matches!(wait_event(32), Some((1, _)) | Some((13, _))) // Success or Short Packet
}

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

/// Reset the controller, stand up the DCBAA + command/event rings, and run it.
/// Returns false (without hanging) if it never comes ready.
fn bringup(op: usize, rt: usize, max_slots: u32) -> bool {
    // Wait until the controller is ready, halt it, then host-controller reset.
    if !wait(|| r32(op + OP_USBSTS) & USBSTS_CNR == 0) {
        return false;
    }
    w32(op + OP_USBCMD, r32(op + OP_USBCMD) & !USBCMD_RS);
    if !wait(|| r32(op + OP_USBSTS) & USBSTS_HCH != 0) {
        return false;
    }
    w32(op + OP_USBCMD, USBCMD_HCRST);
    if !wait(|| r32(op + OP_USBCMD) & USBCMD_HCRST == 0)
        || !wait(|| r32(op + OP_USBSTS) & USBSTS_CNR == 0)
    {
        return false;
    }

    // One contiguous DMA block for all the structures.
    let Some(page) = crate::phys_mm::alloc_phys_contig(DMA_PAGES, 0) else {
        return false;
    };
    let phys = page * 0x1000;
    map_dma(phys, DMA_PAGES);
    unsafe {
        core::ptr::write_bytes(DMA_VA as *mut u8, 0, DMA_PAGES * 0x1000);
        OP = op;
        DMA_PHYS = phys;
    }

    // Enable all device slots; point the controller at the (zeroed) DCBAA.
    w32(op + OP_CONFIG, max_slots);
    w64(op + OP_DCBAAP, phys + DCBAA_OFF as u64);

    // Command ring: a Link TRB at the end loops back to the start (TRB type 6,
    // Toggle-Cycle set). CRCR points at it with Ring-Cycle-State = 1.
    let link = (DMA_VA + CMD_OFF + (RING_TRBS - 1) * 16) as *mut u32;
    unsafe {
        core::ptr::write_volatile(link as *mut u64, phys + CMD_OFF as u64);
        core::ptr::write_volatile(link.add(3), (6 << 10) | (1 << 1));
    }
    w64(op + OP_CRCR, (phys + CMD_OFF as u64) | 1);

    // Event ring: one ERST segment describing the event-ring buffer.
    unsafe {
        let erst = DMA_VA + ERST_OFF;
        core::ptr::write_volatile(erst as *mut u64, phys + EVT_OFF as u64);
        core::ptr::write_volatile((erst + 8) as *mut u32, RING_TRBS as u32);
    }
    w32(rt + IR0_ERSTSZ, 1);
    w64(rt + IR0_ERDP, phys + EVT_OFF as u64);
    w64(rt + IR0_ERSTBA, phys + ERST_OFF as u64);

    // Run.
    w32(op + OP_USBCMD, r32(op + OP_USBCMD) | USBCMD_RS);
    wait(|| r32(op + OP_USBSTS) & USBSTS_HCH == 0)
}

fn map_dma(phys: u64, pages: usize) {
    for i in 0..pages {
        crate::paging2::map_user_page_phys(
            DMA_VA / crate::paging2::PAGE_SIZE + i,
            phys / crate::paging2::PAGE_SIZE as u64 + i as u64,
            crate::paging2::flags::CACHE_DISABLE,
        );
    }
}

/// Reset a root-hub port so the attached device enters the Default state and
/// the port enables (USB2 needs the reset; USB3 auto-enables, but it's
/// harmless). Preserves the port's RW1C change bits. The controller owns the
/// reset timing and signals completion via Port-Enabled — we just wait.
fn reset_port(op: usize, port: u32) {
    let off = op + OP_PORTSC + (port as usize - 1) * 0x10;
    let rw1c = 0x00FE_0000; // CSC/PEC/WRC/OCC/PRC/PLC/CEC — write-1-to-clear
    w32(off, (r32(off) & !rw1c) | (1 << 4)); // PR = Port Reset
    wait(|| r32(off) & (1 << 1) != 0); // PED (Port Enabled)
}

/// Initialise the default-control-endpoint (EP0) transfer ring: zeroed, with a
/// Link TRB at the end looping to the start (Toggle Cycle set).
fn init_ep0_ring() {
    unsafe {
        core::ptr::write_bytes((DMA_VA + EP0_OFF) as *mut u8, 0, 0x1000);
        let link = (DMA_VA + EP0_OFF + (RING_TRBS - 1) * 16) as *mut u32;
        core::ptr::write_volatile(link as *mut u64, DMA_PHYS + EP0_OFF as u64);
        core::ptr::write_volatile(link.add(3), (6 << 10) | (1 << 1));
    }
}

/// Build the input context (Slot + EP0) and issue Address Device, moving the
/// device to the Addressed state (the controller performs SET_ADDRESS on the
/// wire). `stride` is the context size (32 or 64 bytes per HCCPARAMS1.CSZ).
fn address_device(slot: u32, port: u32, speed: u32, stride: usize) -> bool {
    init_ep0_ring();
    unsafe {
        let inctx = DMA_VA + INCTX_OFF;
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
        core::ptr::write_volatile((ep0 + 8) as *mut u64, (DMA_PHYS + EP0_OFF as u64) | 1);
        // DCBAA[slot] → device (output) context.
        core::ptr::write_volatile(
            (DMA_VA + DCBAA_OFF + slot as usize * 8) as *mut u64,
            DMA_PHYS + DEVCTX_OFF as u64,
        );
    }
    // Address Device (TRB type 11): input-context pointer, slot id in 31:24.
    let inctx_phys = unsafe { DMA_PHYS } + INCTX_OFF as u64;
    ring_cmd(inctx_phys, 0, (11 << 10) | (slot << 24));
    matches!(wait_event(33), Some((1, _)))
}

/// Probe for an xHCI controller, bring it up, find the keyboard's port, and put
/// the device into the Addressed state. WIP: control transfers (descriptors,
/// SET_PROTOCOL) and the HID report read come next.
pub fn init() {
    let Some((bus, dev, func)) = find_xhci() else {
        lib::println!("xHCI: none found");
        return;
    };
    let cmd = cfg_read(bus, dev, func, 0x04);
    cfg_write(bus, dev, func, 0x04, (cmd & 0xFFFF) | 0x06);

    let bar0 = cfg_read(bus, dev, func, 0x10);
    if bar0 & 1 != 0 {
        lib::println!("xHCI: BAR0 is I/O space (unexpected) — skipping");
        return;
    }
    let bar_hi = if (bar0 >> 1) & 3 == 2 {
        cfg_read(bus, dev, func, 0x14)
    } else {
        0
    };
    let bar = (((bar_hi as u64) << 32) | (bar0 & 0xFFFF_FFF0) as u64) & !0xFFF;
    map_mmio(bar, 16);

    let cap0 = r32(0x00);
    let caplen = (cap0 & 0xFF) as usize;
    let hcs1 = r32(0x04);
    let max_slots = hcs1 & 0xFF;
    let max_ports = (hcs1 >> 24) & 0xFF;
    let op = caplen;
    let rt = (r32(0x18) & !0x1F) as usize; // RTSOFF
    let db = (r32(0x14) & !0x3) as usize; // DBOFF
    let stride = if (r32(0x10) >> 2) & 1 == 1 { 64 } else { 32 }; // HCCPARAMS1.CSZ
    unsafe {
        RT = rt;
        DB = db;
    }

    if !bringup(op, rt, max_slots) {
        lib::println!("xHCI: controller bringup failed (usbsts={:#x})", r32(op + OP_USBSTS));
        return;
    }
    lib::println!("xHCI: running (slots={} ports={})", max_slots, max_ports);

    // Find the connected root-hub port (the keyboard).
    let (mut port, mut speed) = (0u32, 0u32);
    for p in 1..=max_ports {
        let portsc = r32(op + OP_PORTSC + (p as usize - 1) * 0x10);
        if portsc & 1 != 0 {
            port = p;
            speed = (portsc >> 10) & 0xF; // 1=full 2=low 3=high 4=super
        }
    }
    if port == 0 {
        lib::println!("xHCI: no device connected");
        return;
    }

    // Reset the port, allocate a slot, and address the device.
    reset_port(op, port);
    let Some(slot) = enable_slot() else {
        lib::println!("xHCI: Enable Slot failed (usbsts={:#x})", r32(op + OP_USBSTS));
        return;
    };
    if !address_device(slot, port, speed, stride) {
        lib::println!("xHCI: Address Device failed (usbsts={:#x})", r32(op + OP_USBSTS));
        return;
    }
    lib::println!("xHCI: device addressed (slot {} port {} speed {})", slot, port, speed);

    // Control transfer proof: GET_DESCRIPTOR(device, 18 bytes) → VID/PID.
    if control(slot, 0x80, 0x06, 0x0100, 0, 18) {
        unsafe {
            let d = DMA_VA + XFER_OFF;
            let rd = |o: usize| core::ptr::read_volatile((d + o) as *const u8) as u16;
            let vid = rd(8) | (rd(9) << 8);
            let pid = rd(10) | (rd(11) << 8);
            lib::println!("xHCI: device descriptor VID={:04x} PID={:04x} class={}", vid, pid, rd(4));
        }
    } else {
        lib::println!("xHCI: GET_DESCRIPTOR failed");
    }
}
