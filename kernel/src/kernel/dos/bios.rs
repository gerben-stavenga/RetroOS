//! The DOS personality's own BIOS — Rust services behind a per-vector stub
//! array.
//!
//! DOS guests use one personality-owned firmware on every platform. Native
//! video firmware is isolated behind `BiosDisplayWorkspace`; it is never an
//! alternate DOS execution environment. The personality installs its IVT:
//! every IVT entry points into the ONE 256-slot `CD 31` stub array's vector
//! view (`STUB_SEG:vector*2`, slot index == vector), so any unhooked INT
//! traps to the kernel and is serviced here in Rust. The control slots reach
//! the same bytes through the `CTRL_STUB_SEG` segment alias — CS alone
//! separates the namespaces (see `CTRL_STUB_SEG` in dos.rs) — and "has the
//! guest hooked INT n?" is simply `IVT[n].segment != STUB_SEG`.
//!
//! This replaces the 16-bit C BIOS (`arch-interp/bios/bios.c`, compiled by
//! in-OS Turbo C and loaded at F000) that previously served the interpreter:
//! same services, but kernel-side Rust instead of guest code, owned by the
//! personality instead of one backend — a UEFI-booted metal machine gets it
//! for free.
//!
//! Guest-visible semantics are kept bit-for-bit where guests can observe
//! them: the BDA layout, the keyboard ring convention (head/tail stored as
//! offsets within segment 0x40), the equipment word, and the INT 10h
//! register contracts all match the old C BIOS.
//!
//! Keyboard and PIC services operate on the DOS machine's virtual devices.
//! Native video firmware remains isolated in its display workspace.

use crate::Regs;
use crate::kernel::thread;
use super::machine::{
    vm86_ip, vm86_iret, write_u16,
};
use super::dosabi::STUB_SEG;

// ============================================================================
// BIOS Data Area — a typed Rust projection at linear 0x400 (segment 0x40)
// ============================================================================

/// The BDA fields this BIOS touches, as a `repr(C, packed)` projection of
/// linear 0x400 — the same pattern as `LowMem`: one source of truth for
/// offsets via `offset_of!`, never magic addresses in the handlers. Padding
/// fields position the named ones at their canonical spots (const-asserted
/// below); guests read the same bytes by hardcoded offset, so the layout is
/// ABI, not style.
#[repr(C, packed)]
pub(crate) struct Bda {
    /// 0x00: COM1-4 + LPT1-3 port addresses, EBDA segment.
    io_ports: [u16; 8],
    /// 0x10: equipment word. Bits 4-5 = 00 mean "EGA/VGA with its own BIOS" —
    /// games' adapter detection (e.g. SkyRoads) checks this alongside
    /// INT 10h AX=1A00.
    equipment: u16,
    _pad_12: u8,
    /// 0x13: conventional memory size in KB (INT 12h reads this).
    mem_size_kb: u16,
    _pad_15: [u8; 2],
    /// 0x17: keyboard shift/ctrl/alt flag byte (INT 16h AH=02).
    kb_flags: u8,
    _pad_18: [u8; 2],
    /// 0x1A/0x1C: keyboard ring head/tail. BIOS convention: these hold
    /// *offsets within segment 0x40* (so 0x1E..0x3E), not ring indices.
    kb_head: u16,
    kb_tail: u16,
    /// 0x1E: the 16-entry (scancode:ascii) ring itself.
    kb_ring: [u16; 16],
    /// 0x3E/0x3F: diskette calibration state and motor-status latch.
    _diskette_recalibration_status: u8,
    diskette_motor_status: u8,
    /// 0x40: ticks until the BIOS turns off the diskette motor. Programs also
    /// use this byte as a one-tick delay because the ROM BIOS decrements it in
    /// INT 08h even when no motor is active.
    diskette_motor_timeout: u8,
    _pad_41: [u8; 8],
    /// 0x49: current video mode.
    video_mode: u8,
    /// 0x4A: text columns.
    columns: u16,
    /// 0x4C: bytes per display page; 0x4E: active page byte offset.
    video_page_size: u16,
    video_page_start: u16,
    /// 0x50: cursor position per page (low byte = column, high byte = row).
    cursor_pos: [u16; 8],
    /// 0x60: cursor shape (CX of INT 10h AH=01).
    cursor_shape: u16,
    /// 0x62: active display page.
    active_page: u8,
    /// 0x63: CRTC base port (0x3D4 = colour).
    pub(super) crtc_base: u16,
    /// 0x65: current CGA Mode-Control (port 0x3D8) value.
    crt_mode_ctl: u8,
    /// 0x66: current CGA Colour-Select (port 0x3D9) value.
    crt_palette: u8,
    _pad_67: [u8; 5],
    /// 0x6C: BIOS tick count (18.2 Hz), advanced by INT 08h.
    tick_count: u32,
    /// 0x70: midnight rollover flag.
    tick_rollover: u8,
    _pad_71: [u8; 15],
    /// 0x80/0x82: ring buffer start/end offsets (again 0x40-segment offsets).
    kb_ring_start: u16,
    kb_ring_end: u16,
    /// 0x84: text rows - 1.
    rows_minus1: u8,
    /// 0x85: character cell height.
    cell_height: u16,
    _pad_87: [u8; 15],
    /// 0x96: keyboard flags 3. Bit 4 = enhanced (101/102-key) keyboard
    /// installed.
    kb_flags3: u8,
}

/// The BDA's canonical offsets are guest ABI — pin the projection to them.
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(Bda, equipment) == 0x10);
    assert!(offset_of!(Bda, mem_size_kb) == 0x13);
    assert!(offset_of!(Bda, kb_flags) == 0x17);
    assert!(offset_of!(Bda, kb_head) == 0x1A);
    assert!(offset_of!(Bda, kb_ring) == 0x1E);
    assert!(offset_of!(Bda, diskette_motor_timeout) == 0x40);
    assert!(offset_of!(Bda, video_mode) == 0x49);
    assert!(offset_of!(Bda, columns) == 0x4A);
    assert!(offset_of!(Bda, cursor_pos) == 0x50);
    assert!(offset_of!(Bda, cursor_shape) == 0x60);
    assert!(offset_of!(Bda, active_page) == 0x62);
    assert!(offset_of!(Bda, crtc_base) == 0x63);
    assert!(offset_of!(Bda, crt_mode_ctl) == 0x65);
    assert!(offset_of!(Bda, crt_palette) == 0x66);
    assert!(offset_of!(Bda, tick_count) == 0x6C);
    assert!(offset_of!(Bda, kb_ring_start) == 0x80);
    assert!(offset_of!(Bda, rows_minus1) == 0x84);
    assert!(offset_of!(Bda, kb_flags3) == 0x96);
};

impl Bda {
    pub(super) const BASE: usize = 0x400;

    pub(crate) fn video_mode<A: crate::Arch>(machine: &A) -> u8 {
        machine.read(Self::BASE + core::mem::offset_of!(Self, video_mode))
    }

    pub(crate) fn tick_count<A: crate::Arch>(machine: &A) -> u32 {
        machine.read(Self::BASE + core::mem::offset_of!(Self, tick_count))
    }

    pub(crate) fn set_page0_cursor<A: crate::Arch>(machine: &mut A, col: u8, row: u8) {
        let addr = Self::BASE + core::mem::offset_of!(Self, cursor_pos);
        machine.write::<u16>(addr, u16::from_le_bytes([col, row]));
    }

    pub(crate) fn keyboard_buffer_nonempty<A: crate::Arch>(machine: &A) -> bool {
        let head: u16 = machine.read(Self::BASE + core::mem::offset_of!(Self, kb_head));
        let tail: u16 = machine.read(Self::BASE + core::mem::offset_of!(Self, kb_tail));
        head != tail
    }

    pub(crate) fn clear_keyboard_buffer<A: crate::Arch>(machine: &mut A) {
        let first = core::mem::offset_of!(Self, kb_ring) as u16;
        machine.write::<u16>(Self::BASE + core::mem::offset_of!(Self, kb_head), first);
        machine.write::<u16>(Self::BASE + core::mem::offset_of!(Self, kb_tail), first);
        machine.copy_to(Self::BASE + core::mem::offset_of!(Self, kb_ring), &[0; 32]);
    }

    pub(crate) fn pop_keyboard_word<A: crate::Arch>(machine: &mut A) -> Option<u16> {
        let head_addr = Self::BASE + core::mem::offset_of!(Self, kb_head);
        let tail_addr = Self::BASE + core::mem::offset_of!(Self, kb_tail);
        let head: u16 = machine.read(head_addr);
        let tail: u16 = machine.read(tail_addr);
        if head == tail {
            return None;
        }
        let first = core::mem::offset_of!(Self, kb_ring) as u16;
        let end = first + core::mem::size_of::<[u16; 16]>() as u16;
        let word = machine.read::<u16>(Self::BASE + head as usize);
        let next = if head + 2 >= end { first } else { head + 2 };
        machine.write::<u16>(head_addr, next);
        Some(word)
    }

    pub(crate) fn keyboard_flags<A: crate::Arch>(machine: &A) -> u8 {
        machine.read(Self::BASE + core::mem::offset_of!(Self, kb_flags))
    }

    pub(crate) fn set_keyboard_flags<A: crate::Arch>(machine: &mut A, flags: u8) {
        machine.write(Self::BASE + core::mem::offset_of!(Self, kb_flags), flags);
    }
}

macro_rules! bda_field {
    ($machine:expr, $field:ident) => {
        $machine.read(Bda::BASE + core::mem::offset_of!(Bda, $field))
    };
    ($machine:expr, $field:ident = $val:expr) => {
        $machine.write(Bda::BASE + core::mem::offset_of!(Bda, $field), $val)
    };
}
pub(super) use bda_field;

mod clock;
pub(crate) use clock::win16_int1a;
pub(super) mod keyboard;
mod system;
mod serial;
pub(super) mod vbe;
pub(super) mod video;

// ============================================================================
// Install
// ============================================================================

/// Install the personality BIOS: point all 256 IVT entries at the stub
/// array's vector view and seed the BDA. The stub bytes themselves are
/// filled by `setup_ivt` (one array serves vector and control views). The
/// kernel-DOS IVT redirects written after this overwrite their vectors with
/// identical values — the layering matches a real machine (BIOS first, DOS
/// on top). This is deliberately identical with or without a platform ROM.
pub(super) fn install<A: crate::Arch>(machine: &mut A) {
    crate::compact_dbg_println!("DOS: installing substitute BIOS (vga_passthrough={})",
        crate::kernel::platform::get().vga_passthrough);
    // Serviced vectors use their own trap stub; unused vectors remain NULL.
    for n in 0..256u32 {
        // INT 4Bh (VDS) needs a callable default even though VDS is absent
        // (40:7B bit 5 remains clear). Some DOS extenders unconditionally
        // balance an earlier "disable DMA translation" with AX=810Ch during
        // teardown. A real BIOS/DOS dummy handler simply IRETs; a NULL vector
        // transfers control to 0000:0000 and turns that harmless cleanup call
        // into execution of the IVT itself.
        let serviced = matches!(n,
            0x00..=0x33 | 0x40..=0x46 | 0x4A..=0x4B | 0x67 | 0x70..=0x77);
        if !serviced {
            // NULL, not a dummy stub — a real BIOS leaves the unused vectors
            // (the 0x60-0x67 and 0x78-0x7F user ranges especially) at
            // 0000:0000, and TSRs SCAN for that to find a free vector to
            // publish their API on. Pointing all 256 at the shared dummy
            // advertises zero free vectors: UltraMID's scan found none and
            // installed itself on INT 00h instead of INT 79h, so the game's
            // probe missed it ("UltraMID not found") and the unload left a
            // divide-by-zero vector dangling into freed memory.
            write_u16(machine, 0, n * 4, 0);
            write_u16(machine, 0, n * 4 + 2, 0);
            continue;
        }
        write_u16(machine, 0, n * 4, (n * 2) as u16);
        write_u16(machine, 0, n * 4 + 2, STUB_SEG);
    }
    // DOS/4GW (raptor's bound extender) finds the BIOS dummy handler by
    // scanning for an address that appears in TWO entries; the NULLs above
    // are that duplicate now, so the scan still terminates.
    seed_bda(machine);
    video::install_rom_font(machine);
}

/// Seed the BDA fields a real POST would have set.
fn seed_bda<A: crate::Arch>(machine: &mut A) {
    // Zero the whole BDA first: on a UEFI machine this low page holds
    // whatever the firmware left behind (a real POST cleared it), and guests
    // read unseeded fields directly — DOS/4GW #DE'd converting a leftover
    // 0xFFF1xxxx at 40:6C to a time of day.
    machine.copy_to(Bda::BASE, &[0u8; 0x100]);
    // Tick-of-day counter: a real POST seeds 40:6C from the RTC.
    let ticks = super::dos::rtc_ticks_today(machine);
    bda_field!(machine, tick_count = ticks);
    bda_field!(machine, mem_size_kb = 640u16);
    bda_field!(machine, video_mode = 3u8); // 80x25 colour text
    bda_field!(machine, columns = 80u16);
    bda_field!(machine, video_page_size = 0x1000u16);
    bda_field!(machine, crtc_base = 0x03D4u16);
    bda_field!(machine, rows_minus1 = 24u8);
    bda_field!(machine, cell_height = 16u16);
    // Bit 0: diskette drives present; bits 7-6: drive count minus one.
    // Two floppy units (the A:/B: image slots), matching the CDS.
    bda_field!(machine, equipment = 0x0241u16);
    machine.write::<u16>(0x400, 0x3f8);
    // A real POST leaves the text cursor shape and the CGA compatibility
    // register mirrors set for mode 3; AH=1Bh publishes all three, and a guest
    // reading them back as zero sees a machine with no cursor.
    bda_field!(machine, cursor_shape = video::TEXT_CURSOR_SHAPE);
    bda_field!(machine, crt_mode_ctl = 0x29u8);
    bda_field!(machine, crt_palette = 0x30u8);
    bda_field!(machine, kb_head = keyboard::KB_RING_FIRST);
    bda_field!(machine, kb_tail = keyboard::KB_RING_FIRST);
    bda_field!(machine, kb_ring_start = keyboard::KB_RING_FIRST);
    bda_field!(machine, kb_ring_end = keyboard::KB_RING_END);
    bda_field!(machine, kb_flags3 = keyboard::KB3_ENHANCED);
    video::seed_video_static_info(machine);
}

// ============================================================================
// Dispatch
// ============================================================================

/// Service an INT vector the kernel-DOS dispatcher doesn't own (called from
/// `rm_vector_dispatch`, CS == `STUB_SEG`). The guest's INT pushed
/// FLAGS/CS/IP; the stub's `CD 31` trapped with IP = vector*2 + 2. Unless a
/// service parks or chains, the frame is popped here — IRET semantics, like
/// the old C BIOS's `interrupt` handlers.
pub(super) fn dispatch<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    let int_num = (ip.wrapping_sub(2) / 2) as u8;

    match int_num {
        0x08 => {
            if clock::int08(machine, dos, regs) {
                return thread::KernelAction::Done;
            }
        }
        0x09 => {
            if keyboard::int09(machine, dos, regs) {
                return thread::KernelAction::Done;
            }
        }
        0x0A..=0x0F => {
            if let Some(irq) = dos.pc.vpic.master_ocw2(0x20) {
                dos.pc.audio.lock().sb.acknowledge_irq(machine, irq);
            }
        }
        0x70..=0x77 => {
            // Slave-PIC IRQ default: EOI both.
            dos.pc.vpic.slave_ocw2(0x20);
            if let Some(irq) = dos.pc.vpic.master_ocw2(0x20) {
                dos.pc.audio.lock().sb.acknowledge_irq(machine, irq);
            }
        }
        0x10 => video::int10(machine, bios_display, dos, regs),
        0x11 => system::int11(machine, regs),
        0x12 => system::int12(machine, regs),
        0x14 => serial::int14(dos, regs),
        0x15 => system::int15(machine, regs),
        0x16 => {
            if keyboard::int16(machine, regs, ip) == keyboard::Parked::Yes {
                return thread::KernelAction::Done;
            }
        }
        0x1A => clock::int1a(machine, regs),
        _ => {} // plain IRET — a real BIOS leaves no vector null
    }

    vm86_iret(machine, regs);
    thread::KernelAction::Done
}
