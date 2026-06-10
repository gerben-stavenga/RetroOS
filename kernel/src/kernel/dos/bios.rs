//! The DOS personality's own BIOS — Rust services behind a per-vector stub
//! array.
//!
//! On machines with no native BIOS ROM (the interpreter's empty guest RAM
//! today; UEFI metal later), DOS guests calling INT 08/10/11/16/1A would land
//! on a null IVT and self-corrupt. The personality installs its own firmware:
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
//! Port I/O goes through `machine::emulate_inb`/`emulate_outb` — the same
//! virtual port layer guest IN/OUT instructions trap into — NOT the raw
//! `Arch` port calls. The PIC (vpic) and the 8042 (vkbd) are *kernel-side*
//! per-thread devices: a raw `machine.outb(0x20, 0x20)` would bypass the
//! vpic, the EOI would never retire IRQ0, and timer ticks would freeze
//! (reproducer: SkyRoads fades its palette in on a tick wait — black screen
//! forever).

use arch_abi::GuestBytes;
use crate::arch::Vcpu;
use crate::kernel::thread;
use super::machine::{
    self, emulate_inb, emulate_outb, vm86_ip, vm86_pop, vm86_sp, vm86_ss, read_u16, write_u16,
};
use super::dos::STUB_SEG;

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
struct Bda {
    /// 0x00: COM1-4 + LPT1-3 port addresses, EBDA segment.
    io_ports: [u16; 8],
    /// 0x10: equipment word. Bits 4-5 = 00 mean "EGA/VGA with its own BIOS" —
    /// games' adapter detection (e.g. SkyRoads) checks this alongside
    /// INT 10h AX=1A00.
    equipment: u16,
    _pad_12: [u8; 5],
    /// 0x17: keyboard shift/ctrl/alt flag byte (INT 16h AH=02).
    kb_flags: u8,
    _pad_18: [u8; 2],
    /// 0x1A/0x1C: keyboard ring head/tail. BIOS convention: these hold
    /// *offsets within segment 0x40* (so 0x1E..0x3E), not ring indices.
    kb_head: u16,
    kb_tail: u16,
    /// 0x1E: the 16-entry (scancode:ascii) ring itself.
    kb_ring: [u16; 16],
    _pad_3e: [u8; 11],
    /// 0x49: current video mode.
    video_mode: u8,
    /// 0x4A: text columns.
    columns: u16,
    _pad_4c: [u8; 4],
    /// 0x50: cursor position per page (low byte = column, high byte = row).
    cursor_pos: [u16; 8],
    /// 0x60: cursor shape (CX of INT 10h AH=01).
    cursor_shape: u16,
    /// 0x62: active display page.
    active_page: u8,
    /// 0x63: CRTC base port (0x3D4 = colour).
    crtc_base: u16,
    _pad_65: [u8; 7],
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
}

/// The BDA's canonical offsets are guest ABI — pin the projection to them.
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(Bda, equipment) == 0x10);
    assert!(offset_of!(Bda, kb_flags) == 0x17);
    assert!(offset_of!(Bda, kb_head) == 0x1A);
    assert!(offset_of!(Bda, kb_ring) == 0x1E);
    assert!(offset_of!(Bda, video_mode) == 0x49);
    assert!(offset_of!(Bda, columns) == 0x4A);
    assert!(offset_of!(Bda, cursor_pos) == 0x50);
    assert!(offset_of!(Bda, cursor_shape) == 0x60);
    assert!(offset_of!(Bda, active_page) == 0x62);
    assert!(offset_of!(Bda, crtc_base) == 0x63);
    assert!(offset_of!(Bda, tick_count) == 0x6C);
    assert!(offset_of!(Bda, kb_ring_start) == 0x80);
    assert!(offset_of!(Bda, rows_minus1) == 0x84);
};

const BDA_BASE: usize = 0x400;

/// Linear address of a `Bda` field: `bda(offset_of!(Bda, tick_count))`.
#[inline]
fn bda(field_off: usize) -> usize {
    BDA_BASE + field_off
}

/// Ring head/tail values as the guest stores them: segment-0x40 offsets.
const KB_RING_FIRST: u16 = core::mem::offset_of!(Bda, kb_ring) as u16;
const KB_RING_END: u16 = KB_RING_FIRST + (16 * 2);

macro_rules! bda_field {
    ($regs:expr, $field:ident) => {
        $regs.read(bda(core::mem::offset_of!(Bda, $field)))
    };
    ($regs:expr, $field:ident = $val:expr) => {
        $regs.write(bda(core::mem::offset_of!(Bda, $field)), $val)
    };
}

// ============================================================================
// Install
// ============================================================================

/// True when a native BIOS ROM owns the machine: every legacy BIOS has a
/// far-JMP (0xEA) at the reset vector F000:FFF0. The interpreter's zeroed
/// guest RAM and a UEFI-booted machine (no CSM, nothing mapped at the legacy
/// ROM window) read something else there.
pub(super) fn native_bios_present(regs: &Vcpu) -> bool {
    regs.read::<u8>(0xFFFF0) == 0xEA
}

/// Install the personality BIOS: point all 256 IVT entries at the stub
/// array's vector view and seed the BDA. The stub bytes themselves are
/// filled by `setup_ivt` (one array serves vector and control views). The
/// kernel-DOS IVT redirects written after this overwrite their vectors with
/// identical values — the layering matches a real machine (BIOS first, DOS
/// on top).
pub(super) fn install(regs: &mut Vcpu) {
    for n in 0..256u32 {
        write_u16(regs, 0, n * 4, (n * 2) as u16);
        write_u16(regs, 0, n * 4 + 2, STUB_SEG);
    }
    seed_bda(regs);
}

/// Seed the BDA fields a real POST would have set.
fn seed_bda(regs: &mut Vcpu) {
    bda_field!(regs, video_mode = 3u8); // 80x25 colour text
    bda_field!(regs, columns = 80u16);
    bda_field!(regs, crtc_base = 0x03D4u16);
    bda_field!(regs, rows_minus1 = 24u8);
    bda_field!(regs, cell_height = 16u16);
    bda_field!(regs, equipment = 0x0001u16);
    bda_field!(regs, kb_head = KB_RING_FIRST);
    bda_field!(regs, kb_tail = KB_RING_FIRST);
    bda_field!(regs, kb_ring_start = KB_RING_FIRST);
    bda_field!(regs, kb_ring_end = KB_RING_END);
}

// ============================================================================
// Dispatch
// ============================================================================

/// Service an INT vector the kernel-DOS dispatcher doesn't own (called from
/// `rm_vector_dispatch`, CS == `STUB_SEG`). The guest's INT pushed
/// FLAGS/CS/IP; the stub's `CD 31` trapped with IP = vector*2 + 2. Unless a
/// service parks or chains, the frame is popped here — IRET semantics, like
/// the old C BIOS's `interrupt` handlers.
pub(super) fn dispatch(
    machine: &mut crate::TheArch,
    dos: &mut super::DosState,
    regs: &mut Vcpu,
) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    let int_num = (ip.wrapping_sub(2) / 2) as u8;

    match int_num {
        0x08 => {
            // Timer tick. EOI before the 1C chain (the C BIOS EOI'd after
            // geninterrupt(0x1C) returned; chaining by frame-reuse means we
            // never regain control, so the EOI moves ahead of the handler).
            let t: u32 = bda_field!(regs, tick_count);
            bda_field!(regs, tick_count = t.wrapping_add(1));
            emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
            // Chain the user timer tick like a real INT 08 does. The
            // selector tells us whether anyone hooked INT 1C — unhooked
            // points back into this array (a no-op), so skip the bounce.
            let seg = read_u16(regs, 0, 0x1C * 4 + 2);
            if seg != STUB_SEG {
                let off = read_u16(regs, 0, 0x1C * 4);
                // Reuse the caller's IRET frame: the 1C handler's IRET
                // returns straight to the interrupted code.
                machine::set_vm86_cs(regs, seg);
                machine::set_vm86_ip(regs, off);
                return thread::KernelAction::Done;
            }
        }
        0x09 => int09(machine, dos, regs),
        0x0A..=0x0F => emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20), // master-PIC IRQ default: EOI
        0x70..=0x77 => {
            // Slave-PIC IRQ default: EOI both.
            emulate_outb(machine, &mut dos.pc, regs, 0xA0, 0x20);
            emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
        }
        0x10 => int10(machine, dos, regs),
        0x11 => {
            let equip: u16 = bda_field!(regs, equipment);
            regs.rax = (regs.rax & !0xFFFF) | equip as u64;
        }
        0x16 => {
            if int16(regs, ip) == Parked::Yes {
                return thread::KernelAction::Done;
            }
        }
        0x1A => int1a(regs),
        _ => {} // plain IRET — a real BIOS leaves no vector null
    }

    pop_iret_frame(regs);
    thread::KernelAction::Done
}

/// Pop the caller's INT frame (IP/CS/FLAGS) — the IRET every handler ends in.
fn pop_iret_frame(regs: &mut Vcpu) {
    let ret_ip = vm86_pop(regs);
    let ret_cs = vm86_pop(regs);
    let ret_flags = vm86_pop(regs);
    machine::set_vm86_ip(regs, ret_ip);
    machine::set_vm86_cs(regs, ret_cs);
    machine::set_vm86_flags(regs, ret_flags as u32);
}

// ============================================================================
// INT 16h: keyboard
// ============================================================================

#[derive(PartialEq)]
enum Parked {
    Yes,
    No,
}

fn int16(regs: &mut Vcpu, stub_ip: u16) -> Parked {
    let ah = (regs.rax >> 8) as u8;
    let head: u16 = bda_field!(regs, kb_head);
    let tail: u16 = bda_field!(regs, kb_tail);
    match ah {
        0x00 | 0x10 => {
            // Blocking read. Empty ring: park by rewinding IP onto the
            // stub's own CD 31 — the thread re-traps and re-polls every
            // slice until the host keyboard IRQ (INT 09 below) fills the
            // ring. Guest-visibly identical to the C BIOS's in-guest spin,
            // but the kernel never blocks, and a parked launch_int16_read
            // continuation (INT 21 console reads) stays parked alongside.
            if head == tail {
                machine::set_vm86_ip(regs, stub_ip.wrapping_sub(2));
                return Parked::Yes;
            }
            let key: u16 = regs.read(BDA_BASE + head as usize);
            let mut next = head + 2;
            if next >= KB_RING_END {
                next = KB_RING_FIRST;
            }
            bda_field!(regs, kb_head = next);
            regs.rax = (regs.rax & !0xFFFF) | key as u64;
        }
        0x01 | 0x11 => {
            // Peek: ZF in the caller's stacked FLAGS (popped on return).
            let ss = vm86_ss(regs) as u32;
            let fl_off = (vm86_sp(regs) as u32).wrapping_add(4);
            let mut flags = read_u16(regs, ss, fl_off);
            if head == tail {
                flags |= 0x40;
            } else {
                flags &= !0x40;
                let key: u16 = regs.read(BDA_BASE + head as usize);
                regs.rax = (regs.rax & !0xFFFF) | key as u64;
            }
            write_u16(regs, ss, fl_off, flags);
        }
        0x02 | 0x12 => {
            let fl: u8 = bda_field!(regs, kb_flags);
            regs.rax = (regs.rax & !0xFF) | fl as u64;
        }
        _ => {}
    }
    Parked::No
}

// ============================================================================
// INT 09h: keyboard IRQ1
// ============================================================================

/// Scancode→ASCII, lower/upper case (set 1, keys 0..0x39).
const KB_LC: [u8; 58] = *b"\x00\x1b1234567890-=\x08\tqwertyuiop[]\x0d\x00asdfghjkl;'`\x00\\zxcvbnm,./\x00*\x00 ";
const KB_UC: [u8; 58] = *b"\x00\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\x0d\x00ASDFGHJKL:\"~\x00|ZXCVBNM<>?\x00*\x00 ";

/// The kernel raises IRQ1 with a scancode readable at port 0x60 (the
/// virtual 8042 on interp, the real one on metal). Translate to ASCII,
/// track shift/ctrl in the BDA flag byte, push (scancode:ascii) into the
/// ring for INT 16h. Extended keys (arrows, F-keys) push ascii=0.
fn int09(machine: &mut crate::TheArch, dos: &mut super::DosState, regs: &mut Vcpu) {
    let sc = emulate_inb(machine, &mut dos.pc, 0x60);
    let key = sc & 0x7F;
    let mut flags: u8 = bda_field!(regs, kb_flags);

    // Shift / Ctrl are modifiers: update the BDA flag byte, don't enqueue.
    let modifier_bit = match key {
        0x2A => Some(0x02u8), // left shift
        0x36 => Some(0x01),   // right shift
        0x1D => Some(0x04),   // ctrl
        _ => None,
    };
    if let Some(bit) = modifier_bit {
        flags = if sc & 0x80 != 0 { flags & !bit } else { flags | bit };
        bda_field!(regs, kb_flags = flags);
        emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
        return;
    }
    if sc & 0x80 != 0 {
        emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20); // other key releases
        return;
    }

    let mut asc = 0u8;
    if (key as usize) < KB_LC.len() {
        let tab = if flags & 0x03 != 0 { &KB_UC } else { &KB_LC };
        asc = tab[key as usize];
        if flags & 0x04 != 0 && (asc | 0x20).is_ascii_lowercase() {
            asc &= 0x1F; // Ctrl-letter
        }
    }

    let tail: u16 = bda_field!(regs, kb_tail);
    let mut next = tail + 2;
    if next >= KB_RING_END {
        next = KB_RING_FIRST;
    }
    let head: u16 = bda_field!(regs, kb_head);
    if next != head {
        // ring not full
        regs.write::<u16>(BDA_BASE + tail as usize, ((key as u16) << 8) | asc as u16);
        bda_field!(regs, kb_tail = next);
    }
    emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
}

// ============================================================================
// INT 10h: video
// ============================================================================

const VRAM_TEXT: usize = 0xB8000;
const VRAM_MODE13: usize = 0xA0000;

fn int10(machine: &mut crate::TheArch, dos: &mut super::DosState, regs: &mut Vcpu) {
    let ax = regs.rax as u16;
    let ah = (ax >> 8) as u8;
    match ah {
        0x00 => {
            // Set video mode — record it, set BDA geometry, clear VRAM.
            let mode = (ax & 0x7F) as u8;
            bda_field!(regs, video_mode = mode);
            bda_field!(regs, columns = if mode <= 1 || mode == 0x13 { 40u16 } else { 80 });
            bda_field!(regs, rows_minus1 = 24u8);
            bda_field!(regs, cell_height = if mode == 0x13 { 8u16 } else { 16 });
            bda_field!(regs, active_page = 0u8);
            bda_field!(regs, cursor_pos = [0u16; 8]);
            if ax & 0x80 == 0 {
                // AL bit 7 clear: clear the framebuffer.
                if mode == 0x13 {
                    for i in 0..(320 * 200 / 4) {
                        regs.write::<u32>(VRAM_MODE13 + i * 4, 0);
                    }
                } else {
                    for i in 0..16384 {
                        // full 32K text window
                        regs.write::<u16>(VRAM_TEXT + i * 2, 0x0720);
                    }
                }
            }
        }
        0x01 => {
            bda_field!(regs, cursor_shape = regs.rcx as u16);
        }
        0x02 => {
            // Set cursor position: BH=page, DH=row, DL=col.
            let page = ((regs.rbx >> 8) & 0x7) as usize;
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
            regs.write::<u16>(bda(pos_off), regs.rdx as u16);
        }
        0x03 => {
            let page = ((regs.rbx >> 8) & 0x7) as usize;
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
            let pos: u16 = regs.read(bda(pos_off));
            let shape: u16 = bda_field!(regs, cursor_shape);
            regs.rdx = (regs.rdx & !0xFFFF) | pos as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | shape as u64;
        }
        0x05 => {
            bda_field!(regs, active_page = (ax & 0xFF) as u8);
        }
        0x0E => {
            // Teletype output: write at cursor, advance. (Scroll is handled
            // by direct writers, matching the C BIOS.)
            let ch = (ax & 0xFF) as u8;
            let page: u8 = bda_field!(regs, active_page);
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + (page & 7) as usize * 2;
            let pos: u16 = regs.read(bda(pos_off));
            let (mut row, mut col) = ((pos >> 8) as u32, (pos & 0xFF) as u32);
            let cols: u16 = bda_field!(regs, columns);
            match ch {
                b'\r' => col = 0,
                b'\n' => row += 1,
                0x08 => col = col.saturating_sub(1),
                _ => {
                    let off = (row * cols as u32 + col) as usize * 2;
                    regs.write::<u8>(VRAM_TEXT + off, ch);
                    col += 1;
                    if col >= cols as u32 {
                        col = 0;
                        row += 1;
                    }
                }
            }
            row = row.min(24);
            regs.write::<u16>(bda(pos_off), ((row << 8) | col) as u16);
        }
        0x0F => {
            // Get video mode: AL=mode, AH=columns, BH=page.
            let mode: u8 = bda_field!(regs, video_mode);
            let cols: u16 = bda_field!(regs, columns);
            let page: u8 = bda_field!(regs, active_page);
            regs.rax = (regs.rax & !0xFFFF) | ((cols << 8) | mode as u16) as u64;
            regs.rbx = (regs.rbx & !0xFF00) | ((page as u64) << 8);
        }
        0x10 => {
            // Palette/DAC — forward to the DAC ports so the platform's
            // palette capture (and a real card on metal) sees one path.
            match (ax & 0xFF) as u8 {
                0x10 => {
                    // Set one DAC register: BX=index, DH=R, CH=G, CL=B.
                    let (bx, dx, cx) = (regs.rbx as u8, regs.rdx, regs.rcx);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C8, bx);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C9, (dx >> 8) as u8);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C9, (cx >> 8) as u8);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C9, cx as u8);
                }
                0x12 => {
                    // Set DAC block: BX=first, CX=count, ES:DX=RGB triples.
                    let tbl = ((regs.es as u16 as usize) << 4) + regs.rdx as u16 as usize;
                    let n = (regs.rcx as u16 as usize) * 3;
                    let bx = regs.rbx as u8;
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C8, bx);
                    for i in 0..n {
                        let b: u8 = regs.read(tbl + i);
                        emulate_outb(machine, &mut dos.pc, regs, 0x3C9, b);
                    }
                }
                _ => {}
            }
        }
        0x12 => {
            if (regs.rbx & 0xFF) as u8 == 0x10 {
                // EGA info: BH=colour, BL=mem, CL=switches.
                regs.rbx = (regs.rbx & !0xFFFF) | 0x0003;
                regs.rcx = (regs.rcx & !0xFFFF) | 0x0009;
            }
        }
        0x1A => {
            // Display combination code — the canonical "is this VGA?".
            if ax & 0xFF == 0 {
                regs.rax = (regs.rax & !0xFF) | 0x1A; // function supported
                regs.rbx = (regs.rbx & !0xFFFF) | 0x0008; // VGA, colour analog
            }
        }
        _ => {}
    }
}

// ============================================================================
// INT 1Ah: system timer
// ============================================================================

fn int1a(regs: &mut Vcpu) {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        0x00 => {
            // Read tick count: CX:DX = ticks, AL = midnight flag.
            let ticks: u32 = bda_field!(regs, tick_count);
            regs.rcx = (regs.rcx & !0xFFFF) | (ticks >> 16) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (ticks & 0xFFFF) as u64;
            regs.rax &= !0xFF; // AL = 0 (no rollover)
        }
        0x01 => {
            // Set tick count from CX:DX.
            let t = ((regs.rcx as u16 as u32) << 16) | regs.rdx as u16 as u32;
            bda_field!(regs, tick_count = t);
        }
        _ => {}
    }
}
