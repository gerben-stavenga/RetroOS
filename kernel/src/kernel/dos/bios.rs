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
//! Port I/O goes through `machine::emulate_inb`/`emulate_outb` — the same
//! virtual port layer guest IN/OUT instructions trap into — NOT the raw
//! `Arch` port calls. The PIC (vpic) and the 8042 (vkbd) are *kernel-side*
//! per-thread devices: a raw `machine.outb(0x20, 0x20)` would bypass the
//! vpic, the EOI would never retire IRQ0, and timer ticks would freeze
//! (reproducer: SkyRoads fades its palette in on a tick wait — black screen
//! forever).

use crate::Regs;
use crate::kernel::thread;
use super::machine::{
    self, emulate_inb, emulate_outb, vm86_ip, vm86_pop, vm86_push, vm86_sp, vm86_ss,
    read_u16, write_u16,
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
    const BASE: usize = 0x400;

    #[inline]
    fn addr(field_off: usize) -> usize {
        Self::BASE + field_off
    }

    pub(crate) fn video_mode<A: crate::Arch>(machine: &A) -> u8 {
        machine.read(Self::addr(core::mem::offset_of!(Self, video_mode)))
    }

    pub(crate) fn tick_count<A: crate::Arch>(machine: &A) -> u32 {
        machine.read(Self::addr(core::mem::offset_of!(Self, tick_count)))
    }

    pub(crate) fn set_page0_cursor<A: crate::Arch>(machine: &mut A, col: u8, row: u8) {
        let addr = Self::addr(core::mem::offset_of!(Self, cursor_pos));
        machine.write::<u16>(addr, u16::from_le_bytes([col, row]));
    }

    pub(crate) fn keyboard_buffer_nonempty<A: crate::Arch>(machine: &A) -> bool {
        let head: u16 = machine.read(Self::addr(core::mem::offset_of!(Self, kb_head)));
        let tail: u16 = machine.read(Self::addr(core::mem::offset_of!(Self, kb_tail)));
        head != tail
    }

    pub(crate) fn clear_keyboard_buffer<A: crate::Arch>(machine: &mut A) {
        let first = core::mem::offset_of!(Self, kb_ring) as u16;
        machine.write::<u16>(Self::addr(core::mem::offset_of!(Self, kb_head)), first);
        machine.write::<u16>(Self::addr(core::mem::offset_of!(Self, kb_tail)), first);
        machine.copy_to(Self::addr(core::mem::offset_of!(Self, kb_ring)), &[0; 32]);
    }

    pub(crate) fn pop_keyboard_word<A: crate::Arch>(machine: &mut A) -> Option<u16> {
        let head_addr = Self::addr(core::mem::offset_of!(Self, kb_head));
        let tail_addr = Self::addr(core::mem::offset_of!(Self, kb_tail));
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
        machine.read(Self::addr(core::mem::offset_of!(Self, kb_flags)))
    }

    pub(crate) fn set_keyboard_flags<A: crate::Arch>(machine: &mut A, flags: u8) {
        machine.write(Self::addr(core::mem::offset_of!(Self, kb_flags)), flags);
    }
}

/// Linear address of a `Bda` field: `bda(offset_of!(Bda, tick_count))`.
#[inline]
fn bda(field_off: usize) -> usize {
    Bda::addr(field_off)
}

/// Ring head/tail values as the guest stores them: segment-0x40 offsets.
const KB_RING_FIRST: u16 = core::mem::offset_of!(Bda, kb_ring) as u16;
const KB_RING_END: u16 = KB_RING_FIRST + (16 * 2);

/// The BIOS default text cursor: a two-scanline underline (start 6, end 7),
/// what a mode set installs in every text mode.
const TEXT_CURSOR_SHAPE: u16 = 0x0607;

macro_rules! bda_field {
    ($machine:expr, $field:ident) => {
        $machine.read(bda(core::mem::offset_of!(Bda, $field)))
    };
    ($machine:expr, $field:ident = $val:expr) => {
        $machine.write(bda(core::mem::offset_of!(Bda, $field)), $val)
    };
}

// ============================================================================
// Install
// ============================================================================

/// Install the personality BIOS: point all 256 IVT entries at the stub
/// array's vector view and seed the BDA. The stub bytes themselves are
/// filled by `setup_ivt` (one array serves vector and control views). The
/// kernel-DOS IVT redirects written after this overwrite their vectors with
/// identical values — the layering matches a real machine (BIOS first, DOS
/// on top). This is deliberately identical with or without a platform ROM.
pub(super) fn install<A: crate::Arch>(machine: &mut A, _regs: &mut Regs) {
    crate::compact_dbg_println!("DOS: installing substitute BIOS (vga_passthrough={})",
        crate::kernel::platform::get().vga_passthrough);
    // Vectors with a real service keep their own stub (slot index == vector);
    // everything unserviced shares ONE dummy cell, exactly like a real BIOS
    // points its unassigned vectors at a single dummy handler. The duplicates
    // are load-bearing: DOS/4GW (raptor's bound extender, RM code at
    // 04e6:62d8) discovers the BIOS dummy-handler address by scanning the
    // IVT for an address that appears in TWO entries (any duplicate must be
    // the shared dummy; it then knows "unhooked" == that value). With 256
    // distinct stub addresses the scan never terminates — raptor spun
    // forever here. Dispatch is unaffected: the dummy decodes as vector
    // 0xFF → plain IRET, and "has the guest hooked INT n" tests only the
    // segment.
    const DUMMY_OFF: u16 = 0xFF * 2;
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
    let _ = DUMMY_OFF;
    seed_bda(machine);
    install_rom_font(machine);
}

/// Publish the standard VGA character generators through the interfaces that
/// are *data pointers*, not handlers: INT 43h → the active graphics font,
/// INT 1Fh → the upper 128 glyphs of 8x8, and INT 10h AX=1130h → any standard
/// ROM font. A game drawing its own text in a graphics mode follows one of
/// these pointers; stale register or interrupt-vector contents become pixels
/// and text comes out garbled.
/// Plenty of games skip the vectors entirely and read the 8x8 table at its
/// hardcoded IBM ROM address, `F000:FA6E` — so the substitute BIOS has to put
/// glyphs there too. That address is *inside* the ROM window a real machine
/// has and our F000 page is plain RAM, whatever the firmware left in it: on
/// hosted it reads back as zeros (text renders blank), on a UEFI machine as
/// leftover firmware bytes (text renders as garbage). Only the low 128 glyphs
/// fit below the 1 MB wall from FA6E; complete guest-readable copies live in
/// the substitute BIOS's fixed low-memory data area.
const ROM_FONT_8X8: usize = 0xF_FA6E;

fn set_data_vector<A: crate::Arch>(machine: &mut A, vector: u32, addr: u32) {
    write_u16(machine, 0, vector * 4, (addr & 0xF) as u16);
    write_u16(machine, 0, vector * 4 + 2, (addr >> 4) as u16);
}

fn rom_font_addr(glyph_h: u8) -> u32 {
    match glyph_h {
        8 => super::dos::font_8x8_addr(),
        14 => super::dos::font_8x14_addr(),
        _ => super::dos::font_8x16_addr(),
    }
}

/// INT 43h is the active graphics character generator, so it changes along
/// with the mode's character height rather than permanently naming 8x8.
fn publish_active_font<A: crate::Arch>(machine: &mut A, glyph_h: u8) {
    set_data_vector(machine, 0x43, rom_font_addr(glyph_h));
}

fn install_rom_font<A: crate::Arch>(machine: &mut A) {
    let font8 = super::dos::font_8x8_addr();
    let font14 = super::dos::font_8x14_addr();
    let font16 = super::dos::font_8x16_addr();
    machine.copy_to(ROM_FONT_8X8, &lib::vga_fonts::FONT_8X8[..1024]);
    machine.copy_to(font8 as usize, &lib::vga_fonts::FONT_8X8);
    machine.copy_to(font14 as usize, &lib::vga_fonts::FONT_8X14);
    machine.copy_to(font16 as usize, &lib::vga_fonts::FONT_8X16);
    set_data_vector(machine, 0x1F, font8 + 128 * 8);
    publish_active_font(machine, 16); // POST starts in 80x25, 8x16 mode 3.
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
    bda_field!(machine, crtc_base = 0x03D4u16);
    bda_field!(machine, rows_minus1 = 24u8);
    bda_field!(machine, cell_height = 16u16);
    // Bit 0: diskette drives present; bits 7-6: drive count minus one.
    // Two floppy units (the A:/B: image slots), matching the CDS.
    bda_field!(machine, equipment = 0x0041u16);
    // A real POST leaves the text cursor shape and the CGA compatibility
    // register mirrors set for mode 3; AH=1Bh publishes all three, and a guest
    // reading them back as zero sees a machine with no cursor.
    bda_field!(machine, cursor_shape = TEXT_CURSOR_SHAPE);
    bda_field!(machine, crt_mode_ctl = 0x29u8);
    bda_field!(machine, crt_palette = 0x30u8);
    bda_field!(machine, kb_head = KB_RING_FIRST);
    bda_field!(machine, kb_tail = KB_RING_FIRST);
    bda_field!(machine, kb_ring_start = KB_RING_FIRST);
    bda_field!(machine, kb_ring_end = KB_RING_END);
    bda_field!(machine, kb_flags3 = KB3_ENHANCED);
    seed_video_static_info(machine);
}

/// Seed the video BIOS static functionality table AH=1Bh points at — the VGA
/// capability set, matching what we actually emulate (all modes 0-13h, 200/350/
/// 400-line, DAC palette + colour paging, DCC available).
fn seed_video_static_info<A: crate::Arch>(machine: &mut A) {
    let mut t = [0u8; 16];
    t[0] = 0xFF; // modes 00h-07h supported
    t[1] = 0xE0; // modes 0Dh-0Fh
    t[2] = 0x0F; // modes 10h-13h
    t[7] = 0x07; // scan lines: 200, 350, 400
    t[8] = 4; // total text character blocks
    t[9] = 2; // max active text character blocks
    // Misc support #1: all modes on all displays, gray summing, font load,
    // default palette load, cursor emulation, EGA palette, DAC palette,
    // colour paging.
    t[10] = 0xFF;
    // Misc support #2: save/restore state, blink/intensity control, DCC.
    t[11] = 0x0E;
    machine.copy_to(super::dos::video_static_info_addr() as usize, &t);
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
            // Timer tick. EOI before the 1C chain (the C BIOS EOI'd after
            // geninterrupt(0x1C) returned; chaining by frame-reuse means we
            // never regain control, so the EOI moves ahead of the handler).
            let t: u32 = bda_field!(machine, tick_count);
            bda_field!(machine, tick_count = t.wrapping_add(1));
            emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
            // Chain the user timer tick like a real INT 08 does. The
            // selector tells us whether anyone hooked INT 1C — unhooked
            // points back into this array (a no-op), so skip the bounce.
            let seg = read_u16(machine, 0, 0x1C * 4 + 2);
            if seg != STUB_SEG {
                let off = read_u16(machine, 0, 0x1C * 4);
                // Reuse the caller's IRET frame: the 1C handler's IRET
                // returns straight to the interrupted code.
                machine::set_vm86_cs(regs, seg);
                machine::set_vm86_ip(regs, off);
                return thread::KernelAction::Done;
            }
        }
        0x09 => {
            if int09(machine, dos, regs) {
                return thread::KernelAction::Done;
            }
        }
        0x0A..=0x0F => emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20), // master-PIC IRQ default: EOI
        0x70..=0x77 => {
            // Slave-PIC IRQ default: EOI both.
            emulate_outb(machine, &mut dos.pc, regs, 0xA0, 0x20);
            emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
        }
        0x10 => int10(machine, bios_display, dos, regs),
        0x11 => {
            let equip: u16 = bda_field!(machine, equipment);
            regs.rax = (regs.rax & !0xFFFF) | equip as u64;
        }
        0x12 => {
            // Conventional memory size in KB (the BDA word a POST seeded).
            let kb: u16 = bda_field!(machine, mem_size_kb);
            regs.rax = (regs.rax & !0xFFFF) | kb as u64;
        }
        0x15 => match (regs.rax >> 8) as u8 {
            // AH=84h joystick support. We expose no game port, so report all
            // four active-low buttons released and zeroed timing counters.
            // Leaving this call untouched is not a harmless "unsupported"
            // result: old games commonly ignore CF and inspect AL directly;
            // their input AX (84xx) then looks like a permanently held fire
            // button. Dyna Blaster does exactly that in its title/menu loop.
            0x84 => match regs.rdx as u16 {
                0 => {
                    regs.rax = (regs.rax & !0xFF) | 0xF0;
                    set_iret_cf(machine, regs, false);
                }
                1 => {
                    regs.rax &= !0xFFFF;
                    regs.rbx &= !0xFFFF;
                    regs.rcx &= !0xFFFF;
                    regs.rdx &= !0xFFFF;
                    set_iret_cf(machine, regs, false);
                }
                _ => {
                    regs.rax = (regs.rax & !0xFF00) | 0x8600;
                    set_iret_cf(machine, regs, true);
                }
            },
            // AH=87h block move: the ROM does this via a protected-mode LGDT
            // excursion (illegal under VM86). Do the copy directly instead.
            0x87 => int15_block_move(machine, regs),
            // AH=89h switch-to-PM: a VM86 guest cannot take over real PM — the
            // monitor owns it. Refuse, exactly as EMM386 does (DPMI is the
            // sanctioned path). AH=86h = "unsupported", CF set.
            0x89 => {
                regs.rax = (regs.rax & !0xFF00) | 0x8600;
                set_iret_cf(machine, regs, true);
            }
            _ => {},
        },
        0x16 => {
            if int16(machine, regs, ip) == Parked::Yes {
                return thread::KernelAction::Done;
            }
        }
        0x1A => int1a(machine, regs),
        _ => {} // plain IRET — a real BIOS leaves no vector null
    }

    pop_iret_frame(machine, regs);
    thread::KernelAction::Done
}

/// Pop the caller's INT frame (IP/CS/FLAGS) — the IRET every handler ends in.
fn pop_iret_frame<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let ret_ip = vm86_pop(machine, regs);
    let ret_cs = vm86_pop(machine, regs);
    let ret_flags = vm86_pop(machine, regs);
    machine::set_vm86_ip(regs, ret_ip);
    machine::set_vm86_cs(regs, ret_cs);
    machine::set_vm86_flags(regs, ret_flags as u32);
}

/// Set/clear CF in the caller's *stacked* FLAGS (at `SS:SP+4`), which
/// `pop_iret_frame` restores on return — clearing the live flag would just be
/// overwritten by that pop. This is how a real BIOS reports carry through IRET.
fn set_iret_cf<A: crate::Arch>(machine: &mut A, regs: &mut Regs, cf: bool) {
    let flin = (((vm86_ss(regs) as u32) << 4) + vm86_sp(regs) as u32 + 4) as usize;
    let mut f = machine.read::<u16>(flin);
    if cf { f |= 1 } else { f &= !1 }
    machine.write::<u16>(flin, f);
}

/// INT 15h AH=87h — copy a block to/from extended memory. `ES:SI` → the
/// caller's GDT; descriptor `[0x10]` is the source, `[0x18]` the destination,
/// each carrying a 24/32-bit linear base (bytes 2–4 = base 0–23, byte 7 =
/// 24–31). `CX` = words to copy. We perform the copy directly — the same
/// operation as XMS AH=0Bh (`copy_within`) — instead of letting the ROM `LGDT`
/// into protected mode, which is illegal under VM86.
fn int15_block_move<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let gdt = ((regs.es as u32) << 4) + (regs.rsi as u32 & 0xFFFF);
    let base = |_regs: &Regs, desc: u32| -> u32 {
        let d = (gdt + desc) as usize;
        (machine.read::<u16>(d + 2) as u32)                      // base bits 0–15
            | (((machine.read::<u16>(d + 4) as u32) & 0xFF) << 16) // byte 4: bits 16–23
            | (((machine.read::<u16>(d + 6) as u32) >> 8) << 24)   // byte 7: bits 24–31
    };
    let src = base(regs, 0x10);
    let dst = base(regs, 0x18);
    let len = (regs.rcx as usize & 0xFFFF) * 2;
    machine.copy_within(src as usize, dst as usize, len);
    regs.rax &= !0xFF00;       // AH = 0 (success)
    set_iret_cf(machine, regs, false);  // CF = 0
}

// ============================================================================
// INT 16h: keyboard
// ============================================================================

#[derive(PartialEq)]
enum Parked {
    Yes,
    No,
}

/// BDA 40:96 bit 1 — "the last scancode was E0". The BIOS's own scratch bit
/// between the prefix byte's INT 09 and the next one's.
const KB3_LAST_E0: u8 = 0x02;
/// BDA 40:96 bit 4 — an enhanced (101/102-key) keyboard is installed. A real
/// POST sets it; software reads it to decide between the conventional
/// (AH=00/01) and enhanced (AH=10/11) INT 16h calls.
const KB3_ENHANCED: u8 = 0x10;

/// Fold an enhanced keystroke back to what the *conventional* INT 16h calls
/// (AH=00/01) report: they predate the 101-key keyboard, so the gray keys must
/// look like the 83-key ones whose scancodes they share. AL=0xE0 becomes 0x00
/// (an extended key with no ASCII), and gray Enter / gray `/` — which carry the
/// 0xE0 in the scancode slot — get their real scancodes back. AH=10/11 report
/// the word untouched; that difference is the whole point of the enhanced calls.
fn conventional(word: u16) -> u16 {
    match ((word >> 8) as u8, word as u8) {
        (0xE0, 0x0D) => 0x1C0D, // gray Enter → the main Enter's scancode
        (0xE0, 0x2F) => 0x352F, // gray /     → the main /'s scancode
        (scan, 0xE0) if scan != 0 => word & 0xFF00, // gray cursor block: AL=0
        _ => word,
    }
}

fn int16<A: crate::Arch>(machine: &mut A, regs: &mut Regs, stub_ip: u16) -> Parked {
    // A real INT 16h opens with `STI`, and its wait loop keeps interrupts on
    // (IBM's K16 spins `sti; nop; cli; check-buffer`) — so calling it is how a
    // program with interrupts OFF gets them back on, and the only reason the
    // very IRQ1 it is waiting for can ever arrive. We are that ROM here, so
    // raise virtual IF the same way; `pop_iret_frame` restores the caller's
    // own IF from its stacked FLAGS on return, exactly as the ROM's IRET does.
    //
    // Without this, a guest that CLI'd before the call parked forever: VIF
    // stayed 0, so `pick_pending_vec` delivered neither the keystroke nor the
    // timer (Xenon 2's video-mode menu hung on "press ENTER" — its keys were
    // queued in the vkbd and never surfaced as an INT 09). Native-BIOS boots
    // were unaffected because there the ROM's own `sti` did this, which is
    // what made it look like a firmware bug.
    regs.frame.rflags |= machine::VIF_FLAG as u64;

    let ah = (regs.rax >> 8) as u8;
    let head: u16 = bda_field!(machine, kb_head);
    let tail: u16 = bda_field!(machine, kb_tail);
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
            let key: u16 = machine.read(Bda::BASE + head as usize);
            let mut next = head + 2;
            if next >= KB_RING_END {
                next = KB_RING_FIRST;
            }
            bda_field!(machine, kb_head = next);
            let key = if ah == 0x00 { conventional(key) } else { key };
            regs.rax = (regs.rax & !0xFFFF) | key as u64;
        }
        0x01 | 0x11 => {
            // Peek: ZF in the caller's stacked FLAGS (popped on return).
            let ss = vm86_ss(regs) as u32;
            let fl_off = (vm86_sp(regs) as u32).wrapping_add(4);
            let mut flags = read_u16(machine, ss, fl_off);
            if head == tail {
                flags |= 0x40;
            } else {
                flags &= !0x40;
                let key: u16 = machine.read(Bda::BASE + head as usize);
                let key = if ah == 0x01 { conventional(key) } else { key };
                regs.rax = (regs.rax & !0xFFFF) | key as u64;
            }
            write_u16(machine, ss, fl_off, flags);
        }
        0x02 | 0x12 => {
            let fl: u8 = bda_field!(machine, kb_flags);
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
/// track shift/ctrl/alt in the BDA flag byte, push (scancode:ascii) into the
/// ring for INT 16h. Extended keys (arrows, F-keys) push ascii=0.
/// Start BIOS INT 9 processing. Returns true when a guest INT 15h/AH=4Fh
/// intercept was launched and will finish through SLOT_KBD_INTERCEPT_RETURN.
fn int09<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>, regs: &mut Regs) -> bool {
    let sc = emulate_inb(machine, &mut dos.pc, 0x60);
    let int15_off = read_u16(machine, 0, 0x15 * 4);
    let int15_seg = read_u16(machine, 0, 0x15 * 4 + 2);
    if int15_seg != STUB_SEG {
        // IBM-compatible BIOSes offer every keyboard byte to INT 15h/AH=4Fh
        // before translating it. CF enters set; the hook may replace AL and
        // returns CF set to continue normal BIOS handling, clear to consume.
        // This is an asynchronous host-Rust equivalent of a BIOS subroutine
        // call, so retain INT 9's registers until the control-slot return.
        dos.int09_registers = [
            regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp,
            regs.ds, regs.es, regs.fs, regs.gs,
        ];
        regs.rax = (regs.rax & !0xFFFF) | u64::from(0x4F00 | u16::from(sc));
        let flags = (machine::vm86_flags(regs) as u16) | 1;
        vm86_push(machine, regs, flags);
        vm86_push(machine, regs, super::dos::CTRL_STUB_SEG);
        vm86_push(machine, regs,
            super::dos::ctrl_slot_off(super::dos::SLOT_KBD_INTERCEPT_RETURN));
        machine::set_vm86_cs(regs, int15_seg);
        machine::set_vm86_ip(regs, int15_off);
        regs.set_flag32(1);
        return true;
    }
    finish_int09(machine, dos, regs, sc, true);
    false
}

/// Continue INT 9 after the guest's INT 15h/AH=4Fh hook returns.
pub(super) fn int09_intercept_return<A: crate::Arch>(
    machine: &mut A,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) {
    let accepted = machine::vm86_flags(regs) & 1 != 0;
    let sc = regs.rax as u8;
    finish_int09(machine, dos, regs, sc, accepted);
    let [rax, rbx, rcx, rdx, rsi, rdi, rbp, ds, es, fs, gs] = dos.int09_registers;
    [regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp,
     regs.ds, regs.es, regs.fs, regs.gs] =
        [rax, rbx, rcx, rdx, rsi, rdi, rbp, ds, es, fs, gs];
    // The nested INT 15 frame was consumed on entry to this slot; unwind the
    // original hardware INT 9 frame after completing BIOS processing.
    pop_iret_frame(machine, regs);
}

fn finish_int09<A: crate::Arch>(
    machine: &mut A,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
    sc: u8,
    accepted: bool,
) {
    if !accepted {
        emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
        return;
    }
    // The E0 prefix arrives as its own byte with its own IRQ1 (real 8042, and
    // `vkbd` queues it the same way). It is not a keystroke — latch it in the
    // BDA flag that exists for exactly this and wait for the code it prefixes.
    let flags3: u8 = bda_field!(machine, kb_flags3);
    if sc == 0xE0 {
        bda_field!(machine, kb_flags3 = flags3 | KB3_LAST_E0);
        emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
        return;
    }
    let e0 = flags3 & KB3_LAST_E0 != 0;
    if e0 {
        bda_field!(machine, kb_flags3 = flags3 & !KB3_LAST_E0);
    }
    let key = sc & 0x7F;
    let mut flags: u8 = bda_field!(machine, kb_flags);

    // Shift / Ctrl / Alt are modifiers: update the BDA flag byte, don't
    // enqueue. These are the conventional INT 16h AH=02h flag bits.
    let modifier_bit = match key {
        0x2A => Some(0x02u8), // left shift
        0x36 => Some(0x01),   // right shift
        0x1D => Some(0x04),   // ctrl
        0x38 => Some(0x08),   // alt (left Alt, or E0-prefixed right Alt)
        _ => None,
    };
    if let Some(bit) = modifier_bit {
        flags = if sc & 0x80 != 0 { flags & !bit } else { flags | bit };
        bda_field!(machine, kb_flags = flags);
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

    // The buffer word. An E0-prefixed key is an *enhanced* keystroke: the gray
    // duplicates report AL=0xE0 in place of an ASCII code (that marker is how
    // software tells the gray cursor block from the keypad keys that share its
    // scancodes), and the two gray keys that do have an ASCII code — Enter and
    // `/` — put the 0xE0 in the scancode slot instead. `int16` folds all of
    // this back for the conventional AH=00/01 reads.
    let word = if flags & 0x08 != 0 {
        alt_key_word(key, e0)
    } else if e0 {
        enhanced_key_word(key)
    } else {
        ((key as u16) << 8) | asc as u16
    };
    let tail: u16 = bda_field!(machine, kb_tail);
    let mut next = tail + 2;
    if next >= KB_RING_END {
        next = KB_RING_FIRST;
    }
    let head: u16 = bda_field!(machine, kb_head);
    if next != head {
        // ring not full
        machine.write::<u16>(Bda::BASE + tail as usize, word);
        bda_field!(machine, kb_tail = next);
    }
    emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
}

fn enhanced_key_word(key: u8) -> u16 {
    match key {
        0x1C => 0xE00D, // gray Enter
        0x35 => 0xE02F, // gray /
        _ => ((key as u16) << 8) | 0x00E0,
    }
}

fn alt_function_key_word(key: u8) -> Option<u16> {
    match key {
        0x3B..=0x44 => Some((u16::from(0x68 + key - 0x3B)) << 8), // Alt+F1..F10
        0x57 => Some(0x8B00),                                    // Alt+F11
        0x58 => Some(0x8C00),                                    // Alt+F12
        _ => None,
    }
}

fn alt_key_word(key: u8, e0: bool) -> u16 {
    // BIOS Alt combinations carry a zero ASCII byte. Borland's menu handling
    // consequently recognizes Alt+F as 0x2100 and Alt+X as 0x2D00, not as the
    // ordinary `f`/`x` character paired with its physical scan code.
    alt_function_key_word(key).unwrap_or_else(|| {
        if e0 { enhanced_key_word(key) } else { u16::from(key) << 8 }
    })
}

#[cfg(test)]
mod keyboard_tests {
    use super::{alt_function_key_word, alt_key_word};

    #[test]
    fn bios_alt_function_scan_codes() {
        assert_eq!(alt_function_key_word(0x3B), Some(0x6800));
        assert_eq!(alt_function_key_word(0x3C), Some(0x6900));
        assert_eq!(alt_function_key_word(0x44), Some(0x7100));
        assert_eq!(alt_function_key_word(0x57), Some(0x8B00));
        assert_eq!(alt_function_key_word(0x58), Some(0x8C00));
        assert_eq!(alt_function_key_word(0x1C), None);
    }

    #[test]
    fn bios_alt_letters_have_no_ascii_byte() {
        assert_eq!(alt_key_word(0x21, false), 0x2100); // Alt+F
        assert_eq!(alt_key_word(0x2d, false), 0x2d00); // Alt+X
    }
}

// ============================================================================
// INT 10h: video
// ============================================================================

const VRAM_TEXT: usize = 0xB8000;
const VRAM_MODE13: usize = 0xA0000;

/// Is this a text mode? Only 0-3 and 7 have character cells; everything else
/// the BIOS knows is a pixel buffer, where the text services rasterize glyphs
/// (`vga::bios_draw_glyph`) instead of writing cells.
fn is_text_mode(mode: u8) -> bool {
    matches!(mode, 0..=3 | 7)
}

/// INT 10h AH=11h — VGA character generator. Besides loading plane-2 fonts,
/// the 11h/12h/14h variants select 25/50-row text geometry. ST3 uses AX=1112
/// to enter 80x50; ignoring it leaves its 4,000 character cells interpreted as
/// 25 rows of 16-line glyphs, which appears as a screen of garbage symbols.
fn get_font_info<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let bh = (regs.rbx >> 8) as u8;
    let addr = match bh {
        // Current upper/current active font are the same data pointers exposed
        // through INT 1Fh/43h. Read the vectors rather than duplicating their
        // selection policy here.
        0x00 => {
            let off: u16 = machine.read(0x1F * 4);
            let seg: u16 = machine.read(0x1F * 4 + 2);
            (u32::from(seg) << 4) + u32::from(off)
        }
        0x01 => {
            let off: u16 = machine.read(0x43 * 4);
            let seg: u16 = machine.read(0x43 * 4 + 2);
            (u32::from(seg) << 4) + u32::from(off)
        }
        0x02 => super::dos::font_8x14_addr(),
        0x03 => super::dos::font_8x8_addr(),
        0x04 => super::dos::font_8x8_addr() + 128 * 8,
        // VGA defines alternate 9-dot 14/16-line selections here. Character
        // generator rows are still eight stored bits wide (the adapter makes
        // the ninth column), and our canonical ROM faces are the compatible
        // substitute when no separate alternate face is supplied.
        0x05 => super::dos::font_8x14_addr(),
        0x06 => super::dos::font_8x16_addr(),
        0x07 => super::dos::font_8x16_addr(),
        _ => return,
    };
    regs.es = u64::from(addr >> 4);
    regs.rbp = (regs.rbp & !0xFFFF) | u64::from(addr & 0xF);
    let glyph_h: u16 = bda_field!(machine, cell_height);
    regs.rcx = (regs.rcx & !0xFFFF) | u64::from(glyph_h & 0xFF);
    let rows_minus1: u8 = bda_field!(machine, rows_minus1);
    regs.rdx = (regs.rdx & !0xFF) | u64::from(rows_minus1);
}

fn font_service<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) {
    let subfn = regs.rax as u8;
    if subfn == 0x30 {
        get_font_info(machine, regs);
        return;
    }
    let map = usize::from(regs.rbx as u8 & 7);
    let set_geometry = matches!(subfn, 0x10 | 0x11 | 0x12 | 0x14);

    let mut owned = alloc::vec::Vec::new();
    let (first, glyph_h, font): (usize, usize, &[u8]) = match subfn {
        0x00 | 0x10 => {
            let glyph_h = usize::from((regs.rbx >> 8) as u8);
            let count = match regs.rcx as u16 { 0 => 256, n => usize::from(n) };
            let first = usize::from(regs.rdx as u16);
            if glyph_h == 0 || glyph_h > 32 || first + count > 256 { return; }
            owned.resize(count * glyph_h, 0);
            let src = es_offset(dos, regs, regs.rbp as u16 as u32);
            machine.copy_from(src, &mut owned);
            (first, glyph_h, &owned)
        }
        0x01 | 0x11 => (0, 14, &lib::vga_fonts::FONT_8X14),
        0x02 | 0x12 => (0, 8, &lib::vga_fonts::FONT_8X8),
        0x04 | 0x14 => (0, 16, &lib::vga_fonts::FONT_8X16),
        0x03 => {
            if let Some(display) = dos.pc.vga.native_mut() {
                let _ = display.cap_mut().bios_font_call(machine, bios_display, regs, None);
            } else {
                super::machine::vga::bios_set_font_map_select(&mut dos.pc.vga, regs.rbx as u8);
            }
            return;
        }
        _ => return,
    };

    if let Some(display) = dos.pc.vga.native_mut() {
        let buffer = matches!(subfn, 0x00 | 0x10).then_some(font);
        let _ = display.cap_mut().bios_font_call(machine, bios_display, regs, buffer);
    } else {
        super::machine::vga::bios_load_font(
            machine, &mut dos.pc.vga, map, first, font, glyph_h,
        );
        if set_geometry {
            super::machine::vga::bios_set_text_height(&mut dos.pc.vga, glyph_h as u8);
        }
    }

    if set_geometry {
        let rows = if glyph_h == 8 { 50 } else { 25 };
        bda_field!(machine, rows_minus1 = rows - 1);
        bda_field!(machine, cell_height = glyph_h as u16);
        bda_field!(machine, cursor_shape = ((glyph_h as u16 - 2) << 8) | (glyph_h as u16 - 1));
        publish_active_font(machine, glyph_h as u8);
    }
}

/// Linear address of one text cell. A page is 0x1000 bytes in the 80-column
/// modes and 0x800 in the 40-column ones, which the BDA's column count
/// decides — the same rule a real BIOS applies.
/// DOS teletype: write `ch` at the BDA cursor and advance it.
///
/// The one implementation, shared by INT 10h AH=0Eh and the INT 21h character
/// output calls. There used to be a second one: INT 21h borrowed the *kernel's*
/// terminal (`lib::term`) for its cursor and scroll, then wrote the result back
/// to the BDA so the two agreed. That handshake was the tell — a DOS program has
/// no console to borrow, it owns the display, and its cursor is the BDA's. Going
/// through the machine also means this works on every backend, where the kernel
/// terminal wrote to a host pointer that hosted had to fake.
///
/// `fg` is the foreground colour for graphics modes (INT 10h takes it in BL);
/// text modes write the character byte at the cursor cell.
///
/// Past the bottom row a text page scrolls, as a real BIOS teletype does —
/// INT 21h output relied on this when it went through the kernel terminal, and
/// COMMAND.COM output longer than a screen depends on it. Graphics modes still
/// clamp: there is no cheap cell-wise scroll there and the C BIOS left it to
/// direct writers.
pub(super) fn teletype<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, ch: u8, fg: u8) {
    let page: u8 = bda_field!(machine, active_page);
    let pos_off = core::mem::offset_of!(Bda, cursor_pos) + (page & 7) as usize * 2;
    let pos: u16 = machine.read(bda(pos_off));
    let (mut row, mut col) = ((pos >> 8) as u32, (pos & 0xFF) as u32);
    let cols: u16 = bda_field!(machine, columns);
    let mode = Bda::video_mode(machine);
    match ch {
        b'\r' => col = 0,
        b'\n' => row += 1,
        0x08 => col = col.saturating_sub(1),
        _ => {
            // Graphics modes have no text cell: rasterize the glyph into the
            // framebuffer. Text modes write the char byte at the cursor cell.
            if !super::machine::vga::bios_draw_glyph(machine, &mut dos.pc.vga, mode, ch, col, row, fg) {
                let at = text_cell(machine, page, row, col);
                machine.write::<u8>(at, ch);
            }
            col += 1;
            if col >= cols as u32 {
                col = 0;
                row += 1;
            }
        }
    }
    let max_row: u8 = bda_field!(machine, rows_minus1);
    if row > max_row as u32 {
        scroll_text_page(machine, page, cols, max_row);
        row = max_row as u32;
    }
    machine.write::<u16>(bda(pos_off), ((row << 8) | col) as u16);
    // Keep the CRTC hardware cursor in step, so `vga_hw::save` captures it.
    let offset = (row * cols as u32 + col) as u16;
    machine.outb(0x3D4, 0x0E); machine.outb(0x3D5, (offset >> 8) as u8);
    machine.outb(0x3D4, 0x0F); machine.outb(0x3D5, offset as u8);
}

/// Scroll a text page up one line, blanking the last. A no-op in a graphics
/// mode, where there are no character cells to move.
fn scroll_text_page<A: crate::Arch>(machine: &mut A, page: u8, cols: u16, max_row: u8) {
    let mode = Bda::video_mode(machine);
    if !is_text_mode(mode) {
        return;
    }
    let cols = cols as usize;
    let rows = max_row as usize + 1;
    let base = text_cell(machine, page, 0, 0);
    // Move rows 1..rows up one, then blank the last with the current attribute.
    for r in 1..rows {
        for c in 0..cols {
            let v: u16 = machine.read(base + (r * cols + c) * 2);
            machine.write::<u16>(base + ((r - 1) * cols + c) * 2, v);
        }
    }
    // Blank with the attribute the vacated line already carried, so a coloured
    // screen scrolls in its own colour rather than reverting to grey-on-black.
    let attr = machine.read::<u16>(base + ((rows - 1) * cols) * 2) & 0xFF00;
    for c in 0..cols {
        machine.write::<u16>(base + ((rows - 1) * cols + c) * 2, attr | b' ' as u16);
    }
}

fn text_cell<A: crate::Arch>(machine: &mut A, page: u8, row: u32, col: u32) -> usize {
    let cols: u16 = bda_field!(machine, columns);
    let page_size = if cols > 40 { 0x1000 } else { 0x800 };
    VRAM_TEXT
        + (page as usize & 7) * page_size
        + (row as usize * cols as usize + col as usize) * 2
}

/// A page's cursor position from the BDA, as (row, column).
fn cursor_of<A: crate::Arch>(machine: &mut A, page: u8) -> (u32, u32) {
    let pos_off = core::mem::offset_of!(Bda, cursor_pos) + (page as usize & 7) * 2;
    let pos: u16 = machine.read(bda(pos_off));
    ((pos >> 8) as u32, (pos & 0xFF) as u32)
}

/// Apply the VGA BIOS's CGA-palette compatibility mapping. Port 3D9h is a
/// physical CGA register; EGA/VGA BIOSes emulate it by rewriting Attribute
/// Controller palette entries. Keeping the 3D9h mirror alone is sufficient
/// for our CGA renderer but has no visible effect on a native VGA card.
fn set_cga_compat_palette<A: crate::Arch>(
    machine: &mut A,
    pc: &mut super::machine::PcMachine,
    regs: &mut Regs,
    function: u8,
    value: u8,
) {
    let mut ac_write = |index: u8, transform: &dyn Fn(u8) -> u8| {
        let _ = emulate_inb(machine, pc, 0x3DA);
        emulate_outb(machine, pc, regs, 0x3C0, index);
        let old = emulate_inb(machine, pc, 0x3C1);
        emulate_outb(machine, pc, regs, 0x3C0, transform(old));
    };
    match function {
        0 => {
            // Border/background: AC0 gets the CGA colour; bit 4 selects
            // foreground intensity for the remaining three entries.
            let mut background = value & 0x0F;
            if background & 0x08 != 0 {
                background += 0x08;
            }
            ac_write(0, &|_| background);
            for index in 1..4 {
                ac_write(index, &|old| (old & !0x10) | (value & 0x10));
            }
        }
        1 => {
            // Palette 0/1 is encoded in bit 0 of AC entries 1..3.
            for index in 1..4 {
                ac_write(index, &|old| (old & !1) | (value & 1));
            }
        }
        _ => return,
    }
    let _ = emulate_inb(machine, pc, 0x3DA);
    emulate_outb(machine, pc, regs, 0x3C0, 0x20); // palette-address source
}

/// INT 10h AH=06/07: scroll a text window up (`up`) or down, filling the
/// vacated lines with blanks in BH's attribute. AL = lines to scroll; 0 (or
/// any count that covers the window) clears it outright — the "clear the
/// screen" idiom nearly every text-mode program opens with.
///
/// Graphics modes are left alone: scrolling a pixel buffer needs the mode's
/// plane layout, and no guest we serve asks for it.
fn scroll_window<A: crate::Arch>(machine: &mut A, regs: &mut Regs, up: bool) {
    let mode = Bda::video_mode(machine);
    if !is_text_mode(mode) {
        return;
    }
    let cols: u16 = bda_field!(machine, columns);
    let rows: u8 = bda_field!(machine, rows_minus1);
    let (cols, rows) = (cols as u32, rows as u32 + 1);
    let top = ((regs.rcx >> 8) & 0xFF) as u32;
    let left = (regs.rcx & 0xFF) as u32;
    let bottom = (((regs.rdx >> 8) & 0xFF) as u32).min(rows - 1);
    let right = ((regs.rdx & 0xFF) as u32).min(cols - 1);
    if top > bottom || left > right {
        return;
    }
    let height = bottom - top + 1;
    let lines = (regs.rax & 0xFF) as u32;
    let n = if lines == 0 || lines > height { height } else { lines };
    let blank = (((regs.rbx >> 8) as u16 & 0xFF) << 8) | 0x20;
    let page: u8 = bda_field!(machine, active_page);
    // Walk from the edge the vacated lines end up on, so a source row is
    // always one this pass has not overwritten yet.
    for i in 0..height {
        let dst = if up { top + i } else { bottom - i };
        let src = if up { dst.checked_add(n) } else { dst.checked_sub(n) }
            .filter(|r| (top..=bottom).contains(r));
        for c in left..=right {
            let val = match src {
                Some(s) => {
                    let from = text_cell(machine, page, s, c);
                    machine.read::<u16>(from)
                }
                None => blank,
            };
            let to = text_cell(machine, page, dst, c);
            machine.write::<u16>(to, val);
        }
    }
}

pub(super) fn int10<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) {
    let ax = regs.rax as u16;
    let ah = (ax >> 8) as u8;
    match ah {
        0x00 => {
            // Set video mode — record it, set BDA geometry, clear VRAM.
            let mode = (ax & 0x7F) as u8;
            let clear = ax & 0x80 == 0;
            if let Some(display) = dos.pc.as_mut().vga.native_mut() {
                let _ = display.cap_mut().guest_bios_set_mode(
                    machine, bios_display, u16::from(mode));
            }
            bda_field!(machine, video_mode = mode);
            // Text-grid geometry per mode: 40-column modes (CGA/EGA 320-wide and
            // mode 13h) vs 80; 30 rows on the 480-line VGA modes; character cell
            // height 8 (200-line + 13h), 14 (350-line EGA), or 16 (text/480-line).
            bda_field!(machine, columns = match mode { 0 | 1 | 4 | 5 | 0x0D | 0x13 => 40u16, _ => 80 });
            bda_field!(machine, rows_minus1 = if matches!(mode, 0x11 | 0x12) { 29u8 } else { 24 });
            let cell_height = match mode {
                4 | 5 | 6 | 0x0D | 0x0E | 0x13 => 8u16,
                0x0F | 0x10 => 14,
                _ => 16,
            };
            bda_field!(machine, cell_height = cell_height);
            publish_active_font(machine, cell_height as u8);
            bda_field!(machine, active_page = 0u8);
            bda_field!(machine, cursor_pos = [0u16; 8]);
            // A mode set resets the cursor to the BIOS default underline (and
            // hides it in graphics modes) — guests read it back via AH=03 and
            // AH=1Bh, so it must not stay at whatever the last program set.
            bda_field!(machine, cursor_shape =
                if is_text_mode(mode) { TEXT_CURSOR_SHAPE } else { 0x0000u16 });
            // Arm/disarm the planar VRAM trap for the EGA 16-colour family
            // (0x0D–0x12, Keen): a BIOS-set planar mode never toggles the
            // Sequencer chain-4 bit, so this is the only place the trap gets
            // armed. (`clear` also blanks the planes.)
            super::machine::vga::on_set_mode(machine, &mut dos.pc, regs, mode, clear);
            // The IBM BIOS programs the CGA compatibility registers (0x3D8
            // Mode-Control, 0x3D9 Colour-Select) on every mode set and mirrors
            // them in the BDA. The Colour-Select default is what gives mode 4/5
            // its canonical cyan/magenta/white (palette 1, bright) and mode 6
            // its white foreground — a game that wants green/red/brown must
            // select palette 0 itself (AH=0Bh or an 0x3D9 write).
            let mode_ctl: u8 = match mode {
                0 => 0x2C, 1 => 0x28, 2 => 0x2D, 4 => 0x2A, 5 => 0x2E, 6 => 0x1E, _ => 0x29,
            };
            let palette: u8 = if mode == 6 { 0x3F } else { 0x30 };
            bda_field!(machine, crt_mode_ctl = mode_ctl);
            bda_field!(machine, crt_palette = palette);
            emulate_outb(machine, &mut dos.pc, regs, 0x3D8, mode_ctl);
            emulate_outb(machine, &mut dos.pc, regs, 0x3D9, palette);
            if clear {
                // AL bit 7 clear: clear the framebuffer. Planar modes are
                // cleared inside on_set_mode (their VRAM is the plane window).
                if mode == 0x13 {
                    for i in 0..(320 * 200 / 4) {
                        machine.write::<u32>(VRAM_MODE13 + i * 4, 0);
                    }
                } else if !matches!(mode, 0x0D..=0x12) {
                    // Text modes blank to space-on-gray cells; the CGA graphics
                    // modes (4-6) share the window but blank to pixel value 0 —
                    // 0x0720 there is a red/green/brown pixel-stripe pattern.
                    let blank: u16 = if matches!(mode, 4..=6) { 0x0000 } else { 0x0720 };
                    for i in 0..16384 {
                        // full 32K text window
                        machine.write::<u16>(VRAM_TEXT + i * 2, blank);
                    }
                }
            }
        }
        0x01 => {
            bda_field!(machine, cursor_shape = regs.rcx as u16);
        }
        0x02 => {
            // Set cursor position: BH=page, DH=row, DL=col.
            let page = ((regs.rbx >> 8) & 0x7) as usize;
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
            machine.write::<u16>(bda(pos_off), regs.rdx as u16);
        }
        0x03 => {
            let page = ((regs.rbx >> 8) & 0x7) as usize;
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
            let pos: u16 = machine.read(bda(pos_off));
            let shape: u16 = bda_field!(machine, cursor_shape);
            regs.rdx = (regs.rdx & !0xFFFF) | pos as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | shape as u64;
        }
        0x05 => {
            bda_field!(machine, active_page = (ax & 0xFF) as u8);
        }
        0x06 | 0x07 => scroll_window(machine, regs, ah == 0x06),
        0x08 => {
            // Read the character + attribute under the cursor (BH = page).
            let page = ((regs.rbx >> 8) & 7) as u8;
            let (row, col) = cursor_of(machine, page);
            let mode = Bda::video_mode(machine);
            let cell = if is_text_mode(mode) {
                let at = text_cell(machine, page, row, col);
                machine.read::<u16>(at)
            } else {
                0x0720 // graphics modes: no cell to read back
            };
            regs.rax = (regs.rax & !0xFFFF) | cell as u64;
        }
        0x09 | 0x0A => {
            // Write a character at the cursor CX times WITHOUT advancing it —
            // how full-screen text UIs paint (Xenon 2's video-mode menu is
            // drawn entirely with AH=09; with this unserviced its menu was
            // invisible and it sat in INT 16h waiting for a key nobody knew
            // to press). AH=09 also sets the attribute from BL; AH=0A leaves
            // the cell's existing one.
            let ch = (ax & 0xFF) as u8;
            let page = ((regs.rbx >> 8) & 7) as u8;
            let attr = regs.rbx as u8;
            let count = ((regs.rcx as u16).max(1)) as u32;
            let (row, col) = cursor_of(machine, page);
            let mode = Bda::video_mode(machine);
            let cols: u16 = bda_field!(machine, columns);
            let rows: u8 = bda_field!(machine, rows_minus1);
            let (cols, rows) = (cols as u32, rows as u32 + 1);
            for i in 0..count {
                // A run that overflows the line wraps to the next, as on a
                // real BIOS; one that overflows the screen is dropped.
                let (r, c) = (row + (col + i) / cols, (col + i) % cols);
                if r >= rows {
                    break;
                }
                // BL is the foreground colour in graphics modes, the
                // attribute in text ones.
                if !super::machine::vga::bios_draw_glyph(machine, &mut dos.pc.vga, mode, ch, c, r, attr) {
                    let at = text_cell(machine, page, r, c);
                    if ah == 0x09 {
                        machine.write::<u16>(at, ((attr as u16) << 8) | ch as u16);
                    } else {
                        machine.write::<u8>(at, ch);
                    }
                }
            }
        }
        0x0B => {
            // CGA palette control. The BDA/3D9 mirror feeds the emulated CGA;
            // VGA hardware implements the same BIOS service by changing its
            // Attribute Controller palette entries.
            let bh = (regs.rbx >> 8) as u8;
            let bl = regs.rbx as u8;
            let old: u8 = bda_field!(machine, crt_palette);
            let new = if bh == 0 {
                (old & 0xE0) | (bl & 0x1F)
            } else {
                (old & !0x20) | ((bl & 1) << 5)
            };
            bda_field!(machine, crt_palette = new);
            emulate_outb(machine, &mut dos.pc, regs, 0x3D9, new);
            set_cga_compat_palette(machine, &mut dos.pc, regs, bh, bl);
        }
        0x0E => {
            // Teletype output: DOS's own, on DOS's own cursor.
            teletype(machine, dos, (ax & 0xFF) as u8, regs.rbx as u8);
        }
        0x0F => {
            // Get video mode: AL=mode, AH=columns, BH=page.
            let mode = Bda::video_mode(machine);
            let cols: u16 = bda_field!(machine, columns);
            let page: u8 = bda_field!(machine, active_page);
            regs.rax = (regs.rax & !0xFFFF) | ((cols << 8) | mode as u16) as u64;
            regs.rbx = (regs.rbx & !0xFF00) | ((page as u64) << 8);
        }
        0x10 => {
            // A native card's firmware owns palette semantics: an SVGA or
            // unusual legacy mode need not expose a plain VGA-compatible DAC.
            // Bounce pointer-bearing PM calls through the ROM's private RM
            // workspace. The substitute/emulated path below owns its ports.
            let subfn = (ax & 0xFF) as u8;
            if dos.pc.vga.is_native() {
                let (mut buffer, copy_to_bios, guest_dst) = match subfn {
                    0x02 => {
                        let tbl = es_offset(dos, regs, regs.rdx as u16 as u32);
                        let mut data = alloc::vec![0; 17];
                        machine.copy_from(tbl, &mut data);
                        (data, true, None)
                    }
                    0x12 => {
                        let tbl = es_offset(dos, regs, regs.rdx as u16 as u32);
                        let mut data = alloc::vec![0; regs.rcx as u16 as usize * 3];
                        machine.copy_from(tbl, &mut data);
                        (data, true, None)
                    }
                    0x17 => {
                        let tbl = es_offset(dos, regs, regs.rdx as u16 as u32);
                        (alloc::vec![0; regs.rcx as u16 as usize * 3], false, Some(tbl))
                    }
                    _ => (alloc::vec![], true, None),
                };
                let called = if let Some(display) = dos.pc.vga.native_mut() {
                    display.cap_mut()
                        .bios_palette_call(
                            machine,
                            bios_display,
                            regs,
                            (!buffer.is_empty()).then_some(buffer.as_mut_slice()),
                            copy_to_bios,
                            false,
                        )
                        .is_ok()
                } else {
                    false
                };
                if called
                    && let Some(dst) = guest_dst
                {
                    machine.copy_to(dst, &buffer);
                }
                return;
            }
            match subfn {
                0x00 => {
                    // Set one EGA palette (Attribute Controller) register:
                    // BL = register 0..15, BH = colour value. Keen recolours its
                    // title (and fades it in) through these — without it every
                    // value-1 pixel stays at the default AC[1]=blue.
                    let idx = (regs.rbx & 0x1F) as u8;
                    let val = (regs.rbx >> 8) as u8;
                    let _ = emulate_inb(machine, &mut dos.pc, 0x3DA); // reset AC flip-flop
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, idx); // index (PAS=0)
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, val); // data
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, 0x20); // re-enable display
                }
                0x01 => {
                    // Set overscan/border colour (AC register 0x11) = BH.
                    let val = (regs.rbx >> 8) as u8;
                    let _ = emulate_inb(machine, &mut dos.pc, 0x3DA);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, 0x11);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, val);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, 0x20);
                }
                0x02 => {
                    // Set all 16 palette registers + overscan: ES:DX → 17 bytes
                    // (0..15 = palette, 16 = overscan). Keen loads its title
                    // palette in one shot here.
                    let tbl = es_offset(dos, regs, regs.rdx as u16 as u32);
                    let _ = emulate_inb(machine, &mut dos.pc, 0x3DA);
                    for i in 0..16u8 {
                        let b: u8 = machine.read(tbl + i as usize);
                        emulate_outb(machine, &mut dos.pc, regs, 0x3C0, i);
                        emulate_outb(machine, &mut dos.pc, regs, 0x3C0, b);
                    }
                    let ov: u8 = machine.read(tbl + 16);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, 0x11);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, ov);
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, 0x20);
                }
                0x03 => {
                    // Toggle blink/intensity (BL bit 0: 1 = blink, 0 = 16
                    // background colors). Program AC reg 0x10 bit 3 through
                    // the ports like a real BIOS — one path for the emulated
                    // model and a real card alike.
                    let blink = regs.rbx & 1 != 0;
                    let _ = emulate_inb(machine, &mut dos.pc, 0x3DA); // reset AC flip-flop
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, 0x10 | 0x20);
                    // Read back through the same port path rather than the
                    // register shadow: a native owner has no shadow, and
                    // 0x3C1 answers from whichever side holds the state.
                    let cur = emulate_inb(machine, &mut dos.pc, 0x3C1);
                    let val = if blink { cur | 0x08 } else { cur & !0x08 };
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, val);
                }
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
                    let tbl = es_offset(dos, regs, regs.rdx as u16 as u32);
                    let n = (regs.rcx as u16 as usize) * 3;
                    let bx = regs.rbx as u8;
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C8, bx);
                    for i in 0..n {
                        let b: u8 = machine.read(tbl + i);
                        emulate_outb(machine, &mut dos.pc, regs, 0x3C9, b);
                    }
                }
                0x15 => {
                    // Read one DAC register: BX=index → DH=R, CH=G, CL=B.
                    // Fade loops read-modify-write through here; without it
                    // they scale garbage and the palette decays.
                    let bx = regs.rbx as u8;
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C7, bx);
                    let r = emulate_inb(machine, &mut dos.pc, 0x3C9) as u64;
                    let g = emulate_inb(machine, &mut dos.pc, 0x3C9) as u64;
                    let b = emulate_inb(machine, &mut dos.pc, 0x3C9) as u64;
                    regs.rdx = (regs.rdx & !0xFF00) | (r << 8);
                    regs.rcx = (regs.rcx & !0xFFFF) | (g << 8) | b;
                }
                0x17 => {
                    // Read DAC block: BX=first, CX=count → ES:DX RGB triples.
                    let tbl = es_offset(dos, regs, regs.rdx as u16 as u32);
                    let n = (regs.rcx as u16 as usize) * 3;
                    let bx = regs.rbx as u8;
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C7, bx);
                    for i in 0..n {
                        let v = emulate_inb(machine, &mut dos.pc, 0x3C9);
                        machine.write::<u8>(tbl + i, v);
                    }
                }
                _ => {}
            }
        }
        0x11 => font_service(machine, bios_display, dos, regs),
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
        0x1B => state_info(machine, dos, regs),
        0x4F => vbe(machine, bios_display, dos, regs),
        _ => {}
    }
}

/// INT 10h AH=1Bh — Functionality/State Information (VGA and up): a 64-byte
/// block at ES:DI describing the current mode plus a far pointer to the static
/// functionality table. The *other* canonical "is this a VGA?" probe next to
/// AX=1A00 — Operation Wolf zeroes the block, calls this, and scans it: an
/// all-zero block (i.e. an unserviced function) means "no VGA", and it drops to
/// its EGA path with the worse palette. DOS never chains this service to a
/// platform ROM, so an unimplemented AH=1Bh is an all-zero block.
fn state_info<A: crate::Arch>(machine: &mut A, dos: &super::DosState<A>, regs: &mut Regs) {
    if regs.rbx as u16 != 0 {
        return; // BX=0 is the only defined implementation type
    }
    let lin = es_offset(dos, regs, regs.rdi as u16 as u32);
    machine.copy_to(lin, &[0u8; 64]);
    let mode = Bda::video_mode(machine);
    let columns: u16 = bda_field!(machine, columns);
    let rows_minus1: u8 = bda_field!(machine, rows_minus1);
    let rows = rows_minus1 + 1;
    // Regen buffer size/start, colours and page count per mode family: text
    // pages are 2 bytes/cell rounded to 4 KB, the CGA graphics modes share one
    // 16 KB buffer, and 13h is a single 64000-byte page.
    let (regen_len, colours, pages) = match mode {
        0x13 => (0xFA00u16, 256u16, 1u8),
        0x0D => (0x2000, 16, 8),
        0x0E => (0x4000, 16, 4),
        0x0F => (0x8000, 2, 2), // mono planar
        0x10 => (0x8000, 16, 2),
        0x11 => (0x9600, 2, 1), // mono 640x480
        0x12 => (0x9600, 16, 1),
        4 | 5 => (0x4000, 4, 1),
        6 => (0x4000, 2, 1),
        // Text: one *page*, not the whole window — 80×25×2 rounded up to 4 KB
        // (what a real VGA BIOS reports here; 40-column pages are half that).
        _ => (if columns > 40 { 0x1000 } else { 0x0800 }, if mode == 7 { 1 } else { 16 }, 8),
    };
    machine.write::<u32>(lin, super::dos::video_static_info_addr());
    machine.write::<u8>(lin + 0x04, mode);
    machine.write::<u16>(lin + 0x05, columns);
    machine.write::<u16>(lin + 0x07, regen_len);
    machine.write::<u16>(lin + 0x09, 0); // page 0 starts at the buffer base
    for page in 0..8 {
        let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
        let pos: u16 = machine.read(bda(pos_off));
        machine.write::<u16>(lin + 0x0B + page * 2, pos);
    }
    let shape: u16 = bda_field!(machine, cursor_shape);
    machine.write::<u8>(lin + 0x1B, shape as u8); // cursor end line
    machine.write::<u8>(lin + 0x1C, (shape >> 8) as u8); // cursor start line
    machine.write::<u8>(lin + 0x1D, bda_field!(machine, active_page));
    machine.write::<u16>(lin + 0x1E, bda_field!(machine, crtc_base));
    machine.write::<u8>(lin + 0x20, bda_field!(machine, crt_mode_ctl));
    machine.write::<u8>(lin + 0x21, bda_field!(machine, crt_palette));
    machine.write::<u8>(lin + 0x22, rows);
    machine.write::<u16>(lin + 0x23, bda_field!(machine, cell_height));
    machine.write::<u8>(lin + 0x25, 0x08); // active display combination: VGA colour
    machine.write::<u8>(lin + 0x26, 0x00); // no alternate display
    machine.write::<u16>(lin + 0x27, colours);
    machine.write::<u8>(lin + 0x29, pages);
    // Active scan lines: 0 = 200, 1 = 350, 2 = 400, 3 = 480.
    machine.write::<u8>(lin + 0x2A, match mode {
        0x11 | 0x12 => 3,
        0x0F | 0x10 => 1,
        4..=6 | 0x0D | 0x0E | 0x13 => 0,
        _ => 2, // BIOS text modes come up 400-line (8x16 cells)
    });
    machine.write::<u8>(lin + 0x2B, 0); // primary character block
    machine.write::<u8>(lin + 0x2C, 0); // secondary character block
    // Misc flags: all modes on all displays, plus blink/intensity control in
    // text modes (bit 5).
    machine.write::<u8>(lin + 0x2D, if is_text_mode(mode) { 0x21 } else { 0x01 });
    machine.write::<u8>(lin + 0x31, 3); // 256 KB of video memory
    regs.rax = (regs.rax & !0xFF) | 0x1B; // function supported
}

// ============================================================================
// VESA VBE (INT 10h AH=4Fh)
// ============================================================================

/// The banked SVGA modes we expose: (VBE mode#, width, height, bpp). Presented
/// through the emulated framebuffer sink, integer-scaled/centred to the panel.
/// 8bpp goes through the DAC palette; 15/16/24 are direct colour. Substitute
/// path only — the native/SeaBIOS path has the card's own VBE.
const VBE_MODES: &[(u16, u16, u16, u8)] = &[
    (0x101, 640, 480, 8),
    (0x103, 800, 600, 8),
    (0x110, 640, 480, 15),
    (0x111, 640, 480, 16),
    (0x112, 640, 480, 24),
];

fn substitute_vbe_mode(number: u16) -> Option<crate::kernel::platform::VbeMode> {
    let &(_, width, height, bits_per_pixel) =
        VBE_MODES.iter().find(|&&(candidate, ..)| candidate == number)?;
    let format = if bits_per_pixel == 8 {
        crate::kernel::display::FormatSpec::Indexed8
    } else {
        let packed = match bits_per_pixel {
            15 => crate::kernel::display::PixelFormat::RGB555,
            16 => crate::kernel::display::PixelFormat::RGB565,
            24 => crate::kernel::display::PixelFormat::RGB888,
            _ => return None,
        };
        crate::kernel::display::FormatSpec::Packed(packed)
    };
    let pitch = width * u16::from(bits_per_pixel.div_ceil(8));
    let image_bytes = usize::from(pitch) * usize::from(height);
    let image_count = (super::machine::vga::SVGA_LFB_MAX_BYTES / image_bytes)
        .clamp(1, 256);
    let image_pages = (image_count - 1) as u8;
    Some(crate::kernel::platform::VbeMode {
        number,
        // This is an implementation detail of the RAM-backed substitute mode;
        // its public ModeInfo still deliberately says not VGA compatible.
        vga_compatible: false,
        physical_base: super::machine::vga::svga_lfb_base(),
        width,
        height,
        pitch,
        banked_pitch: pitch,
        linear_pitch: pitch,
        bits_per_pixel,
        format,
        // The RAM-backed substitute surface has no independent output
        // RAMDAC; Voodoo applies its CLUT while rendering into the host sink.
        programmable_ramp: false,
        window_segment: 0xA000,
        window_granularity_kb: 64,
        window_size_kb: 64,
        banked_image_pages: image_pages,
        linear_image_pages: image_pages,
        framebuffer_bytes: (image_count * image_bytes) as u32,
        window_function: 0,
    })
}

fn vbe<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) {
    // Every VBE call returns AL=4Fh ("supported"); AH=00h success, 01h failed.
    let al = regs.rax as u8;
    let done = |regs: &mut Regs, ok: bool| {
        regs.rax = (regs.rax & !0xFFFF) | if ok { 0x004F } else { 0x014F };
    };
    match al {
        0x00 => {
            let native_modes = bios_display.curated_modes();
            vbe_controller_info(machine, dos, regs, native_modes);
            done(regs, true);
        }
        0x01 => {
            let native_mode = bios_display.curated_mode(regs.rcx as u16 & 0x3FFF);
            let ok = synthetic_vbe_mode_info(machine, dos, regs, native_mode);
            done(regs, ok);
        }
        0x02 => {
            let ok = vbe_set_mode(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        0x03 => {
            let cur = if let Some(display) = dos.pc.vga.native() {
                match display.cap()
                    .bios_current_vbe_mode(machine, bios_display)
                {
                    Ok(Some((mode, linear))) => mode.number | if linear { 0x4000 } else { 0 },
                    Ok(None) => 0,
                    Err(_) => { done(regs, false); return; }
                }
            } else {
                match dos.pc.vga.emulated().expect("DOS video has no VGA state").resume {
                    crate::kernel::bios_display::VideoResume::Vbe { request, .. } => request,
                    crate::kernel::bios_display::VideoResume::Legacy { .. } => 0,
                }
            };
            regs.rbx = (regs.rbx & !0xFFFF) | cur as u64;
            done(regs, true);
        }
        0x05 => {
            let ok = vbe_window(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        0x06 => {
            let ok = vbe_scan_line(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        0x07 => {
            let ok = if let Some(display) = dos.pc.vga.native() {
                display.cap().guest_bios_display_start(
                    machine, bios_display, regs,
                ).is_ok()
            } else {
                emulated_vbe_display_start(&mut dos.pc, regs)
            };
            done(regs, ok);
        }
        0x08 => { vbe_dac_format(regs); done(regs, true); }
        0x09 => {
            let ok = vbe_palette(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        // The native 4F0Ah result is executable code in the isolated BIOS
        // workspace. Returning its ES:DI would hand the guest a pointer into a
        // different address space. Report the standard failure so clients use
        // their INT 10h fallback (including Build's 4F05h/4F07h paths).
        0x0A => done(regs, false),
        _ => done(regs, false),
    }
}

/// VBE 4F08h — Set/Get DAC palette format. We model only the 6-bit VGA DAC, so
/// report BH=6 for both set and get (a client asking for 8-bit falls back).
fn vbe_dac_format(regs: &mut Regs) {
    regs.rbx = (regs.rbx & !0xFF00) | (6 << 8);
}

/// VBE 4F09h — Set/Get Palette Data. CX entries from index DX at ES:DI, each 4
/// bytes (Blue, Green, Red, align), 6-bit components. Routed through the DAC
/// ports so the SVGA renderer (which reads `vga.dac`) sees one palette path.
fn vbe_palette<A: crate::Arch>(
    machine: &mut A,
    _bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) -> bool {
    let indexed = if let Some(display) = dos.pc.vga.native() {
        display.is_indexed_vbe()
    } else {
        matches!(dos.pc.vga.emulated().expect("DOS video has no VGA state").resume,
            crate::kernel::bios_display::VideoResume::Vbe { mode, .. }
                if matches!(mode.format,
                    crate::kernel::display::FormatSpec::Indexed8))
    };
    if !indexed { return false; }
    let count = regs.rcx as u16 as usize;
    let start = regs.rdx as u8;
    if count > 256 - usize::from(start) { return false; }
    let tbl = es_offset(dos, regs, regs.rdi as u32);
    if let Some(display) = dos.pc.vga.native_mut() {
        // The guest sees a RetroOS VBE adapter, not the physical ROM's API.
        // Implement its indexed-palette service directly on the VGA DAC so a
        // card BIOS that has modes but no 4F09h (notably the Cirrus GD5446
        // ROM in 86Box) cannot make our advertised service a false success.
        let mut data = alloc::vec![0; count * 4];
        if !display.physical_vbe_dac_access() {
            let copy_to_bios = matches!(regs.rbx as u8, 0x00 | 0x80);
            if !copy_to_bios && regs.rbx as u8 != 0x01 { return false; }
            if copy_to_bios { machine.copy_from(tbl, &mut data); }
            let ok = display.cap_mut().bios_palette_call(
                machine,
                _bios_display,
                regs,
                (!data.is_empty()).then_some(data.as_mut_slice()),
                copy_to_bios,
                true,
            ).is_ok();
            if ok && !copy_to_bios { machine.copy_to(tbl, &data); }
            return ok;
        }
        match regs.rbx as u8 {
            0x00 | 0x80 => {
                machine.copy_from(tbl, &mut data);
                crate::kernel::drivers::vga_hw::set_vbe_palette(
                    display.cap(), start, &data,
                );
            }
            0x01 => {
                crate::kernel::drivers::vga_hw::get_vbe_palette(
                    display.cap(), start, &mut data,
                );
                machine.copy_to(tbl, &data);
            }
            _ => return false,
        }
        return true;
    }
    match regs.rbx as u8 {
        0x00 | 0x80 => {
            // Set (00h) / set-during-retrace (80h): we apply immediately.
            emulate_outb(machine, &mut dos.pc, regs, 0x3C8, start);
            for i in 0..count {
                let e = tbl + i * 4;
                let (b, g, r): (u8, u8, u8) = (machine.read(e), machine.read(e + 1), machine.read(e + 2));
                emulate_outb(machine, &mut dos.pc, regs, 0x3C9, r);
                emulate_outb(machine, &mut dos.pc, regs, 0x3C9, g);
                emulate_outb(machine, &mut dos.pc, regs, 0x3C9, b);
            }
            true
        }
        0x01 => {
            // Get: read the DAC back into the caller's table.
            emulate_outb(machine, &mut dos.pc, regs, 0x3C7, start);
            for i in 0..count {
                let r = emulate_inb(machine, &mut dos.pc, 0x3C9);
                let g = emulate_inb(machine, &mut dos.pc, 0x3C9);
                let b = emulate_inb(machine, &mut dos.pc, 0x3C9);
                let e = tbl + i * 4;
                machine.write::<u8>(e, b);
                machine.write::<u8>(e + 1, g);
                machine.write::<u8>(e + 2, r);
                machine.write::<u8>(e + 3, 0);
            }
            true
        }
        _ => false, // 02h secondary palette: unsupported
    }
}

/// Resolve an INT 10h ES:offset buffer. Real-mode callers pass paragraphs;
/// protected-mode callers reach the direct-service vector with their selector
/// intact, so use its LDT descriptor base.
fn es_offset<A: crate::Arch>(dos: &super::DosState<A>, regs: &Regs, off: u32) -> usize {
    if regs.mode() == crate::UserMode::VM86 {
        (((regs.es as u16 as u32) << 4).wrapping_add(off & 0xFFFF) & !(1 << 20)) as usize
    } else {
        super::mode_transitions::seg_base(&dos.ldt[..], regs.es as u16)
            .wrapping_add(off) as usize
    }
}

/// VBE 4F00h — controller info into ES:DI, with the mode list placed in the
/// block's reserved area and pointed at by VideoModePtr.
fn vbe_controller_info<A: crate::Arch>(
    machine: &mut A,
    dos: &super::DosState<A>,
    regs: &mut Regs,
    native_modes: Option<&[crate::kernel::platform::VbeMode]>,
) {
    let lin = es_offset(dos, regs, regs.rdi as u32);
    for i in (0..256).step_by(4) {
        machine.write::<u32>(lin + i, 0);
    }
    machine.write::<u8>(lin, b'V');
    machine.write::<u8>(lin + 1, b'E');
    machine.write::<u8>(lin + 2, b'S');
    machine.write::<u8>(lin + 3, b'A');
    machine.write::<u16>(lin + 0x04, 0x0200); // VBE 2.0
    // VideoModePtr (0x0E) → mode list at ES:(DI+0x20), in the reserved area.
    let list_off = (regs.rdi as u16).wrapping_add(0x20);
    machine.write::<u32>(lin + 0x0E, ((regs.es as u32 & 0xFFFF) << 16) | list_off as u32);
    machine.write::<u16>(lin + 0x12, 0x100); // generic adapter memory: 16 MB
    let mut p = lin + 0x20;
    if let Some(modes) = native_modes {
        for mode in modes {
            machine.write::<u16>(p, mode.number);
            p += 2;
        }
    } else {
        for &(num, ..) in VBE_MODES {
            machine.write::<u16>(p, num);
            p += 2;
        }
    }
    machine.write::<u16>(p, 0xFFFF); // list terminator
}

/// Generic RetroOS VBE 4F01h — mode info for CX into ES:DI. Curated native
/// modes retain only validated geometry, pitch, pixel format and apertures;
/// vendor identity, executable pointers and private controller fields never
/// cross out of the firmware workspace.
fn synthetic_vbe_mode_info<A: crate::Arch>(
    machine: &mut A,
    dos: &super::DosState<A>,
    regs: &mut Regs,
    native_mode: Option<crate::kernel::platform::VbeMode>,
) -> bool {
    let want = regs.rcx as u16 & 0x1FF;
    let mode = native_mode.or_else(|| substitute_vbe_mode(want));
    let (w, h, bpp, banked_pitch, linear_pitch, physical_base, format,
        window_segment, granularity, window_size, banked_pages, linear_pages) = if let Some(mode) = mode {
        (mode.width, mode.height, mode.bits_per_pixel, mode.banked_pitch,
            mode.linear_pitch,
            mode.physical_base, mode.format, mode.window_segment,
            mode.window_granularity_kb, mode.window_size_kb,
            mode.banked_image_pages, mode.linear_image_pages)
    } else {
        return false;
    };
    let lin = es_offset(dos, regs, regs.rdi as u32);
    for i in (0..256).step_by(4) {
        machine.write::<u32>(lin + i, 0);
    }
    let direct = matches!(format, crate::kernel::display::FormatSpec::Packed(_));
    // ModeAttributes: supported|reserved|colour|graphics, plus LFB only when
    // the curated hardware mode actually has one.
    machine.write::<u16>(lin, 0x003B | if physical_base != 0 { 0x0080 } else { 0 });
    machine.write::<u8>(lin + 0x02, if window_segment != 0 { 0x07 } else { 0 });
    machine.write::<u8>(lin + 0x03, 0x00); // win B: not present
    machine.write::<u16>(lin + 0x04, granularity); // granularity (KB)
    machine.write::<u16>(lin + 0x06, window_size); // window size (KB)
    machine.write::<u16>(lin + 0x08, window_segment); // win A segment
    if window_segment != 0 {
        // A process-owned real-mode thunk with the standard 4F05 register ABI.
        // Guests may call this hot bank switch directly without learning the
        // physical BIOS's private address-space pointer.
        machine.write::<u32>(lin + 0x0C, super::dos::vbe_window_ptr());
    }
    machine.write::<u16>(lin + 0x10, banked_pitch); // banked bytes per scanline
    machine.write::<u16>(lin + 0x12, w);
    machine.write::<u16>(lin + 0x14, h);
    machine.write::<u8>(lin + 0x16, 8); // char width
    machine.write::<u8>(lin + 0x17, 16); // char height
    machine.write::<u8>(lin + 0x18, 1); // planes
    machine.write::<u8>(lin + 0x19, bpp);
    machine.write::<u8>(lin + 0x1A, 1); // banks
    machine.write::<u8>(lin + 0x1B, if direct { 6 } else { 4 }); // direct vs packed
    machine.write::<u8>(lin + 0x1D, banked_pages);
    machine.write::<u8>(lin + 0x1E, 1); // reserved (must be 1)
    if direct {
        // (red, grn, blu, rsv) as (mask_size, field_position) at 0x1F..0x26.
        let crate::kernel::display::FormatSpec::Packed(pixel) = format else {
            return false;
        };
        let used = pixel.red_size + pixel.green_size + pixel.blue_size;
        let masks: [(u8, u8); 4] = [
            (pixel.red_size, pixel.red_pos),
            (pixel.green_size, pixel.green_pos),
            (pixel.blue_size, pixel.blue_pos),
            (bpp.saturating_sub(used), used),
        ];
        for (i, &(sz, pos)) in masks.iter().enumerate() {
            machine.write::<u8>(lin + 0x1F + i * 2, sz);
            machine.write::<u8>(lin + 0x20 + i * 2, pos);
            // VBE 3.0's linear-framebuffer mask fields. The curated model
            // exposes one canonical pixel encoding for both access paths.
            machine.write::<u8>(lin + 0x36 + i * 2, sz);
            machine.write::<u8>(lin + 0x37 + i * 2, pos);
        }
        machine.write::<u8>(lin + 0x27, 1); // direct-colour mode information
    }
    // PhysBasePtr (0x28): the framebuffer's linear base — directly usable by a
    // PM/DPMI client (physical == linear here). LinBytesPerScanLine (0x32)
    // mirrors the banked pitch since the framebuffer is contiguous.
    machine.write::<u32>(lin + 0x28, physical_base);
    machine.write::<u16>(lin + 0x32, linear_pitch);
    machine.write::<u8>(lin + 0x35, linear_pages);
    true
}

/// VBE 4F07h over the detached process framebuffer, including every image the
/// curated mode advertised. The active start is process state, not firmware
/// state, and therefore survives OSD/background execution exactly.
fn emulated_vbe_display_start(pc: &mut super::machine::PcMachine, regs: &mut Regs) -> bool {
    let Some(dev) = pc.vga.emulated_mut() else { return false };
    let crate::kernel::bios_display::VideoResume::Vbe {
        mode, display_start, logical_pitch, ..
    } = &mut dev.resume else {
        return regs.rbx as u8 == 0x01 && {
            regs.rcx &= !0xFFFF;
            regs.rdx &= !0xFFFF;
            true
        };
    };
    match regs.rbx as u8 {
        0x00 | 0x80 => {
            let x = regs.rcx as u16;
            let y = regs.rdx as u16;
            let step = u32::from(mode.bits_per_pixel.div_ceil(8));
            let start = u32::from(y) * u32::from(*logical_pitch) + u32::from(x) * step;
            let visible = u32::from(mode.height.saturating_sub(1))
                * u32::from(*logical_pitch)
                + u32::from(mode.width) * step;
            if start.saturating_add(visible) > mode.framebuffer_bytes { return false; }
            *display_start = (x, y);
            true
        }
        0x01 => {
            regs.rcx = (regs.rcx & !0xFFFF) | u64::from(display_start.0);
            regs.rdx = (regs.rdx & !0xFFFF) | u64::from(display_start.1);
            true
        }
        _ => false,
    }
}

fn vbe_scan_line<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) -> bool {
    if let Some(display) = dos.pc.vga.native() {
        return display.cap().guest_bios_scan_line_length(machine, bios, regs).is_ok();
    }
    let Some(dev) = dos.pc.vga.emulated_mut() else { return false };
    let crate::kernel::bios_display::VideoResume::Vbe {
        mode, logical_pitch, ..
    } = &mut dev.resume else { return false };
    let step = u16::from(mode.bits_per_pixel.div_ceil(8));
    let requested = match regs.rbx as u8 {
        0 => (regs.rcx as u16).checked_mul(step),
        2 => Some(regs.rcx as u16),
        1 | 3 => Some(*logical_pitch),
        _ => return false,
    };
    let Some(pitch) = requested else { return false };
    if pitch < mode.width.saturating_mul(step) { return false; }
    if matches!(regs.rbx as u8, 0 | 2) {
        *logical_pitch = pitch;
        dev.state.svga_pitch = pitch;
    }
    regs.rbx = (regs.rbx & !0xFFFF) | u64::from(*logical_pitch);
    regs.rcx = (regs.rcx & !0xFFFF) | u64::from(*logical_pitch / step.max(1));
    regs.rdx = (regs.rdx & !0xFFFF)
        | u64::from((mode.framebuffer_bytes / u32::from(*logical_pitch)).min(u32::from(u16::MAX)) as u16);
    true
}

/// VBE 4F02h — set mode (BX). The substitute exposes both the bank window and
/// its RAM-backed PhysBasePtr; native firmware receives the request unchanged.
fn vbe_set_mode<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) -> bool {
    if let Some(display) = dos.pc.as_mut().vga.native_mut() {
        return display.cap_mut()
            .guest_bios_set_mode_request(machine, bios_display, regs.rbx as u16)
            .is_ok();
    }
    if let Some(mode) = bios_display.curated_mode(regs.rbx as u16 & 0x3FFF) {
        let request = regs.rbx as u16;
        let linear_ok = request & 0x4000 == 0 || mode.physical_base != 0;
        let banked_ok = request & 0x4000 != 0 || mode.window_segment != 0;
        if !linear_ok || !banked_ok { return false; }
        super::machine::vga::svga_set_curated_mode(
            machine, &mut dos.pc, mode, request);
        super::dpmi::refresh_physical_mappings(machine, dos);
        return true;
    }
    let want = regs.rbx as u16 & 0x3FFF;
    let Some(mode) = substitute_vbe_mode(want) else {
        return false;
    };
    super::machine::vga::svga_set_curated_mode(
        machine, &mut dos.pc, mode, regs.rbx as u16,
    );
    super::dpmi::refresh_physical_mappings(machine, dos);
    true
}

/// VBE 4F05h — window control. BH=0 set / 1 get; BL=window (we only do A); DX=bank.
fn vbe_window<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) -> bool {
    if let Some(display) = dos.pc.as_mut().vga.native_mut() {
        let set = ((regs.rbx >> 8) as u8 == 0).then_some(regs.rdx as u16);
        return match display.cap().guest_bios_window(machine, bios_display, set) {
            Ok(bank) => {
                regs.rdx = (regs.rdx & !0xFFFF) | u64::from(bank);
                true
            }
            Err(_) => false,
        };
    }
    let Some(dev) = dos.pc.vga.emulated() else { return false };
    if matches!(dev.resume,
        crate::kernel::bios_display::VideoResume::Vbe { request, .. }
            if request & 0x4000 != 0)
    {
        return false;
    }
    if (regs.rbx >> 8) as u8 == 0 {
        super::machine::vga::svga_set_bank(machine, &mut dos.pc, regs.rdx as u16);
    } else {
        let Some(dev) = dos.pc.vga.emulated() else { return false };
        let bank = dev.state.svga_bank;
        regs.rdx = (regs.rdx & !0xFFFF) | bank as u64;
    }
    true
}

/// Real-mode far-call entry advertised as ModeInfoBlock.WinFuncPtr. Unlike the
/// INT 10h dispatcher it owns a CALL FAR return frame, which the control-stub
/// dispatcher pops after this operation completes.
pub(super) fn vbe_window_entry<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut super::DosState<A>,
    regs: &mut Regs,
) -> bool {
    vbe_window(machine, bios_display, dos, regs)
}

// ============================================================================
// INT 1Ah: system timer
// ============================================================================

fn int1a<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        0x00 => {
            // Read tick count: CX:DX = ticks, AL = midnight flag.
            let ticks: u32 = bda_field!(machine, tick_count);
            regs.rcx = (regs.rcx & !0xFFFF) | (ticks >> 16) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (ticks & 0xFFFF) as u64;
            regs.rax &= !0xFF; // AL = 0 (no rollover)
        }
        0x01 => {
            // Set tick count from CX:DX.
            let t = ((regs.rcx as u16 as u32) << 16) | regs.rdx as u16 as u32;
            bda_field!(machine, tick_count = t);
        }
        0x02 => {
            // Read RTC time: CH=hours CL=minutes DH=seconds DL=DST flag,
            // all BCD, CF clear on success — the real AT BIOS ABI. Backed
            // by the host CMOS like the 40:6C seed.
            let (hour, min, sec) = super::dos::rtc_time(machine);
            let bcd = |v: u8| ((v / 10) << 4) | (v % 10);
            regs.rcx = (regs.rcx & !0xFFFF)
                | ((bcd(hour) as u64) << 8)
                | bcd(min) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | ((bcd(sec) as u64) << 8);
            set_iret_cf(machine, regs, false);
        }
        _ => {}
    }
}
