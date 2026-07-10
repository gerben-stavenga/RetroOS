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

use crate::Regs;
use crate::kernel::thread;
use super::machine::{
    self, emulate_inb, emulate_outb, vm86_ip, vm86_pop, vm86_sp, vm86_ss, read_u16, write_u16,
};
use super::dosabi::STUB_SEG;
use core::sync::atomic::{AtomicU32, Ordering};

/// The native BIOS ROM's INT 15h vector (`seg<<16 | off`), captured before we
/// steal the vector in `setup_ivt`, so subfunctions we don't emulate can chain
/// back to it. `NO_NATIVE` on the Substitute path — there's no ROM to chain to,
/// and unhandled subfunctions just IRET.
const NO_NATIVE: u32 = 0xFFFF_FFFF;
static NATIVE_INT15: AtomicU32 = AtomicU32::new(NO_NATIVE);

/// Record the ROM INT 15h vector before `setup_ivt` redirects it to our stub.
pub(super) fn set_native_int15(seg: u16, off: u16) {
    NATIVE_INT15.store(((seg as u32) << 16) | off as u32, Ordering::Relaxed);
}
fn native_int15() -> Option<(u16, u16)> {
    match NATIVE_INT15.load(Ordering::Relaxed) {
        NO_NATIVE => None,
        v => Some(((v >> 16) as u16, v as u16)),
    }
}

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
/// on top). Native-vs-substitute is decided by the boot-time probe
/// (`platform::Firmware`), not sniffed here.
pub(super) fn install<A: crate::Arch>(machine: &mut A, _regs: &mut Regs) {
    crate::dbg_println!("DOS: no BIOS ROM — installing the personality BIOS (display {:?})",
        crate::kernel::platform::get().display);
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
        let serviced = matches!(n,
            0x00..=0x33 | 0x40..=0x46 | 0x4A | 0x67 | 0x70..=0x77);
        let off = if serviced { (n * 2) as u16 } else { DUMMY_OFF };
        write_u16(machine, 0, n * 4, off);
        write_u16(machine, 0, n * 4 + 2, STUB_SEG);
    }
    seed_bda(machine);
}

/// Seed the BDA fields a real POST would have set.
fn seed_bda<A: crate::Arch>(machine: &mut A) {
    // Zero the whole BDA first: on a UEFI machine this low page holds
    // whatever the firmware left behind (a real POST cleared it), and guests
    // read unseeded fields directly — DOS/4GW #DE'd converting a leftover
    // 0xFFF1xxxx at 40:6C to a time of day.
    machine.copy_to(0x400, &[0u8; 0x100]);
    // Tick-of-day counter: a real POST seeds 40:6C from the RTC.
    let ticks = super::dos::rtc_ticks_today(machine);
    bda_field!(machine, tick_count = ticks);
    bda_field!(machine, mem_size_kb = 640u16);
    bda_field!(machine, video_mode = 3u8); // 80x25 colour text
    bda_field!(machine, columns = 80u16);
    bda_field!(machine, crtc_base = 0x03D4u16);
    bda_field!(machine, rows_minus1 = 24u8);
    bda_field!(machine, cell_height = 16u16);
    bda_field!(machine, equipment = 0x0001u16);
    bda_field!(machine, kb_head = KB_RING_FIRST);
    bda_field!(machine, kb_tail = KB_RING_FIRST);
    bda_field!(machine, kb_ring_start = KB_RING_FIRST);
    bda_field!(machine, kb_ring_end = KB_RING_END);
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
        0x09 => int09(machine, dos, regs),
        0x0A..=0x0F => emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20), // master-PIC IRQ default: EOI
        0x70..=0x77 => {
            // Slave-PIC IRQ default: EOI both.
            emulate_outb(machine, &mut dos.pc, regs, 0xA0, 0x20);
            emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
        }
        0x10 => int10(machine, dos, regs),
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
            // Everything else: on a real BIOS, hand back to the ROM (WAIT,
            // ext-mem size, …) reusing the caller's INT frame. On Substitute
            // there's no ROM, so fall through to a plain IRET as before.
            _ => if let Some((seg, off)) = native_int15() {
                machine::set_vm86_cs(regs, seg);
                machine::set_vm86_ip(regs, off);
                return thread::KernelAction::Done;
            },
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

fn int16<A: crate::Arch>(machine: &mut A, regs: &mut Regs, stub_ip: u16) -> Parked {
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
            let key: u16 = machine.read(BDA_BASE + head as usize);
            let mut next = head + 2;
            if next >= KB_RING_END {
                next = KB_RING_FIRST;
            }
            bda_field!(machine, kb_head = next);
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
                let key: u16 = machine.read(BDA_BASE + head as usize);
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
/// track shift/ctrl in the BDA flag byte, push (scancode:ascii) into the
/// ring for INT 16h. Extended keys (arrows, F-keys) push ascii=0.
fn int09<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>, regs: &mut Regs) {
    let sc = emulate_inb(machine, &mut dos.pc, 0x60);
    let key = sc & 0x7F;
    let mut flags: u8 = bda_field!(machine, kb_flags);

    // Shift / Ctrl are modifiers: update the BDA flag byte, don't enqueue.
    let modifier_bit = match key {
        0x2A => Some(0x02u8), // left shift
        0x36 => Some(0x01),   // right shift
        0x1D => Some(0x04),   // ctrl
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

    let tail: u16 = bda_field!(machine, kb_tail);
    let mut next = tail + 2;
    if next >= KB_RING_END {
        next = KB_RING_FIRST;
    }
    let head: u16 = bda_field!(machine, kb_head);
    if next != head {
        // ring not full
        machine.write::<u16>(BDA_BASE + tail as usize, ((key as u16) << 8) | asc as u16);
        bda_field!(machine, kb_tail = next);
    }
    emulate_outb(machine, &mut dos.pc, regs, 0x20, 0x20);
}

// ============================================================================
// INT 10h: video
// ============================================================================

const VRAM_TEXT: usize = 0xB8000;
const VRAM_MODE13: usize = 0xA0000;

fn int10<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>, regs: &mut Regs) {
    let ax = regs.rax as u16;
    let ah = (ax >> 8) as u8;
    match ah {
        0x00 => {
            // Set video mode — record it, set BDA geometry, clear VRAM.
            let mode = (ax & 0x7F) as u8;
            let clear = ax & 0x80 == 0;
            bda_field!(machine, video_mode = mode);
            // Text-grid geometry per mode: 40-column modes (CGA/EGA 320-wide and
            // mode 13h) vs 80; 30 rows on the 480-line VGA modes; character cell
            // height 8 (200-line + 13h), 14 (350-line EGA), or 16 (text/480-line).
            bda_field!(machine, columns = match mode { 0 | 1 | 4 | 5 | 0x0D | 0x13 => 40u16, _ => 80 });
            bda_field!(machine, rows_minus1 = if matches!(mode, 0x11 | 0x12) { 29u8 } else { 24 });
            bda_field!(machine, cell_height = match mode { 4 | 5 | 6 | 0x0D | 0x0E | 0x13 => 8u16, 0x0F | 0x10 => 14, _ => 16 });
            bda_field!(machine, active_page = 0u8);
            bda_field!(machine, cursor_pos = [0u16; 8]);
            // Arm/disarm the planar VRAM trap for the EGA 16-colour family
            // (0x0D–0x12, Keen): a BIOS-set planar mode never toggles the
            // Sequencer chain-4 bit, so this is the only place the trap gets
            // armed. (`clear` also blanks the planes.)
            super::machine::vga::on_set_mode(machine, &mut dos.pc, regs, mode, clear);
            if clear {
                // AL bit 7 clear: clear the framebuffer. Planar modes are
                // cleared inside on_set_mode (their VRAM is the plane window).
                if mode == 0x13 {
                    for i in 0..(320 * 200 / 4) {
                        machine.write::<u32>(VRAM_MODE13 + i * 4, 0);
                    }
                } else if !matches!(mode, 0x0D..=0x12) {
                    for i in 0..16384 {
                        // full 32K text window
                        machine.write::<u16>(VRAM_TEXT + i * 2, 0x0720);
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
        0x0E => {
            // Teletype output: write at cursor, advance. (Scroll is handled
            // by direct writers, matching the C BIOS.)
            let ch = (ax & 0xFF) as u8;
            let page: u8 = bda_field!(machine, active_page);
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + (page & 7) as usize * 2;
            let pos: u16 = machine.read(bda(pos_off));
            let (mut row, mut col) = ((pos >> 8) as u32, (pos & 0xFF) as u32);
            let cols: u16 = bda_field!(machine, columns);
            let mode: u8 = bda_field!(machine, video_mode);
            match ch {
                b'\r' => col = 0,
                b'\n' => row += 1,
                0x08 => col = col.saturating_sub(1),
                _ => {
                    // Graphics modes have no text cell: rasterize the glyph into
                    // the framebuffer (BL = foreground colour). Text modes write
                    // the char byte at the cursor cell as before.
                    let fg = regs.rbx as u8;
                    if !super::machine::vga::bios_draw_glyph(machine, &mut dos.pc.vga, mode, ch, col, row, fg) {
                        let off = (row * cols as u32 + col) as usize * 2;
                        machine.write::<u8>(VRAM_TEXT + off, ch);
                    }
                    col += 1;
                    if col >= cols as u32 {
                        col = 0;
                        row += 1;
                    }
                }
            }
            let max_row: u8 = bda_field!(machine, rows_minus1);
            row = row.min(max_row as u32);
            machine.write::<u16>(bda(pos_off), ((row << 8) | col) as u16);
        }
        0x0F => {
            // Get video mode: AL=mode, AH=columns, BH=page.
            let mode: u8 = bda_field!(machine, video_mode);
            let cols: u16 = bda_field!(machine, columns);
            let page: u8 = bda_field!(machine, active_page);
            regs.rax = (regs.rax & !0xFFFF) | ((cols << 8) | mode as u16) as u64;
            regs.rbx = (regs.rbx & !0xFF00) | ((page as u64) << 8);
        }
        0x10 => {
            // Palette/DAC — forward to the AC/DAC ports so the platform's
            // palette capture (and a real card on metal) sees one path.
            match (ax & 0xFF) as u8 {
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
                    let tbl = ((regs.es as u16 as usize) << 4) + regs.rdx as u16 as usize;
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
                    let cur = dos.pc.vga.ac[0x10];
                    let val = if blink { cur | 0x08 } else { cur & !0x08 };
                    let _ = emulate_inb(machine, &mut dos.pc, 0x3DA); // reset AC flip-flop
                    emulate_outb(machine, &mut dos.pc, regs, 0x3C0, 0x10 | 0x20);
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
                    let tbl = ((regs.es as u16 as usize) << 4) + regs.rdx as u16 as usize;
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
                    let tbl = ((regs.es as u16 as usize) << 4) + regs.rdx as u16 as usize;
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
        0x4F => vbe(machine, dos, regs),
        _ => {}
    }
}

// ============================================================================
// VESA VBE (INT 10h AH=4Fh)
// ============================================================================

/// The banked SVGA modes we expose: (VBE mode#, width, height, bpp). Presented
/// through the emulated framebuffer sink, integer-scaled/centred to the panel.
/// 8bpp goes through the DAC palette; 15/16/32 are direct colour. Substitute
/// path only — the native/SeaBIOS path has the card's own VBE.
const VBE_MODES: &[(u16, u16, u16, u8)] = &[
    (0x101, 640, 480, 8),
    (0x103, 800, 600, 8),
    (0x110, 640, 480, 15),
    (0x111, 640, 480, 16),
    (0x112, 640, 480, 32),
];

fn vbe<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>, regs: &mut Regs) {
    // Every VBE call returns AL=4Fh ("supported"); AH=00h success, 01h failed.
    let al = regs.rax as u8;
    let done = |regs: &mut Regs, ok: bool| {
        regs.rax = (regs.rax & !0xFFFF) | if ok { 0x004F } else { 0x014F };
    };
    match al {
        0x00 => { vbe_controller_info(machine, regs); done(regs, true); }
        0x01 => { let ok = vbe_mode_info(machine, regs); done(regs, ok); }
        0x02 => { let ok = vbe_set_mode(machine, dos, regs); done(regs, ok); }
        0x03 => {
            let cur = VBE_MODES.iter()
                .find(|&&(_, w, h, b)| w == dos.pc.vga.svga_w && h == dos.pc.vga.svga_h && b == dos.pc.vga.svga_bpp)
                .map(|&(n, ..)| n)
                .unwrap_or(0);
            regs.rbx = (regs.rbx & !0xFFFF) | cur as u64;
            done(regs, true);
        }
        0x05 => { vbe_window(machine, dos, regs); done(regs, true); }
        0x08 => { vbe_dac_format(regs); done(regs, true); }
        0x09 => { let ok = vbe_palette(machine, dos, regs); done(regs, ok); }
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
fn vbe_palette<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>, regs: &mut Regs) -> bool {
    let count = regs.rcx as u16 as usize;
    let start = regs.rdx as u8;
    let tbl = es_di(regs);
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

/// Linear address of the caller's ES:DI block (real-mode VBE buffers).
fn es_di(regs: &Regs) -> usize {
    ((regs.es as usize & 0xFFFF) << 4) + (regs.rdi as usize & 0xFFFF)
}

/// VBE 4F00h — controller info into ES:DI, with the mode list placed in the
/// block's reserved area and pointed at by VideoModePtr.
fn vbe_controller_info<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let lin = es_di(regs);
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
    machine.write::<u16>(lin + 0x12, 0x80); // total memory: 0x80 × 64 KB = 8 MB
    let mut p = lin + 0x20;
    for &(num, ..) in VBE_MODES {
        machine.write::<u16>(p, num);
        p += 2;
    }
    machine.write::<u16>(p, 0xFFFF); // list terminator
}

/// VBE 4F01h — mode info for CX into ES:DI. Returns false for an unknown mode.
fn vbe_mode_info<A: crate::Arch>(machine: &mut A, regs: &mut Regs) -> bool {
    let want = regs.rcx as u16 & 0x1FF;
    let Some(&(_, w, h, bpp)) = VBE_MODES.iter().find(|&&(n, ..)| n == want) else {
        return false;
    };
    let lin = es_di(regs);
    for i in (0..256).step_by(4) {
        machine.write::<u32>(lin + i, 0);
    }
    let bpp8 = (bpp as u16).div_ceil(8);
    let direct = bpp >= 15;
    // ModeAttributes: supported|reserved|colour|graphics, banked + LFB (bit7).
    machine.write::<u16>(lin, 0x009B);
    machine.write::<u8>(lin + 0x02, 0x07); // win A: relocatable|readable|writable
    machine.write::<u8>(lin + 0x03, 0x00); // win B: not present
    machine.write::<u16>(lin + 0x04, 64); // granularity (KB)
    machine.write::<u16>(lin + 0x06, 64); // window size (KB)
    machine.write::<u16>(lin + 0x08, 0xA000); // win A segment
    machine.write::<u16>(lin + 0x10, w * bpp8); // bytes per scanline
    machine.write::<u16>(lin + 0x12, w);
    machine.write::<u16>(lin + 0x14, h);
    machine.write::<u8>(lin + 0x16, 8); // char width
    machine.write::<u8>(lin + 0x17, 16); // char height
    machine.write::<u8>(lin + 0x18, 1); // planes
    machine.write::<u8>(lin + 0x19, bpp);
    machine.write::<u8>(lin + 0x1A, 1); // banks
    machine.write::<u8>(lin + 0x1B, if direct { 6 } else { 4 }); // direct vs packed
    machine.write::<u8>(lin + 0x1E, 1); // reserved (must be 1)
    if direct {
        // (red, grn, blu, rsv) as (mask_size, field_position) at 0x1F..0x26.
        let masks: [(u8, u8); 4] = match bpp {
            15 => [(5, 10), (5, 5), (5, 0), (1, 15)],
            16 => [(5, 11), (6, 5), (5, 0), (0, 0)],
            _ => [(8, 16), (8, 8), (8, 0), if bpp == 32 { (8, 24) } else { (0, 0) }],
        };
        for (i, &(sz, pos)) in masks.iter().enumerate() {
            machine.write::<u8>(lin + 0x1F + i * 2, sz);
            machine.write::<u8>(lin + 0x20 + i * 2, pos);
        }
    }
    // PhysBasePtr (0x28): the framebuffer's linear base — directly usable by a
    // PM/DPMI client (physical == linear here). LinBytesPerScanLine (0x32)
    // mirrors the banked pitch since the framebuffer is contiguous.
    machine.write::<u32>(lin + 0x28, super::machine::vga::svga_lfb_base());
    machine.write::<u16>(lin + 0x32, w * bpp8);
    true
}

/// VBE 4F02h — set mode (BX). Ignores the LFB bit (we only do banked).
fn vbe_set_mode<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>, regs: &mut Regs) -> bool {
    let want = regs.rbx as u16 & 0x1FF;
    let Some(&(_, w, h, bpp)) = VBE_MODES.iter().find(|&&(n, ..)| n == want) else {
        return false;
    };
    super::machine::vga::svga_set_mode(machine, &mut dos.pc, w, h, bpp);
    true
}

/// VBE 4F05h — window control. BH=0 set / 1 get; BL=window (we only do A); DX=bank.
fn vbe_window<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>, regs: &mut Regs) {
    if (regs.rbx >> 8) as u8 == 0 {
        super::machine::vga::svga_set_bank(machine, &mut dos.pc, regs.rdx as u16);
    } else {
        regs.rdx = (regs.rdx & !0xFFFF) | dos.pc.vga.svga_bank as u64;
    }
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
