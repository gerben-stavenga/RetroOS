//! Legacy video BIOS services: INT 10h, fonts and text output.
use crate::Regs;
use crate::kernel::dos::{dos, machine, seg_offset, DosState};
use machine::{emulate_inb, emulate_outb, write_u16};
use machine::vga::bios_write_crtc;
use super::Bda;

/// The BIOS default text cursor: a two-scanline underline (start 6, end 7),
/// what a mode set installs in every text mode.
pub(super) const TEXT_CURSOR_SHAPE: u16 = 0x0607;

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
        8 => dos::font_8x8_addr(),
        14 => dos::font_8x14_addr(),
        _ => dos::font_8x16_addr(),
    }
}

/// INT 43h is the active graphics character generator, so it changes along
/// with the mode's character height rather than permanently naming 8x8.
fn publish_active_font<A: crate::Arch>(machine: &mut A, glyph_h: u8) {
    set_data_vector(machine, 0x43, rom_font_addr(glyph_h));
}

pub(super) fn install_rom_font<A: crate::Arch>(machine: &mut A) {
    let font8 = dos::font_8x8_addr();
    let font14 = dos::font_8x14_addr();
    let font16 = dos::font_8x16_addr();
    machine.copy_to(ROM_FONT_8X8, &lib::vga_fonts::FONT_8X8[..1024]);
    let fonts = lib::codepage::current_codepage().fonts();
    machine.copy_to(font8 as usize, fonts.h8);
    machine.copy_to(font14 as usize, fonts.h14);
    machine.copy_to(font16 as usize, &fonts.h16);
    set_data_vector(machine, 0x1F, font8 + 128 * 8);
    publish_active_font(machine, 16); // POST starts in 80x25, 8x16 mode 3.
}

/// Seed the video BIOS static functionality table AH=1Bh points at — the VGA
/// capability set, matching what we actually emulate (all modes 0-13h, 200/350/
/// 400-line, DAC palette + colour paging, DCC available).
pub(super) fn seed_video_static_info<A: crate::Arch>(machine: &mut A) {
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
    machine.copy_to(dos::video_static_info_addr() as usize, &t);
}

// ============================================================================
// INT 10h: video
// ============================================================================

const VRAM_TEXT: usize = 0xB8000;

/// Bytes in one BIOS video page (per plane in EGA graphics modes).
fn video_page_size(mode: u8, columns: u16) -> u16 {
    match mode {
        0x04..=0x06 => 0x4000,
        0x0D => 0x2000,
        0x0E => 0x4000,
        0x0F | 0x10 => 0x8000,
        0x11 | 0x12 => 0xA000,
        0x13 => 0xFA00,
        _ => (columns * 25 * 2).next_multiple_of(2048),
    }
}

/// BDA byte offset and CRTC start-address units for a valid BIOS page.
fn video_page_start(mode: u8, page: u8, size: u16) -> Option<(u16, u16)> {
    let offset = u32::from(page) * u32::from(size);
    if is_text_mode(mode) {
        (offset + u32::from(size) <= 0x8000).then_some((offset as u16, (offset / 2) as u16))
    } else if matches!(mode, 0x0D..=0x10) {
        // One address per byte within each EGA plane. Page 1 in mode 0Dh
        // starts at A000:2000, not the text-mode 0800-word boundary.
        (offset + u32::from(size) <= 0x10000).then_some((offset as u16, offset as u16))
    } else {
        (page == 0).then_some((0, 0))
    }
}

/// Only modes 0-3 and 7 have character cells.
fn is_text_mode(mode: u8) -> bool {
    matches!(mode, 0..=3 | 7)
}

#[cfg(test)]
mod page_tests {
    use super::{video_page_size, video_page_start};

    #[test]
    fn ega_graphics_pages_use_per_plane_bytes_and_text_uses_words() {
        for (mode, columns, size, last) in [
            (0x0D, 40, 0x2000, 7), (0x0E, 80, 0x4000, 3),
            (0x0F, 80, 0x8000, 1), (0x10, 80, 0x8000, 1),
        ] {
            assert_eq!(video_page_size(mode, columns), size);
            assert_eq!(video_page_start(mode, 1, size), Some((size, size)));
            assert!(video_page_start(mode, last, size).is_some());
            assert!(video_page_start(mode, last + 1, size).is_none());
        }
        assert_eq!(video_page_start(3, 1, video_page_size(3, 80)), Some((0x1000, 0x800)));
        assert_eq!(video_page_start(0x13, 1, video_page_size(0x13, 40)), None);
    }
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
        0x02 => dos::font_8x14_addr(),
        0x03 => dos::font_8x8_addr(),
        0x04 => dos::font_8x8_addr() + 128 * 8,
        // VGA defines alternate 9-dot 14/16-line selections here. Character
        // generator rows are still eight stored bits wide (the adapter makes
        // the ninth column), and our canonical ROM faces are the compatible
        // substitute when no separate alternate face is supplied.
        0x05 => dos::font_8x14_addr(),
        0x06 => dos::font_8x16_addr(),
        0x07 => dos::font_8x16_addr(),
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
    dos: &mut DosState<A>,
    regs: &mut Regs,
) {
    let subfn = regs.rax as u8;
    if subfn == 0x30 {
        get_font_info(machine, regs);
        return;
    }
    let map = usize::from(regs.rbx as u8 & 7);
    let set_geometry = matches!(subfn, 0x10 | 0x11 | 0x12 | 0x14);

    let fonts = lib::codepage::current_codepage().fonts();
    let mut owned = alloc::vec::Vec::new();
    let (first, glyph_h, font): (usize, usize, &[u8]) = match subfn {
        0x00 | 0x10 => {
            let glyph_h = usize::from((regs.rbx >> 8) as u8);
            let count = match regs.rcx as u16 { 0 => 256, n => usize::from(n) };
            let first = usize::from(regs.rdx as u16);
            if glyph_h == 0 || glyph_h > 32 || first + count > 256 { return; }
            owned.resize(count * glyph_h, 0);
            let src = seg_offset(dos, regs, regs.es as u16, regs.rbp as u16 as u32) as usize;
            machine.copy_from(src, &mut owned);
            (first, glyph_h, &owned)
        }
        0x01 | 0x11 => (0, 14, fonts.h14),
        0x02 | 0x12 => (0, 8, fonts.h8),
        0x04 | 0x14 => (0, 16, &fonts.h16),
        0x03 => {
            if let Some(display) = dos.pc.vga.native_mut() {
                let _ = display.cap_mut().bios_font_call(machine, bios_display, regs, None);
            } else {
                machine::vga::bios_set_font_map_select(&mut dos.pc.vga, regs.rbx as u8);
            }
            return;
        }
        _ => return,
    };

    if let Some(display) = dos.pc.vga.native_mut() {
        if matches!(subfn, 0x00 | 0x10) {
            let _ = display.cap_mut().bios_font_call(machine, bios_display, regs, Some(font));
        } else {
            // Native ROM font calls would reload the firmware's CP437 font.
            // Load our selected page through the BIOS user-font interface.
            let mut call = *regs;
            call.rax = if set_geometry { 0x1110 } else { 0x1100 };
            call.rbx = ((glyph_h as u64) << 8) | map as u64;
            call.rcx = 256;
            call.rdx = 0;
            let _ = display.cap_mut().bios_font_call(machine, bios_display, &mut call, Some(font));
            regs.rax = call.rax;
        }
    } else {
        machine::vga::bios_load_font(
            machine, &mut dos.pc.vga, map, first, font, glyph_h,
        );
        if set_geometry {
            machine::vga::bios_set_text_height(&mut dos.pc.vga, glyph_h as u8);
        }
    }

    if set_geometry {
        let rows: u8 = if glyph_h == 8 { 50 } else { 25 };
        bda_field!(machine, rows_minus1 = rows - 1);
        bda_field!(machine, cell_height = glyph_h as u16);
        bda_field!(machine, cursor_shape = ((glyph_h as u16 - 2) << 8) | (glyph_h as u16 - 1));
        publish_active_font(machine, glyph_h as u8);
        let cols: u16 = bda_field!(machine, columns);
        bda_field!(machine, video_page_size = (cols * u16::from(rows) * 2).next_multiple_of(2048));
        sync_cursor_shape(machine, dos);
        sync_cursor_position(machine, dos);
    }
}

/// Replace RetroOS's BIOS font tables and the active VGA character map.
/// Called before publishing a new DOS code page so the byte meanings and
/// displayed glyphs change together.
pub(in crate::kernel::dos) fn install_codepage_font<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    page: &lib::codepage::CodePage,
) -> bool {
    let fonts = page.fonts();
    let cell_height: u16 = bda_field!(machine, cell_height);
    let height = match cell_height as usize {
        8 => 8,
        14 => 14,
        _ => 16,
    };
    let font: &[u8] = match height { 8 => fonts.h8, 14 => fonts.h14, _ => &fonts.h16 };
    let installed = if let Some(display) = dos.pc.vga.native_mut() {
        let mut call = Regs::empty();
        call.rax = 0x1100;
        call.rbx = (height as u64) << 8;
        call.rcx = 256;
        display.cap_mut().bios_font_call(machine, bios_display, &mut call, Some(font)).is_ok()
    } else {
        machine::vga::bios_load_font(machine, &mut dos.pc.vga, 0, 0, font, height);
        machine::vga::bios_load_font(machine, &mut dos.pc.vga, 1, 0, font, height);
        true
    };
    if installed {
        machine.copy_to(dos::font_8x8_addr() as usize, fonts.h8);
        machine.copy_to(dos::font_8x14_addr() as usize, fonts.h14);
        machine.copy_to(dos::font_8x16_addr() as usize, &fonts.h16);
    }
    installed
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
pub(in crate::kernel::dos) fn teletype<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, ch: u8, fg: u8) {
    let page: u8 = bda_field!(machine, active_page);
    let pos_off = core::mem::offset_of!(Bda, cursor_pos) + (page & 7) as usize * 2;
    let pos: u16 = machine.read(Bda::BASE + pos_off);
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
            if !machine::vga::bios_draw_glyph(machine, &mut dos.pc.vga, mode, ch, col, row, fg) {
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
    machine.write::<u16>(Bda::BASE + pos_off, ((row << 8) | col) as u16);
    sync_cursor_position(machine, dos);
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
    let page_size: u16 = bda_field!(machine, video_page_size);
    VRAM_TEXT
        + (page as usize & 7) * usize::from(page_size)
        + (row as usize * cols as usize + col as usize) * 2
}

fn sync_cursor_position<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>) {
    if !is_text_mode(Bda::video_mode(machine)) { return; }
    let page: u8 = bda_field!(machine, active_page);
    let (row, col) = cursor_of(machine, page);
    let cols: u16 = bda_field!(machine, columns);
    let page_size: u16 = bda_field!(machine, video_page_size);
    let address = (u32::from(page & 7) * u32::from(page_size) / 2 + row * u32::from(cols) + col) as u16;
    bios_write_crtc(machine, &mut dos.pc.vga, 0x0E, (address >> 8) as u8);
    bios_write_crtc(machine, &mut dos.pc.vga, 0x0F, address as u8);
}

/// VGA BIOS compatibility: scale a CGA-style cursor to the active font height.
fn cursor_scanlines(shape: u16, height: u16) -> (u8, u8) {
    let mut start = (shape >> 8) as u8;
    let mut end = shape as u8;
    if height > 8 && end < 8 && start < 0x20 {
        start = if end == start + 1 {
            ((u16::from(end) + 1) * height / 8 - 2) as u8
        } else {
            ((u16::from(start) + 1) * height / 8 - 1) as u8
        };
        end = ((u16::from(end) + 1) * height / 8 - 1) as u8;
    }
    (start, end)
}

fn sync_cursor_shape<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>) {
    if !is_text_mode(Bda::video_mode(machine)) { return; }
    let shape: u16 = bda_field!(machine, cursor_shape);
    let height: u16 = bda_field!(machine, cell_height);
    let (start, end) = cursor_scanlines(shape, height);
    bios_write_crtc(machine, &mut dos.pc.vga, 0x0A, start);
    bios_write_crtc(machine, &mut dos.pc.vga, 0x0B, end);
}

/// A page's cursor position from the BDA, as (row, column).
fn cursor_of<A: crate::Arch>(machine: &mut A, page: u8) -> (u32, u32) {
    let pos_off = core::mem::offset_of!(Bda, cursor_pos) + (page as usize & 7) * 2;
    let pos: u16 = machine.read(Bda::BASE + pos_off);
    ((pos >> 8) as u32, (pos & 0xFF) as u32)
}

/// Apply the VGA BIOS's CGA-palette compatibility mapping. Port 3D9h is a
/// physical CGA register; EGA/VGA BIOSes emulate it by rewriting Attribute
/// Controller palette entries. Keeping the 3D9h mirror alone is sufficient
/// for our CGA renderer but has no visible effect on a native VGA card.
fn set_cga_compat_palette<A: crate::Arch>(
    machine: &mut A,
    pc: &mut machine::PcMachine,
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

pub(in crate::kernel::dos) fn int10<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) {
    let ax = regs.rax as u16;
    let ah = (ax >> 8) as u8;
    match ah {
        0x00 => {
            let mode = (ax & 0x7F) as u8;
            let clear = ax & 0x80 == 0;
            let mode_ctl: u8 = match mode {
                0 => 0x2C, 1 => 0x28, 2 => 0x2D, 4 => 0x2A, 5 => 0x2E, 6 => 0x1E, _ => 0x29,
            };
            let palette: u8 = if mode == 6 { 0x3F } else { 0x30 };

            if let Some(display) = dos.pc.vga.native_mut() {
                let _ = display.cap_mut().guest_bios_set_mode(
                    machine, bios_display, ax & 0xFF);
            } else if let Some(display) = dos.pc.vga.emulated_mut() {
                machine::vga::set_emulated_mode(machine, display, mode, clear);
                if let Some(state) = display.state.legacy_mut() {
                    machine::vga::port_write(machine, state, 0x3D8, mode_ctl);
                    machine::vga::port_write(machine, state, 0x3D9, palette);
                }
                if clear {
                    machine::vga::bios_clear_framebuffer(machine, &mut dos.pc.vga, mode);
                }
            }

            // Publish the new mode in the guest's BIOS data area.
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
            bda_field!(machine, video_page_start = 0u16);
            let cols: u16 = bda_field!(machine, columns);
            bda_field!(machine, video_page_size = video_page_size(mode, cols));
            bda_field!(machine, crtc_base = if mode == 7 { 0x3B4u16 } else { 0x3D4u16 });
            bda_field!(machine, cursor_pos = [0u16; 8]);
            // A mode set resets the cursor to the BIOS default underline (and
            // hides it in graphics modes) — guests read it back via AH=03 and
            // AH=1Bh, so it must not stay at whatever the last program set.
            bda_field!(machine, cursor_shape =
                if is_text_mode(mode) { TEXT_CURSOR_SHAPE } else { 0x0000u16 });
            bda_field!(machine, crt_mode_ctl = mode_ctl);
            bda_field!(machine, crt_palette = palette);

            if dos.pc.vga.is_native() {
                if lib::codepage::current_codepage().id != 437 {
                    let _ = install_codepage_font(machine, bios_display, dos, lib::codepage::current_codepage());
                }
            } else {
                sync_cursor_shape(machine, dos);
                sync_cursor_position(machine, dos);
            }
        }
        0x01 => {
            bda_field!(machine, cursor_shape = regs.rcx as u16);
            sync_cursor_shape(machine, dos);
        }
        0x02 => {
            // Set cursor position: BH=page, DH=row, DL=col.
            let page = ((regs.rbx >> 8) & 0x7) as usize;
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
            machine.write::<u16>(Bda::BASE + pos_off, regs.rdx as u16);
            let active: u8 = bda_field!(machine, active_page);
            if page == usize::from(active) { sync_cursor_position(machine, dos); }
        }
        0x03 => {
            let page = ((regs.rbx >> 8) & 0x7) as usize;
            let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
            let pos: u16 = machine.read(Bda::BASE + pos_off);
            let shape: u16 = bda_field!(machine, cursor_shape);
            regs.rdx = (regs.rdx & !0xFFFF) | pos as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | shape as u64;
        }
        0x05 => {
            let page = (ax & 7) as u8;
            let mode = Bda::video_mode(machine);
            let size: u16 = bda_field!(machine, video_page_size);
            if let Some((offset, start)) = video_page_start(mode, page, size) {
                bda_field!(machine, active_page = page);
                bda_field!(machine, video_page_start = offset);
                bios_write_crtc(machine, &mut dos.pc.vga, 0x0C, (start >> 8) as u8);
                bios_write_crtc(machine, &mut dos.pc.vga, 0x0D, start as u8);
                sync_cursor_position(machine, dos);
            }
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
                if !machine::vga::bios_draw_glyph(machine, &mut dos.pc.vga, mode, ch, c, r, attr) {
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
            if dos.pc.vga.native_legacy_vga(bios_display) {
                let (mut buffer, copy_to_bios, guest_dst) = match subfn {
                    0x02 => {
                        let tbl = seg_offset(dos, regs, regs.es as u16, regs.rdx as u16 as u32) as usize;
                        let mut data = alloc::vec![0; 17];
                        machine.copy_from(tbl, &mut data);
                        (data, true, None)
                    }
                    0x12 => {
                        let tbl = seg_offset(dos, regs, regs.es as u16, regs.rdx as u16 as u32) as usize;
                        let mut data = alloc::vec![0; regs.rcx as u16 as usize * 3];
                        machine.copy_from(tbl, &mut data);
                        (data, true, None)
                    }
                    0x17 => {
                        let tbl = seg_offset(dos, regs, regs.es as u16, regs.rdx as u16 as u32) as usize;
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
                    let tbl = seg_offset(dos, regs, regs.es as u16, regs.rdx as u16 as u32) as usize;
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
                    let tbl = seg_offset(dos, regs, regs.es as u16, regs.rdx as u16 as u32) as usize;
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
                    let tbl = seg_offset(dos, regs, regs.es as u16, regs.rdx as u16 as u32) as usize;
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
        0x4F => super::vbe::vbe(machine, bios_display, dos, regs),
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
fn state_info<A: crate::Arch>(machine: &mut A, dos: &DosState<A>, regs: &mut Regs) {
    if regs.rbx as u16 != 0 {
        return; // BX=0 is the only defined implementation type
    }
    let lin = seg_offset(dos, regs, regs.es as u16, regs.rdi as u16 as u32) as usize;
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
    machine.write::<u32>(lin, dos::video_static_info_addr());
    machine.write::<u8>(lin + 0x04, mode);
    machine.write::<u16>(lin + 0x05, columns);
    machine.write::<u16>(lin + 0x07, regen_len);
    machine.write::<u16>(lin + 0x09, 0); // page 0 starts at the buffer base
    for page in 0..8 {
        let pos_off = core::mem::offset_of!(Bda, cursor_pos) + page * 2;
        let pos: u16 = machine.read(Bda::BASE + pos_off);
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
