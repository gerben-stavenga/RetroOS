//! Console presentation and keyboard state used by the Wine host boundary.
use super::{Window, WindowsState};
use alloc::{vec, vec::Vec};

pub(super) struct Console {
    pub cols: u16,
    pub rows: u16,
    cursor_x: u16,
    cursor_y: u16,
    attr: u16,
    cells: Vec<u32>,
    pub(super) input_cp: u32,
    pub(super) keyboard: lib::keyboard::State,
    pub(super) output_cp: u32,
    pub hwnd: u32,
}
impl Console {
    pub(super) fn new() -> Self {
        let mut console = Self {
            cols: 80,
            rows: 25,
            cursor_x: 0,
            cursor_y: 0,
            attr: 0x07,
            cells: Vec::new(),
            keyboard: lib::keyboard::State::new(),
            input_cp: u32::from(lib::codepage::current_codepage().id),
            output_cp: u32::from(lib::codepage::current_codepage().id),
            hwnd: 0,
        };
        console.blank();
        console
    }

    fn blank(&mut self) {
        self.cells.clear();
        self.cells
            .resize(self.cols as usize * self.rows as usize * 2, 0);
        for cell in self.cells.chunks_exact_mut(2) {
            cell[0] = u32::from(b' ');
            cell[1] = u32::from(self.attr);
        }
    }

}

pub(super) fn open_console(state: &mut WindowsState) {
    ensure_window(state);
}

fn ensure_window(state: &mut WindowsState) {
    if state.console.hwnd != 0 {
        return;
    }
    let hwnd = state.next_object;
    state.next_object += 1;
    state.console.hwnd = hwnd;
    let width = state.console.cols as u32 * 8;
    let height = state.console.rows as u32 * 16;
    state.windows.push(Window {
        hwnd,
        parent: 0,
        x: 0,
        y: 0,
        width,
        height,
        visible: true,
        pixels: vec![0; width as usize * height as usize * 4],
    });
    paint(state);
}

fn paint(state: &mut WindowsState) {
    ensure_window(state);
    let hwnd = state.console.hwnd;
    let cols = state.console.cols as usize;
    let rows = state.console.rows as usize;
    let cells = state.console.cells.clone();
    let cursor = (state.console.cursor_x as usize, state.console.cursor_y as usize);
    let Some(window) = state.windows.iter_mut().find(|window| window.hwnd == hwnd) else {
        return;
    };
    for y in 0..rows {
        for x in 0..cols {
            let at = (y * cols + x) * 2;
            let ch = char::from_u32(cells[at]).unwrap_or('\u{fffd}');
            let attr = cells[at + 1] as u8;
            let (fg, bg) = if cursor == (x, y) {
                (color(attr >> 4), color(attr))
            } else {
                (color(attr), color(attr >> 4))
            };
            let glyph = crate::kernel::text::glyph16(ch);
            for (row, &bits) in glyph.iter().enumerate().take(16) {
                for col in 0..8 {
                    let pixel = if bits & (0x80 >> col) != 0 { fg } else { bg };
                    let px = (y * 16 + row) * window.width as usize + x * 8 + col;
                    let dest = px * 4;
                    if dest + 4 <= window.pixels.len() {
                        window.pixels[dest..dest + 4].copy_from_slice(&pixel.to_le_bytes());
                    }
                }
            }
        }
    }
    state.dirty = true;
    let display: Vec<lib::term::Cell> = cells.chunks_exact(2).map(|cell| lib::term::Cell {
        character: char::from_u32(cell[0]).unwrap_or('�'),
        attribute: cell[1] as u8,
    }).collect();
    crate::term::term().blit_unicode_cells(
        cols,
        rows,
        &display,
        cursor.0,
        cursor.1,
    );
}

fn color(index: u8) -> u32 {
    const PALETTE: [u32; 16] = [
        0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa, 0x555555,
        0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
    ];
    PALETTE[(index & 0x0f) as usize]
}
