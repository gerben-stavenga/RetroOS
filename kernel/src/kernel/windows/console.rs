//! Console presentation and keyboard state used by the Wine host boundary.
use super::{Window, WindowsState};
use alloc::{collections::VecDeque, vec, vec::Vec};

pub(super) struct Console {
    pub cols: u16,
    pub rows: u16,
    cursor_x: u16,
    cursor_y: u16,
    attr: u16,
    cells: Vec<u32>,
    keys: VecDeque<[u32; 6]>,
    modes: [u32; 2],
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
            keys: VecDeque::new(),
            modes: [7, 3],
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
    let cursor = (
        state.console.cursor_x as usize,
        state.console.cursor_y as usize,
    );
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
    let display: Vec<lib::term::Cell> = cells
        .chunks_exact(2)
        .map(|cell| lib::term::Cell {
            character: char::from_u32(cell[0]).unwrap_or('�'),
            attribute: cell[1] as u8,
        })
        .collect();
    crate::term::term().blit_unicode_cells(cols, rows, &display, cursor.0, cursor.1);
}

fn color(index: u8) -> u32 {
    const PALETTE: [u32; 16] = [
        0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa, 0x555555,
        0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
    ];
    PALETTE[(index & 0x0f) as usize]
}

pub(super) fn key(state: &mut WindowsState, event: lib::keyboard::Event, control: u32) {
    if state.console.hwnd == 0 || state.console.keys.len() >= 4096 {
        return;
    }
    let vk = u32::from(super::user_queue::virtual_key(u16::from(event.scan), 0));
    let text = if event.length == 0 {
        &['\0'][..]
    } else {
        event.characters()
    };
    for &ch in text {
        let ch = if ch == '\n' { '\r' } else { ch };
        let mut units = [0; 2];
        for &unit in ch.encode_utf16(&mut units).iter() {
            state.console.keys.push_back([
                u32::from(event.pressed),
                1,
                vk,
                u32::from(event.scan),
                u32::from(unit),
                control | u32::from(event.extended) << 8,
            ]);
        }
    }
}

/// Console primitives; Wine's device structures are translated in RETROOS.DLL.
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 5],
) -> u32 {
    let [op, params, buffer, count, out] = args;
    let p: [u32; 8] = core::array::from_fn(|i| machine.read::<u32>(params as usize + i * 4));
    machine.write::<u32>(out as usize, 0);
    let c = &mut state.console;
    match op {
        0 => {
            machine.write::<u32>(buffer as usize, c.input_cp);
            machine.write::<u32>(buffer as usize + 4, c.output_cp);
        }
        1 => {
            if p[0] & !3 != 0
                || (p[0] & 1 != 0 && super::encoding::page(p[1]).is_none())
                || (p[0] & 2 != 0 && super::encoding::page(p[2]).is_none())
            {
                return 0xc000000d;
            }
            if p[0] & 1 != 0 {
                c.input_cp = p[1];
            }
            if p[0] & 2 != 0 {
                c.output_cp = p[2];
            }
        }
        2 => {
            for (i, v) in [
                u32::from(c.cursor_x),
                u32::from(c.cursor_y),
                u32::from(c.cols),
                u32::from(c.rows),
                u32::from(c.attr),
                c.modes[0],
                c.modes[1],
            ]
            .into_iter()
            .enumerate()
            {
                machine.write::<u32>(buffer as usize + i * 4, v);
            }
        }
        3 => {
            if p[0] > 1 {
                return 0xc000000d;
            }
            c.modes[p[0] as usize] = p[1];
        }
        4 => {
            if p[0] >= u32::from(c.cols) || p[1] >= u32::from(c.rows) {
                return 0xc000000d;
            }
            c.cursor_x = p[0] as u16;
            c.cursor_y = p[1] as u16;
            paint(state);
        }
        5 => {
            if count > 1024 * 1024 {
                return 0xc000000d;
            }
            let text = if p[0] == 0 {
                let units: Vec<u16> = (0..count)
                    .map(|i| machine.read::<u16>((buffer + i * 2) as usize))
                    .collect();
                alloc::string::String::from_utf16_lossy(&units)
            } else {
                let mut bytes = vec![0; count as usize];
                machine.copy_from(buffer as usize, &mut bytes);
                super::encoding::page(c.output_cp)
                    .unwrap()
                    .decode(&bytes, false)
                    .unwrap()
            };
            for ch in text.chars() {
                match ch {
                    '\r' => c.cursor_x = 0,
                    '\n' => {
                        c.cursor_x = 0;
                        c.cursor_y += 1;
                    }
                    '\x08' => c.cursor_x = c.cursor_x.saturating_sub(1),
                    _ => {
                        let at = (usize::from(c.cursor_y) * usize::from(c.cols)
                            + usize::from(c.cursor_x))
                            * 2;
                        c.cells[at] = ch as u32;
                        c.cells[at + 1] = u32::from(c.attr);
                        c.cursor_x += 1;
                        if c.cursor_x == c.cols {
                            c.cursor_x = 0;
                            c.cursor_y += 1;
                        }
                    }
                }
                if c.cursor_y == c.rows {
                    let row = usize::from(c.cols) * 2;
                    c.cells.copy_within(row.., 0);
                    let end = c.cells.len();
                    for cell in c.cells[end - row..].chunks_exact_mut(2) {
                        cell[0] = 32;
                        cell[1] = u32::from(c.attr);
                    }
                    c.cursor_y -= 1;
                }
            }
            machine.write::<u32>(out as usize, count);
            paint(state);
        }
        6 => {
            if p[0].checked_add(p[2]).is_none_or(|x| x > u32::from(c.cols))
                || p[1].checked_add(p[3]).is_none_or(|y| y > u32::from(c.rows))
                || p[2].checked_mul(p[3]) != Some(count)
            {
                return 0xc000000d;
            }
            for i in 0..count {
                let at = (((p[1] + i / p[2]) * u32::from(c.cols) + p[0] + i % p[2]) * 2) as usize;
                machine.write::<u32>(
                    (buffer + i * 4) as usize,
                    c.cells[at] | (c.cells[at + 1] << 16),
                );
            }
            machine.write::<u32>(out as usize, count);
        }
        7 => {
            let item = if p[0] == 0 {
                c.keys.pop_front()
            } else {
                c.keys.front().copied()
            };
            if let Some(item) = item {
                for (i, v) in item.into_iter().enumerate() {
                    machine.write::<u32>(buffer as usize + i * 4, v);
                }
                machine.write::<u32>(out as usize, 1);
            }
        }
        8 => {
            c.keys.clear();
        }
        9 => machine.write::<u32>(out as usize, c.keys.len() as u32),
        _ => return 0xc00000bb,
    }
    0
}
