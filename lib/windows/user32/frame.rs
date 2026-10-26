//! Guest-side non-client layout and drawing. Surface/DC primitives know no
//! Windows styles, menus, or title bars; these routines can back Win16 thunks.
use crate::{menu, paint, state};
const CAPTION: u32 = 0x00c00000;
pub const CAPTION_HEIGHT: i32 = 20;
pub const MENU_HEIGHT: i32 = 19;
pub fn margins(style: u32, ex: u32, has_menu: bool) -> [i32; 4] {
    let b = if style & 0x40000 != 0 {
        4
    } else if style & 0x400000 != 0 {
        3
    } else if style & 0x800000 != 0 {
        1
    } else {
        0
    };
    let edge = if ex & 0x200 != 0 { 2 } else { 0 };
    [
        b + edge,
        b + edge
            + if style & CAPTION == CAPTION {
                CAPTION_HEIGHT
            } else {
                0
            }
            + if has_menu { MENU_HEIGHT } else { 0 },
        b + edge,
        b + edge,
    ]
}
pub fn client(s: &state::State, w: &state::Window) -> [i32; 4] {
    let m = margins(
        w.style,
        w.ex_style,
        s.attached_menus
            .iter()
            .any(|a| a.hwnd == w.hwnd && a.menu != 0),
    );
    [
        m[0].min(w.width),
        m[1].min(w.height),
        (w.width - m[2]).max(m[0].min(w.width)),
        (w.height - m[3]).max(m[1].min(w.height)),
    ]
}
pub fn origin(s: &state::State, hwnd: u32, client_area: bool) -> Option<(i32, i32)> {
    if hwnd == 0 {
        return Some((0, 0));
    }
    let w = s.windows.iter().find(|w| w.hwnd == hwnd)?;
    let r = client(s, w);
    let (mut x, mut y) = (w.x, w.y);
    if client_area {
        x += r[0];
        y += r[1];
    }
    let mut parent = w.parent;
    for _ in 0..s.windows.len() {
        if parent == 0 {
            return Some((x, y));
        }
        let p = s.windows.iter().find(|w| w.hwnd == parent)?;
        let r = client(s, p);
        x += p.x + r[0];
        y += p.y + r[1];
        parent = p.parent;
    }
    None
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AdjustWindowRectEx(
    rect: *mut crate::rect::Rect,
    style: u32,
    menu: u32,
    ex: u32,
) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let m = margins(style, ex, menu != 0);
    let mut r = unsafe { rect.read_unaligned() };
    r.left -= m[0];
    r.top -= m[1];
    r.right += m[2];
    r.bottom += m[3];
    unsafe {
        rect.write_unaligned(r);
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AdjustWindowRect(
    rect: *mut crate::rect::Rect,
    style: u32,
    menu: u32,
) -> i32 {
    unsafe { AdjustWindowRectEx(rect, style, menu, 0) }
}
unsafe extern "system" {
    fn CreateCompatibleDC(dc: u32) -> u32;
    fn CreateCompatibleBitmap(dc: u32, w: i32, h: i32) -> u32;
    fn SelectObject(dc: u32, object: u32) -> u32;
    fn DeleteDC(dc: u32) -> i32;
    fn CreateRectRgn(l: i32, t: i32, r: i32, b: i32) -> u32;
    fn CombineRgn(dst: u32, a: u32, b: u32, mode: u32) -> i32;
    fn SelectClipRgn(dc: u32, r: u32) -> i32;
    fn BitBlt(
        dst: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        src: u32,
        sx: i32,
        sy: i32,
        rop: u32,
    ) -> i32;
    fn CreateSolidBrush(color: u32) -> u32;
    fn DeleteObject(handle: u32) -> i32;
    fn FillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32;
    fn SetTextColor(dc: u32, color: u32) -> u32;
    fn SetBkMode(dc: u32, mode: u32) -> i32;
    fn TextOutW(dc: u32, x: i32, y: i32, text: *const u16, len: i32) -> i32;
}
pub fn fill(dc: u32, r: [i32; 4], color: u32) {
    if r[0] >= r[2] || r[1] >= r[3] {
        return;
    }
    unsafe {
        let b = CreateSolidBrush(color);
        FillRect(dc, &r, b);
        DeleteObject(b);
    }
}
pub fn label(dc: u32, x: i32, y: i32, value: &[u16], color: u32) {
    unsafe {
        let old = SetTextColor(dc, color);
        let mode = SetBkMode(dc, 1);
        TextOutW(dc, x, y, value.as_ptr(), value.len() as i32);
        SetBkMode(dc, mode as u32);
        SetTextColor(dc, old);
    }
}
pub fn bevel(dc: u32, r: [i32; 4]) {
    fill(dc, r, 0xc0c0c0);
    fill(dc, [r[0], r[1], r[2], r[1] + 1], 0xffffff);
    fill(dc, [r[0], r[1], r[0] + 1, r[3]], 0xffffff);
    fill(dc, [r[0], r[3] - 1, r[2], r[3]], 0x404040);
    fill(dc, [r[2] - 1, r[1], r[2], r[3]], 0x404040);
}
pub fn paint(h: u32) {
    let info = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == h && w.style & 0x10000000 != 0)
            .map(|w| (w.width, w.height, w.style, w.title.clone(), client(s, w)))
    });
    let Some((width, height, style, title, r)) = info else {
        return;
    };
    if r == [0, 0, width, height] {
        return;
    }
    let target = unsafe { paint::GetWindowDC(h) };
    if target == 0 {
        return;
    }
    // GDI calls can yield between primitives. Compose decorations into a
    // private bitmap, then copy the completed frame/menu in one drawing call.
    let dc = unsafe { CreateCompatibleDC(target) };
    let bitmap = unsafe { CreateCompatibleBitmap(target, width, height) };
    if dc == 0 || bitmap == 0 {
        unsafe {
            if dc != 0 {
                DeleteDC(dc);
            }
            if bitmap != 0 {
                DeleteObject(bitmap);
            }
        }
        paint::ReleaseDC(h, target);
        return;
    }
    let previous = unsafe { SelectObject(dc, bitmap) };
    for area in [
        [0, 0, width, r[1]],
        [0, r[1], r[0], height],
        [r[2], r[1], width, height],
        [r[0], r[3], r[2], height],
    ] {
        fill(dc, area, 0xc0c0c0);
    }
    for inset in 0..r[0].min(3) {
        let c = if inset == 0 { 0x808080 } else { 0xffffff };
        fill(dc, [inset, inset, width - inset, inset + 1], c);
        fill(dc, [inset, inset, inset + 1, height - inset], c);
        fill(
            dc,
            [width - inset - 1, inset, width - inset, height - inset],
            0x404040,
        );
        fill(
            dc,
            [inset, height - inset - 1, width - inset, height - inset],
            0x404040,
        );
    }
    if style & CAPTION == CAPTION {
        let b = margins(style, 0, false)[0];
        fill(dc, [b, b, width - b, b + CAPTION_HEIGHT], 0x800000);
        let limit = ((width - 2 * b - 28).max(0) / 8) as usize;
        label(dc, b + 3, b + 2, &title[..title.len().min(limit)], 0xffffff);
        if style & 0x80000 != 0 {
            let x = width - b - 18;
            bevel(dc, [x, b + 2, x + 16, b + 18]);
            label(dc, x + 4, b + 2, &[b'x' as u16], 0);
        }
    }
    menu::draw(h, dc);
    // Preserve the application's client pixels, except where a popup covers
    // them. The screen sees only the final copy, never the clearing passes.
    unsafe {
        let region = CreateRectRgn(0, 0, width, height);
        let client = CreateRectRgn(r[0], r[1], r[2], r[3]);
        if region != 0 && client != 0 {
            CombineRgn(region, region, client, 4);
            if let Some(p) = menu::popup_rect(h) {
                let popup = CreateRectRgn(p[0], p[1], p[2], p[3]);
                if popup != 0 {
                    CombineRgn(region, region, popup, 2);
                    DeleteObject(popup);
                }
            }
            SelectClipRgn(target, region);
            BitBlt(target, 0, 0, width, height, dc, 0, 0, 0x00cc0020);
            SelectClipRgn(target, 0);
        }
        if region != 0 {
            DeleteObject(region);
        }
        if client != 0 {
            DeleteObject(client);
        }
        SelectObject(dc, previous);
        DeleteDC(dc);
        DeleteObject(bitmap);
    }
    paint::ReleaseDC(h, target);
}
pub fn hit(s: &state::State, h: u32, x: i32, y: i32) -> u32 {
    let Some(w) = s.windows.iter().find(|w| w.hwnd == h) else {
        return 0;
    };
    if x < 0 || y < 0 || x >= w.width || y >= w.height {
        return 0;
    }
    let r = client(s, w);
    let b = margins(w.style, 0, false)[0];
    if w.style & CAPTION == CAPTION && y >= b && y < b + CAPTION_HEIGHT {
        if w.style & 0x80000 != 0 && x >= w.width - b - 18 {
            return 20;
        }
        return 2;
    }
    if s.attached_menus.iter().any(|a| a.hwnd == h && a.menu != 0)
        && y >= r[1] - MENU_HEIGHT
        && y < r[1]
    {
        return 5;
    }
    if x >= r[0] && x < r[2] && y >= r[1] && y < r[3] {
        1
    } else {
        18
    }
}
/// Native input is surface-relative. Translate once into client or screen
/// coordinates before queueing a Windows message; posted messages bypass this.
pub fn input(s: &mut state::State, m: &mut crate::Message) {
    if !(0x200..=0x209).contains(&m.message) {
        return;
    }
    let Some((ox, oy)) = origin(s, m.hwnd, false) else {
        return;
    };
    let (mut x, mut y) = (
        (m.lparam as u16 as i16) as i32,
        ((m.lparam >> 16) as u16 as i16) as i32,
    );
    let screen = (x + ox, y + oy);
    s.cursor = [screen.0, screen.1];
    let capture = s.inputs.iter().find(|i| i.capture != 0).map(|i| i.capture);
    if let Some(h) = capture {
        m.hwnd = h;
        let Some(o) = origin(s, h, true) else {
            return;
        };
        x = screen.0 - o.0;
        y = screen.1 - o.1;
    } else {
        // Child positions are relative to their parent's client origin.
        loop {
            let Some(w) = s.windows.iter().find(|w| w.hwnd == m.hwnd) else {
                return;
            };
            let r = client(s, w);
            let child = s.windows.iter().find(|w| {
                w.parent == m.hwnd
                    && w.style & 0x18000000 == 0x10000000
                    && x - r[0] >= w.x
                    && y - r[1] >= w.y
                    && x - r[0] < w.x + w.width
                    && y - r[1] < w.y + w.height
            });
            let Some(c) = child else {
                break;
            };
            x -= r[0] + c.x;
            y -= r[1] + c.y;
            m.hwnd = c.hwnd;
        }
        let mut ht = hit(s, m.hwnd, x, y);
        if s.menu_popup.as_ref().is_some_and(|p| p.hwnd == m.hwnd) {
            ht = 5;
        }
        if ht != 1 {
            m.message -= 0x160;
            m.wparam = ht;
            m.lparam = pack(screen.0, screen.1);
            return;
        }
        let Some(w) = s.windows.iter().find(|w| w.hwnd == m.hwnd) else {
            return;
        };
        let r = client(s, w);
        x -= r[0];
        y -= r[1];
    }
    m.lparam = pack(x, y);
}
pub fn pack(x: i32, y: i32) -> u32 {
    (x as u32 & 0xffff) | ((y as u32 & 0xffff) << 16)
}
pub fn local(h: u32, l: u32) -> (i32, i32) {
    let o = state::with(|s| origin(s, h, false)).unwrap_or((0, 0));
    (
        (l as u16 as i16) as i32 - o.0,
        ((l >> 16) as u16 as i16) as i32 - o.1,
    )
}
pub fn message(h: u32, m: u32, w: u32, l: u32) -> Option<i32> {
    match m {
        0x85 | 0x86 => {
            paint(h);
            Some(1)
        }
        0x84 => {
            let (x, y) = local(h, l);
            Some(state::with(|s| hit(s, h, x, y)) as i32)
        }
        0xa0 | 0xa1 | 0xa2 => {
            let (x, y) = local(h, l);
            if w == 5 {
                menu::pointer(h, m, x, y);
            } else if w == 20 && m == 0xa1 {
                unsafe {
                    crate::SendMessageW(h, 0x112, 0xf060, 0);
                }
            }
            Some(0)
        }
        0x112 if w & 0xfff0 == 0xf060 => {
            unsafe {
                crate::SendMessageW(h, 0x10, 0, 0);
            }
            Some(0)
        }
        _ => None,
    }
}
