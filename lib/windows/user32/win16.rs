//! Win16 ABI adapters for the ordinary guest USER implementation.
//! Segment and structure translation happens here, never in kernel callbacks.
use crate::{Message, class, input, keyboard, menu, message, paint, rect, state, window};

unsafe extern "system" {
    fn Retro16Call(proc: u32, args: *const u8, bytes: u32, reserve: u32) -> u32;
    fn Rectangle(dc: u32, l: i32, t: i32, r: i32, b: i32) -> i32;
    fn GetSystemMetrics(index: u32) -> u32;
    fn GetPixel(dc: u32, x: i32, y: i32) -> u32;
    fn SetPixel(dc: u32, x: i32, y: i32, color: u32) -> u32;
    fn SetBkColor(dc: u32, color: u32) -> u32;
    fn SetTextColor(dc: u32, color: u32) -> u32;
    fn SetBkMode(dc: u32, mode: u32) -> i32;
    fn SetMapMode(dc: u32, mode: i32) -> i32;
    fn GetMapMode(dc: u32) -> i32;
    fn SetROP2(dc: u32, mode: i32) -> i32;
    fn MoveToEx(dc: u32, x: i32, y: i32, old: *mut [i32; 2]) -> i32;
    fn LineTo(dc: u32, x: i32, y: i32) -> i32;
    fn TextOutA(dc: u32, x: i32, y: i32, text: u32, count: i32) -> i32;
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
    fn SelectClipRgn(dc: u32, region: u32) -> i32;
    fn SelectObject(dc: u32, object: u32) -> u32;
    fn CreateCompatibleBitmap(dc: u32, w: i32, h: i32) -> u32;
    fn CreateCompatibleDC(dc: u32) -> u32;
    fn CreatePen(style: u32, width: i32, color: u32) -> u32;
    fn CreateSolidBrush(color: u32) -> u32;
    fn DeleteDC(dc: u32) -> i32;
    fn DeleteObject(object: u32) -> i32;
    fn GetStockObject(id: u32) -> u32;
    fn FillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32;
}
unsafe extern "C" {
    pub(super) static Retro16Config: [u32; 11];
}
const PROC: u32 = 0xfffd_0000;

fn decode(h: u32) -> u32 {
    if h < 0x8000 {
        h
    } else {
        state::with(|s| {
            s.win16_handles
                .get((h - 0x8000) as usize)
                .copied()
                .unwrap_or(0)
        })
    }
}
fn encode(h: u32) -> u32 {
    if h < 0x8000 {
        return h;
    }
    state::with(|s| {
        if let Some(i) = s.win16_handles.iter().position(|&v| v == h) {
            return 0x8000 + i as u32;
        }
        if s.win16_handles.len() >= 0x7fff {
            return 0;
        }
        s.win16_handles.push(h);
        0x7fff + s.win16_handles.len() as u32
    })
}
const NATIVE_PROC: u32 = 0xfffc_0000;
fn native_procedure(p: u32) -> Option<u32> {
    if p & 0xffff_0000 != NATIVE_PROC {
        return None;
    }
    state::with(|s| s.win16_native_procs.get((p & 0xffff) as usize).copied())
}
fn procedure(p: u32) -> u32 {
    if let Some(native) = native_procedure(p) {
        return native;
    }
    if p == 0 {
        return 0;
    }
    state::with(|s| {
        if let Some(i) = s.win16_procs.iter().position(|&v| v == p) {
            return PROC + i as u32;
        }
        if s.win16_procs.len() >= 0xffff {
            return 0;
        }
        let id = PROC + s.win16_procs.len() as u32;
        s.win16_procs.push(p);
        id
    })
}
fn original(p: u32) -> u32 {
    if p == 0 {
        return 0;
    }
    if p & 0xffff_0000 != PROC {
        return state::with(|s| {
            if let Some(i) = s.win16_native_procs.iter().position(|&v| v == p) {
                return NATIVE_PROC + i as u32;
            }
            if s.win16_native_procs.len() >= 0x10000 {
                return 0;
            }
            let id = NATIVE_PROC + s.win16_native_procs.len() as u32;
            s.win16_native_procs.push(p);
            id
        });
    }
    state::with(|s| {
        s.win16_procs
            .get((p & 0xffff) as usize)
            .copied()
            .unwrap_or(0)
    })
}
unsafe fn segment(sel: u32) -> Option<(u32, u32)> {
    unsafe {
        if sel & 7 != 7 || sel >> 3 >= Retro16Config[6] {
            return None;
        }
        let p = (Retro16Config[4] as *const u32).add((sel as usize >> 3) * 2);
        Some((p.read(), p.add(1).read()))
    }
}
unsafe fn pointer(p: u32, bytes: usize) -> Option<u32> {
    unsafe {
        let (base, limit) = segment(p >> 16)?;
        let offset = p & 0xffff;
        if bytes > 0x10000 || offset.checked_add(bytes.saturating_sub(1) as u32)? > limit {
            return None;
        }
        base.checked_add(offset)
    }
}
unsafe fn string(p: u32) -> Option<u32> {
    if p <= 0xffff {
        return Some(p);
    }
    unsafe {
        let (base, limit) = segment(p >> 16)?;
        let offset = p & 0xffff;
        if offset > limit {
            return None;
        }
        let bytes = core::slice::from_raw_parts(
            (base + offset) as *const u8,
            (limit - offset + 1) as usize,
        );
        bytes.iter().position(|&b| b == 0)?;
        Some(base + offset)
    }
}
unsafe fn word(p: u32, at: usize) -> u32 {
    unsafe { ((p as *const u8).add(at) as *const u16).read_unaligned() as u32 }
}
unsafe fn long(p: u32, at: usize) -> u32 {
    unsafe { ((p as *const u8).add(at) as *const u32).read_unaligned() }
}
unsafe fn putw(p: u32, at: usize, v: u32) {
    unsafe {
        ((p as *mut u8).add(at) as *mut u16).write_unaligned(v as u16);
    }
}
unsafe fn putl(p: u32, at: usize, v: u32) {
    unsafe {
        ((p as *mut u8).add(at) as *mut u32).write_unaligned(v);
    }
}
unsafe fn rectangle(p: u32) -> Option<rect::Rect> {
    unsafe {
        let p = pointer(p, 8)?;
        Some(rect::Rect {
            left: word(p, 0) as i16 as i32,
            top: word(p, 2) as i16 as i32,
            right: word(p, 4) as i16 as i32,
            bottom: word(p, 6) as i16 as i32,
        })
    }
}
unsafe fn write_rect(p: u32, r: &rect::Rect) -> Option<()> {
    unsafe {
        let p = pointer(p, 8)?;
        for (i, v) in [r.left, r.top, r.right, r.bottom].iter().enumerate() {
            putw(p, 2 * i, *v as u32);
        }
        Some(())
    }
}
fn to32(m: u32, w: u32, l: u32) -> (u32, u32) {
    match m {
        0x19 => (decode(w), decode(l & 0xffff)),
        0x111 => (w | (l & 0xffff_0000), decode(l & 0xffff)),
        0x114 | 0x115 => (w | (l << 16), decode(l >> 16)),
        0x14 | 7 | 8 => (decode(w), l),
        6 => (w | (l & 0xffff_0000), decode(l & 0xffff)),
        _ => (w, l),
    }
}
fn to16(m: u32, w: u32, l: u32) -> (u32, u32) {
    match m {
        0x132..=0x138 => (encode(w), encode(l) | ((m - 0x132) << 16)),
        0x111 => (w & 0xffff, encode(l) | (w & 0xffff_0000)),
        0x114 | 0x115 => (w & 0xffff, (w >> 16) | (encode(l) << 16)),
        0x14 | 7 | 8 => (encode(w), l),
        6 => (w & 0xffff, encode(l) | (w & 0xffff_0000)),
        _ => (w, l),
    }
}
unsafe fn read_message(p: u32) -> Option<Message> {
    unsafe {
        let p = pointer(p, 18)?;
        let m = word(p, 2);
        let (w, l) = to32(m, word(p, 4), long(p, 6));
        Some(Message {
            hwnd: decode(word(p, 0)),
            message: m,
            wparam: w,
            lparam: l,
            time: long(p, 10),
            x: word(p, 14) as i16 as i32,
            y: word(p, 16) as i16 as i32,
        })
    }
}
unsafe fn write_message(p: u32, m: &Message) -> Option<()> {
    unsafe {
        let p = pointer(p, 18)?;
        let (w, l) = to16(m.message, m.wparam, m.lparam);
        putw(p, 0, encode(m.hwnd));
        putw(p, 2, m.message);
        putw(p, 4, w);
        putl(p, 6, l);
        putl(p, 10, m.time);
        putw(p, 14, m.x as u32);
        putw(p, 16, m.y as u32);
        Some(())
    }
}

/// Intercept only explicitly registered NE procedures, leaving PE procedures
/// and built-in controls on their ordinary Rust calling convention.
pub unsafe fn invoke(
    address: u32,
    hwnd: u32,
    msg: u32,
    wp: u32,
    lp: u32,
    wide: bool,
) -> Option<i32> {
    if address & 0xffff_0000 != PROC {
        return None;
    }
    unsafe { Some(callback(original(address), hwnd, msg, wp, lp, wide).unwrap_or(0) as i32) }
}
unsafe fn callback(proc: u32, hwnd: u32, msg: u32, wp: u32, lp: u32, wide: bool) -> Option<u32> {
    unsafe {
        let frame = Retro16Config[3] as *const u32;
        if frame.is_null() {
            return None;
        }
        let saved = frame.add(1).read();
        let ss = frame.add(2).read();
        let (base, _) = segment(ss)?;
        let reserve: u32 = if lp != 0 && matches!(msg, 1 | 0x81 | 0xc | 0xd | 0x46 | 0x47) {
            1024
        } else {
            0
        };
        if saved.checked_sub(base)? < reserve + 256 {
            return None;
        }
        let scratch = saved - reserve;
        let far = (ss << 16) | (scratch - base);
        let (w, mut l) = to16(msg, wp, lp);
        if matches!(msg, 1 | 0x81) && lp != 0 {
            let cs = &*(lp as *const crate::CreateStruct);
            putl(scratch, 0, cs.parameter);
            putw(scratch, 4, cs.instance);
            putw(scratch, 6, encode(cs.menu));
            putw(scratch, 8, encode(cs.parent));
            for (i, v) in [cs.height, cs.width, cs.y, cs.x].iter().enumerate() {
                putw(scratch, 10 + i * 2, *v as u32);
            }
            putl(scratch, 18, cs.style);
            putl(scratch, 30, cs.ex_style);
            let mut cursor = 40usize;
            for (offset, p) in [(22, cs.title), (26, cs.class)] {
                if p <= 0xffff {
                    putl(scratch, offset, p);
                    continue;
                }
                let mut text = crate::text::ansi(&crate::text::read(p, wide));
                text.push(0);
                if cursor + text.len() > reserve as usize {
                    return None;
                }
                core::ptr::copy_nonoverlapping(
                    text.as_ptr(),
                    (scratch as *mut u8).add(cursor),
                    text.len(),
                );
                putl(scratch, offset, far + cursor as u32);
                cursor += text.len();
            }
            l = far;
        } else if matches!(msg, 0xc | 0xd) && lp != 0 {
            if msg == 0xc {
                let mut text = crate::text::ansi(&crate::text::read(lp, wide));
                text.push(0);
                if text.len() > reserve as usize {
                    return None;
                }
                core::ptr::copy_nonoverlapping(text.as_ptr(), scratch as *mut u8, text.len());
            } else {
                core::ptr::write_bytes(scratch as *mut u8, 0, reserve as usize);
            }
            l = far;
        } else if matches!(msg, 0x46 | 0x47) && lp != 0 {
            let p = lp as *const u32;
            putw(scratch, 0, encode(p.read()));
            let after = p.add(1).read();
            putw(
                scratch,
                2,
                if after >= 0xffff_fffe {
                    after
                } else {
                    encode(after)
                },
            );
            for i in 2..7 {
                putw(scratch, i * 2, p.add(i).read());
            }
            l = far;
        }
        let mut args = [0u8; 10];
        args[0..4].copy_from_slice(&l.to_le_bytes());
        args[4..6].copy_from_slice(&(w as u16).to_le_bytes());
        let message16 = if (0x132..=0x138).contains(&msg) {
            0x19
        } else {
            msg
        };
        args[6..8].copy_from_slice(&(message16 as u16).to_le_bytes());
        args[8..10].copy_from_slice(&(encode(hwnd) as u16).to_le_bytes());
        if msg == 0xd {
            args[4..6].copy_from_slice(&(wp.min(reserve) as u16).to_le_bytes());
        }
        let result = Retro16Call(proc, args.as_ptr(), 10, reserve);
        if msg == 0xd && lp != 0 {
            let text = crate::text::read(scratch, false);
            return Some(crate::text::write(lp, wp as i32, &text, wide));
        }
        if msg == 0x46 && lp != 0 {
            let p = lp as *mut u32;
            p.write(decode(word(scratch, 0)));
            let after = word(scratch, 2);
            p.add(1).write(if after >= 0xfffe {
                after as i16 as i32 as u32
            } else {
                decode(after)
            });
            for i in 2..6 {
                p.add(i).write(word(scratch, i * 2) as i16 as i32 as u32);
            }
            p.add(6).write(word(scratch, 12));
        }
        Some(if (0x132..=0x138).contains(&msg) {
            decode(result & 0xffff)
        } else {
            result
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Retro16Dispatch(
    ordinal: u32,
    args: *const u8,
    frame: *const u32,
) -> u32 {
    unsafe { dispatch(ordinal, args as u32, frame).unwrap_or(0) }
}
unsafe fn dispatch(o: u32, a: u32, _frame: *const u32) -> Option<u32> {
    unsafe {
        let w = |at| word(a, at);
        let d = |at| long(a, at);
        let i = |at| word(a, at) as i16 as i32;
        let h = |at| decode(word(a, at));
        Some(match o {
            1 => crate::messagebox::MessageBoxA(h(10), string(d(6))?, string(d(2))?, w(0)) as u32,
            5 => 1,
            6 => {
                message::PostQuitMessage(w(0));
                0
            }
            10 => message::SetTimer(h(8), w(6), w(4), procedure(d(0))),
            12 => message::KillTimer(h(2), w(0)) as u32,
            15 => crate::runtime::GetTickCount(),
            18 => encode(input::SetCapture(h(0))),
            19 => input::ReleaseCapture() as u32,
            22 => encode(input::SetFocus(h(0))),
            23 => encode(input::GetFocus()),
            32 | 33 => {
                let mut r = rect::Rect {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                };
                let result = if o == 32 {
                    window::GetWindowRect(h(4), &mut r)
                } else {
                    window::GetClientRect(h(4), &mut r)
                };
                write_rect(d(0), &r)?;
                result as u32
            }
            34 => window::EnableWindow(h(2), i(0)) as u32,
            35 => window::IsWindowEnabled(h(0)) as u32,
            36 => window::GetWindowTextA(h(6), pointer(d(2), w(0) as usize)?, i(0)) as u32,
            37 => window::SetWindowTextA(h(4), string(d(0))?) as u32,
            39 => {
                let out = pointer(d(0), 32)?;
                let mut ps = [0u32; 16];
                let dc = paint::BeginPaint(h(4), ps.as_mut_ptr() as u32);
                core::ptr::write_bytes(out as *mut u8, 0, 32);
                for j in 0..8 {
                    putw(out, j * 2, if j == 0 { encode(ps[j]) } else { ps[j] });
                }
                encode(dc)
            }
            40 => {
                let p = pointer(d(0), 32)?;
                let mut ps = [0u32; 16];
                for j in 0..8 {
                    ps[j] = word(p, j * 2);
                }
                ps[0] = decode(ps[0]);
                paint::EndPaint(h(4), ps.as_ptr() as u32) as u32
            }
            41 => {
                let size = |v: i32| if v == i16::MIN as i32 { i32::MIN } else { v };
                encode(crate::CreateWindowExA(
                    0,
                    string(d(26))?,
                    string(d(22))?,
                    d(18),
                    size(i(16)),
                    size(i(14)),
                    size(i(12)),
                    size(i(10)),
                    h(8),
                    h(6),
                    w(4),
                    d(0),
                ))
            }
            42 => window::ShowWindow(h(2), w(0)) as u32,
            46 => encode(window::GetParent(h(0))),
            47 => window::IsWindow(h(0)) as u32,
            53 => window::DestroyWindow(h(0)) as u32,
            56 => window::MoveWindow(h(10), i(8), i(6), i(4), i(2), i(0)) as u32,
            57 => {
                let p = pointer(d(0), 26)?;
                let wc = [
                    word(p, 0),
                    procedure(long(p, 2)),
                    word(p, 6),
                    word(p, 8),
                    word(p, 10),
                    decode(word(p, 12)),
                    decode(word(p, 14)),
                    decode(word(p, 16)),
                    string(long(p, 18))?,
                    string(long(p, 22))?,
                ];
                class::RegisterClassA(wc.as_ptr() as u32)
            }
            60 => encode(input::GetActiveWindow()),
            62 => crate::scrollbar::SetScrollPos(h(6), i(4), i(2), i(0)) as u32,
            64 => crate::scrollbar::SetScrollRange(h(8), i(6), i(4), i(2), i(0)) as u32,
            66 => encode(paint::GetDC(h(0))),
            68 => paint::ReleaseDC(h(2), h(0)) as u32,
            72 => {
                let r = rect::Rect {
                    left: i(6),
                    top: i(4),
                    right: i(2),
                    bottom: i(0),
                };
                write_rect(d(8), &r)?;
                1
            }
            74 => {
                let r = rectangle(d(0))?;
                write_rect(d(4), &r)?;
                1
            }
            76 => {
                let r = rectangle(d(4))?;
                rect::PtInRect(&r, rect::Point { x: i(0), y: i(2) }) as u32
            }
            77 | 78 => {
                let mut r = rectangle(d(4))?;
                if o == 77 {
                    rect::OffsetRect(&mut r, i(2), i(0));
                } else {
                    rect::InflateRect(&mut r, i(2), i(0));
                }
                write_rect(d(4), &r)?;
                1
            }
            79 => {
                let x = rectangle(d(4))?;
                let y = rectangle(d(0))?;
                let mut out = rect::Rect {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                };
                let result = rect::IntersectRect(&mut out, &x, &y);
                write_rect(d(8), &out)?;
                result as u32
            }
            81 => {
                let r = rectangle(d(2))?;
                FillRect(h(6), &[r.left, r.top, r.right, r.bottom], h(0)) as u32
            }
            85 => {
                let r = rectangle(d(2))?;
                let mut r32 = [r.left, r.top, r.right, r.bottom];
                let count = i(6);
                let text = if count < 0 {
                    string(d(8))?
                } else {
                    pointer(d(8), count as usize)?
                };
                let result = crate::drawing::DrawTextA(h(12), text, count, &mut r32, w(0));
                write_rect(
                    d(2),
                    &rect::Rect {
                        left: r32[0],
                        top: r32[1],
                        right: r32[2],
                        bottom: r32[3],
                    },
                )?;
                result as u32
            }
            87 => crate::dialog::DialogBoxParamA(w(10), string(d(6))?, h(4), procedure(d(0)), 0)
                as u32,
            88 => crate::dialog::EndDialog(h(2), i(0)) as u32,
            91 => encode(window::GetDlgItem(h(2), i(0))),
            92 => crate::dialog::SetDlgItemTextA(h(6), w(4), string(d(0))?) as u32,
            93 => crate::dialog::GetDlgItemTextA(h(8), w(6), pointer(d(2), w(0) as usize)?, w(0))
                as u32,
            94 => crate::dialog::SetDlgItemInt(
                h(6),
                w(4),
                if w(0) != 0 { i(2) as u32 } else { w(2) },
                i(0),
            ) as u32,
            95 => {
                let mut valid = 0;
                let n = crate::dialog::GetDlgItemInt(h(8), w(6), &mut valid, i(0));
                if w(0) != 0 {
                    if !(i16::MIN as i32..=i16::MAX as i32).contains(&(n as i32)) {
                        valid = 0;
                    }
                } else if n > u16::MAX as u32 {
                    valid = 0;
                }
                if d(2) != 0 {
                    putw(pointer(d(2), 2)?, 0, valid as u32);
                }
                if valid != 0 { n } else { 0 }
            }
            96 => {
                for id in w(4)..=w(2) {
                    let child = window::GetDlgItem(h(6), id as i32);
                    crate::SendMessageA(child, 0xf1, u32::from(id == w(0)), 0);
                }
                1
            }
            97 => crate::dialog::SendDlgItemMessageA(h(4), w(2), 0xf1, w(0), 0) as u32,
            98 => crate::dialog::SendDlgItemMessageA(h(2), w(0), 0xf0, 0, 0) as u32,
            101 => {
                let child = window::GetDlgItem(h(10), w(8) as i32);
                translated_message(child, w(6), w(4), d(0), |m, wp, lp| {
                    crate::SendMessageA(child, m, wp, lp) as u32
                })?
            }
            107 | 111 | 110 => {
                let m = w(6);
                if o == 110 {
                    let (wp, lp) = to32(m, w(4), d(0));
                    let lp = if matches!(m, 0xc | 0xd) {
                        pointer(lp, if m == 0xd { wp as usize } else { 1 })?
                    } else {
                        lp
                    };
                    message::PostMessageA(h(8), m, wp, lp) as u32
                } else {
                    translated_message(h(8), m, w(4), d(0), |m, wp, lp| {
                        if o == 107 {
                            window::DefWindowProcA(h(8), m, wp, lp) as u32
                        } else {
                            crate::SendMessageA(h(8), m, wp, lp) as u32
                        }
                    })?
                }
            }
            108 | 109 => {
                let off = if o == 109 { 2 } else { 0 };
                let mut m = Message::default();
                let result = if o == 108 {
                    message::GetMessageA(&mut m, h(4), w(2), w(0))
                } else {
                    message::PeekMessageA(&mut m, h(6), w(4), w(2), w(0))
                };
                if result != 0 || o == 108 {
                    write_message(d(6 + off), &m)?;
                }
                result as u32
            }
            113 => keyboard::TranslateMessage(&read_message(d(0))?) as u32,
            114 => crate::DispatchMessageA(&read_message(d(0))?) as u32,
            122 => {
                // Native control procedures are exposed as opaque Win16
                // tokens; translate at that boundary, never far-call them.
                let proc = d(10);
                if let Some(native) = native_procedure(proc) {
                    return translated_message(h(8), w(6), w(4), d(0), |m, wp, lp| {
                        crate::call_procedure(native, h(8), m, wp, lp, false) as u32
                    });
                }
                // NE-to-NE forwarding preserves segmented LPARAM buffers.
                pointer(proc, 1)?;
                let active = Retro16Config[3] as *const u32;
                let saved = active.add(1).read();
                let (base, _) = segment(active.add(2).read())?;
                if saved.checked_sub(base)? < 256 {
                    return None;
                }
                Retro16Call(proc, a as *const u8, 10, 0)
            }
            124 => paint::UpdateWindow(h(0)) as u32,
            125 | 127 => {
                let off = if o == 125 { 2 } else { 0 };
                let r = if d(off) != 0 {
                    Some(rectangle(d(off))?)
                } else {
                    None
                };
                let p = r.as_ref().map_or(0, |r| r as *const _ as u32);
                if o == 125 {
                    paint::InvalidateRect(h(6), p, w(0)) as u32
                } else {
                    paint::ValidateRect(h(4), p) as u32
                }
            }
            133 => {
                let value = window::word(h(2), i(0), None);
                if matches!(i(0), -6 | -8) {
                    encode(value)
                } else {
                    value
                }
            }
            134 => {
                let value = if matches!(i(2), -6 | -8) { h(0) } else { w(0) };
                let old = window::word(h(4), i(2), Some(value));
                if matches!(i(2), -6 | -8) {
                    encode(old)
                } else {
                    old
                }
            }
            135 => {
                let p = window::GetWindowLongA(h(2), i(0));
                if i(0) == -4 { original(p) } else { p }
            }
            136 => {
                let index = i(4);
                let value = if index == -4 { procedure(d(0)) } else { d(0) };
                let old = window::SetWindowLongA(h(6), index, value);
                if index == -4 { original(old) } else { old }
            }
            150 => encode(menu::LoadMenuA(w(4), string(d(0))?)),
            151 => encode(menu::CreateMenu()),
            152 => menu::DestroyMenu(h(0)) as u32,
            154 => menu::CheckMenuItem(h(4), w(2), w(0)),
            155 => menu::EnableMenuItem(h(4), w(2), w(0)),
            156 => encode(menu::GetSystemMenu(h(2), w(0))),
            157 => encode(menu::GetMenu(h(0))),
            158 => menu::SetMenu(h(2), h(0)) as u32,
            159 => encode(menu::GetSubMenu(h(2), i(0))),
            160 => menu::DrawMenuBar(h(0)) as u32,
            175 => encode(crate::resource::LoadBitmapA(w(4), string(d(0))?)),
            179 => GetSystemMetrics(w(0)),
            236 => encode(input::GetCapture()),
            242 => {
                let p = d(10);
                let (_, limit) = segment(p >> 16)?;
                let at = pointer(p, 1)?;
                let bytes = core::slice::from_raw_parts(
                    at as *const u8,
                    (limit - (p & 0xffff) + 1) as usize,
                );
                let converted = crate::win16_resource::dialog(bytes)?;
                encode(crate::dialog::CreateDialogIndirectParamA(
                    w(14),
                    converted.as_ptr() as u32,
                    h(8),
                    procedure(d(4)),
                    d(0),
                ))
            }
            244 => rect::EqualRect(&rectangle(d(4))?, &rectangle(d(0))?) as u32,
            277 => window::GetDlgCtrlID(h(0)) as u32,
            410 | 411 | 414 => {
                let f = w(6);
                let id = if f & 0x10 != 0 { h(4) } else { w(4) };
                let text = string(d(0))?;
                if o == 411 {
                    menu::AppendMenuA(h(8), f, id, text) as u32
                } else if o == 410 {
                    menu::InsertMenuA(h(10), w(8), f, id, text) as u32
                } else {
                    menu::ModifyMenuA(h(10), w(8), f, id, text) as u32
                }
            }
            412 => menu::RemoveMenu(h(4), w(2), w(0)) as u32,
            413 => menu::DeleteMenu(h(4), w(2), w(0)) as u32,
            1001 => SetBkColor(h(4), d(0)),
            1002 => SetBkMode(h(2), w(0)) as u32,
            1003 => SetMapMode(h(2), i(0)) as u32,
            1004 => SetROP2(h(2), i(0)) as u32,
            1009 => SetTextColor(h(4), d(0)),
            1019 => LineTo(h(4), i(2), i(0)) as u32,
            1020 => {
                let mut old = [0; 2];
                MoveToEx(h(4), i(2), i(0), &mut old);
                old[0] as u16 as u32 | ((old[1] as u16 as u32) << 16)
            }
            1027 => Rectangle(h(8), i(6), i(4), i(2), i(0)) as u32,
            1031 => SetPixel(h(8), i(6), i(4), d(0)),
            1033 => TextOutA(h(10), i(8), i(6), pointer(d(2), w(0) as usize)?, i(0)) as u32,
            1034 => BitBlt(h(18), i(16), i(14), i(12), i(10), h(8), i(6), i(4), d(0)) as u32,
            1044 => SelectClipRgn(h(2), h(0)) as u32,
            1045 => encode(SelectObject(h(2), h(0))),
            1051 => encode(CreateCompatibleBitmap(h(4), i(2), i(0))),
            1052 => encode(CreateCompatibleDC(h(0))),
            1061 => encode(CreatePen(w(6), i(4), d(0))),
            1066 => encode(CreateSolidBrush(d(0))),
            1068 => DeleteDC(h(0)) as u32,
            1069 => DeleteObject(h(0)) as u32,
            1081 => GetMapMode(h(0)) as u32,
            1083 => GetPixel(h(4), i(2), i(0)),
            1087 => encode(GetStockObject(w(0))),
            _ => return None,
        })
    }
}

unsafe fn translated_message(
    hwnd: u32,
    m: u32,
    w: u32,
    l: u32,
    call: impl FnOnce(u32, u32, u32) -> u32,
) -> Option<u32> {
    unsafe {
        // Win16 control messages occupy WM_USER, so translation depends on
        // the target class; application-defined WM_USER messages stay intact.
        let class = state::with(|s| {
            s.windows
                .iter()
                .find(|v| v.hwnd == hwnd)
                .map_or(0, |v| v.class)
        });
        let m = if class == 0xc003 || class == 0xc005 {
            match m {
                0x401..=0x407 => m - 0x401 + 0x180,
                0x408 => 0x187,
                0x409 => 0x188,
                0x40a => 0x189,
                0x40b => 0x18a,
                0x40c => 0x18b,
                0x40d..=0x423 => m - 0x40d + 0x18c,
                _ => m,
            }
        } else if class == 0xc004 && (0x400..=0x418).contains(&m) {
            m - 0x400 + 0x140
        } else {
            m
        };
        let (wp, lp) = to32(m, w, l);
        let wp = if matches!(m, 0x181 | 0x186 | 0x14a | 0x14e) {
            wp as u16 as i16 as i32 as u32
        } else {
            wp
        };
        let m = if m == 0x19 {
            0x132 + (l >> 16).min(6)
        } else {
            m
        };
        // Win16 forwards a segmented, WORD-sized WINDOWPOS back to
        // USER. Keep the translated storage alive through nested calls.
        let position = if lp != 0 && matches!(m, 0x46 | 0x47) {
            Some(pointer(lp, 14)?)
        } else {
            None
        };
        let mut pos = [0u32; 7];
        if let Some(p) = position {
            pos[0] = decode(word(p, 0));
            let after = word(p, 2);
            pos[1] = if after >= 0xfffe {
                after as i16 as i32 as u32
            } else {
                decode(after)
            };
            for n in 2..6 {
                pos[n] = word(p, n * 2) as i16 as i32 as u32;
            }
            pos[6] = word(p, 12);
        }
        let lp = if position.is_some() {
            pos.as_mut_ptr() as u32
        } else if matches!(
            m,
            0x180 | 0x181 | 0x18c | 0x18f | 0x1a2 | 0x143 | 0x14a | 0x14c | 0x14d
        ) {
            string(lp)?
        } else if matches!(m, 0x189 | 0x148) {
            let count_msg = if m == 0x189 { 0x18a } else { 0x149 };
            let count = crate::SendMessageA(hwnd, count_msg, wp, 0);
            if count < 0 {
                return Some(u32::MAX);
            }
            pointer(lp, count as usize + 1)?
        } else if matches!(m, 0xc | 0xd) {
            pointer(lp, if m == 0xd { wp as usize } else { 1 })?
        } else {
            lp
        };
        let result = call(m, wp, lp);
        if m == 0x46 {
            if let Some(p) = position {
                putw(p, 0, encode(pos[0]));
                putw(
                    p,
                    2,
                    if pos[1] >= 0xffff_fffe {
                        pos[1]
                    } else {
                        encode(pos[1])
                    },
                );
                for n in 2..7 {
                    putw(p, n * 2, pos[n]);
                }
            }
        }
        Some(if (0x132..=0x138).contains(&m) {
            encode(result)
        } else {
            result
        })
    }
}
