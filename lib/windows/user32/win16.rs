//! Win16 ABI adapters for the ordinary guest USER implementation.
//! Segment and structure translation happens here, never in kernel callbacks.
use crate::{Message, class, input, keyboard, menu, message, paint, rect, state, window};

unsafe extern "system" {
    fn SetBitmapBits(bitmap:u32,n:u32,p:*const u8)->i32;
    fn GetBitmapBits(bitmap: u32, n: i32, p: *mut u8) -> i32;
    fn GetObjectW(object: u32, n: i32, p: *mut u32) -> i32;
    fn Polygon(dc: u32, points: *const [i32; 2], count: i32) -> i32;
    fn GetDeviceCaps(dc: u32, index: i32) -> i32;
    fn CreatePatternBrush(bitmap: u32) -> u32;
    fn CreateBitmap(w:i32,h:i32,planes:u32,depth:u32,p:*const u8)->u32;
    fn CreateFontIndirectA(p:*const u8)->u32;
    fn GetBkMode(dc:u32)->i32;
    fn SetPolyFillMode(dc:u32,value:i32)->i32;
    fn GetBitmapDimensionEx(h:u32,out:*mut [i32;2])->i32;
    fn SetBitmapDimensionEx(h:u32,x:i32,y:i32,out:*mut [i32;2])->i32;
    fn CreatePalette(p:*const u8)->u32;
    fn GetNearestPaletteIndex(palette:u32,color:u32)->u32;
    fn AnimatePalette(h:u32,start:u32,n:u32,p:*const u32)->u32;
    fn GetPaletteEntries(palette:u32,start:u32,count:u32,out:*mut u32)->u32;
    fn GetTextAlign(dc:u32)->u32;
    fn SetPaletteEntries(h:u32,start:u32,n:u32,p:*const u32)->u32;
    fn GetSystemPaletteEntries(dc:u32,start:u32,n:u32,p:*mut u32)->u32;
    fn SelectPalette(dc:u32,p:u32,b:u32)->u32;
    fn RealizePalette(dc:u32)->u32;

    fn GetPrivateProfileStringW(section:*const u16,key:*const u16,default:*const u16,out:*mut u16,capacity:u32,path:*const u16)->u32;
    fn PatBlt(dc:u32,x:i32,y:i32,width:i32,height:i32,rop:u32)->i32;
    fn ExtTextOutA(dc:u32,x:i32,y:i32,options:u32,rect:*const rect::Rect,text:u32,count:u32,dx:*const i32)->i32;
    fn GetSystemDirectoryA(out:u32,capacity:u32)->u32;
    fn MulDiv(number:i32,numerator:i32,denominator:i32)->i32;
    fn GetPrivateProfileIntW(section:*const u16,key:*const u16,default:i32,path:*const u16)->u32;
    fn GetBkColor(dc:u32)->u32;
    fn GetTextColor(dc:u32)->u32;
    fn SetTextAlign(dc:u32,align:u32)->u32;
    fn ExtFloodFill(dc:u32,x:i32,y:i32,color:u32,kind:u32)->i32;
    fn GlobalAddAtomA(name: u32) -> u32;
    fn GlobalFindAtomA(name: u32) -> u32;
    fn GlobalDeleteAtom(atom: u32) -> u32;
    fn GlobalGetAtomNameA(atom: u32, out: u32, capacity: u32) -> u32;
    fn GetWindowsDirectoryA(out: u32, capacity: u32) -> u32;
    fn GetTempFileNameA(path: u32, prefix: u32, unique: u32, out: u32) -> u32;
    fn GetTempPathA(n: u32, p: u32) -> u32;
    fn GetCurrentDirectoryA(n: u32, p: u32) -> u32;
    fn GetFileAttributesA(p: u32) -> u32;
    fn LZCopy(source: u32, dest: u32) -> i32;

    fn WinExec(command: u32, show: u32) -> u32;
    fn CreateFileA(
        path: u32,
        access: u32,
        share: u32,
        security: u32,
        disposition: u32,
        flags: u32,
        template: u32,
    ) -> u32;
    fn CloseHandle(handle: u32) -> i32;
    fn ReadFile(handle: u32, buffer: u32, count: u32, done: *mut u32, overlapped: u32) -> i32;
    fn WriteFile(handle: u32, buffer: u32, count: u32, done: *mut u32, overlapped: u32) -> i32;
    fn SetFilePointer(handle: u32, offset: i32, high: u32, origin: u32) -> u32;
    fn SetEndOfFile(handle: u32) -> i32;

    fn Retro16Call(proc: u32, args: *const u8, bytes: u32, reserve: u32) -> u32;
    fn Rectangle(dc: u32, l: i32, t: i32, r: i32, b: i32) -> i32;
    fn GetSystemMetrics(index: u32) -> u32;
    fn GetKeyState(key: u32) -> i32;
    fn SetBrushOrgEx(dc: u32, x: i32, y: i32, old: *mut [i32; 2]) -> i32;
    fn UnrealizeObject(object: u32) -> i32;
    fn GetPixel(dc: u32, x: i32, y: i32) -> u32;
    fn SetPixel(dc: u32, x: i32, y: i32, color: u32) -> u32;
    fn SetBkColor(dc: u32, color: u32) -> u32;
    fn SetTextColor(dc: u32, color: u32) -> u32;
    fn SetBkMode(dc: u32, mode: u32) -> i32;
    fn SetMapMode(dc: u32, mode: i32) -> i32;
    fn GetMapMode(dc: u32) -> i32;
    fn SetROP2(dc: u32, mode: i32) -> i32;
    fn GetTextExtentPoint32A(dc:u32,text:*const u8,count:i32,out:*mut [i32;2])->i32;
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
    pub(super) static Retro16Config: [u32; 12];
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
fn native_procedure(p: u32) -> Option<u32> {
    let base = unsafe { Retro16Config[11] };
    let offset = p.checked_sub(base)?;
    if offset >= 256 * 16 || offset % 16 != 0 { return None; }
    state::with(|s| s.win16_native_procs.get((offset / 16) as usize).copied())
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
                return unsafe { Retro16Config[11] } + i as u32 * 16;
            }
            if s.win16_native_procs.len() >= 256 {
                return 0;
            }
            let id = unsafe { Retro16Config[11] } + s.win16_native_procs.len() as u32 * 16;
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
// Huge pointers cross consecutive 64 KiB selectors. Validate the whole
// extent before handing a flat pointer to the shared file/memory functions.
unsafe fn huge_pointer(p: u32, bytes: usize) -> Option<u32> {
    unsafe {
        if bytes == 0 { return Some(0); }
        let mut sel = p >> 16;
        let mut offset = p & 0xffff;
        let start = segment(sel)?.0.checked_add(offset)?;
        let mut next = start;
        let mut remaining = bytes;
        while remaining != 0 {
            let (base, limit) = segment(sel)?;
            if base.checked_add(offset)? != next || offset > limit { return None; }
            let n = remaining.min((limit.min(65535) - offset + 1) as usize);
            remaining -= n;
            next = next.checked_add(n as u32)?;
            sel = sel.checked_add(8)?;
            offset = 0;
        }
        Some(start)
    }
}
unsafe fn far_pointer(p: u32) -> Option<u32> {
    if p <= 0xffff { return Some(p); }
    unsafe {
        for index in 1..Retro16Config[6] {
            let sel = index * 8 + 7;
            let (base, limit) = segment(sel)?;
            if let Some(offset) = p.checked_sub(base)
                && offset <= limit.min(0xffff) { return Some((sel << 16) | offset); }
        }
    }
    None
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
// The callback context lives on the ordinary guest stack, so enumeration can
// reenter USER or start another enumeration without global callback state.
unsafe extern "system" fn enum_window_callback(hwnd: u32, context: u32) -> i32 {
    unsafe {
        let context = &*(context as *const [u32; 2]);
        let mut args = [0u8; 6];
        args[..4].copy_from_slice(&context[1].to_le_bytes());
        args[4..].copy_from_slice(&(encode(hwnd) as u16).to_le_bytes());
        (Retro16Call(context[0], args.as_ptr(), 6, 0) as u16 != 0) as i32
    }
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
        // A subclass still receives the Win16 control message numbers and
        // segmented string pointers, even though USER dispatches Win32 messages.
        let class=state::with(|s|s.windows.iter().find(|v|v.hwnd==hwnd).map_or(0,|v|v.class));
        let control_msg=if class==0xc004 && (0x140..=0x158).contains(&msg) {
            msg-0x140+0x400
        } else if class==0xc003 || class==0xc005 {
            match msg {
                0x180..=0x186=>msg-0x180+0x401,
                0x187..=0x18b=>msg-0x187+0x408,
                0x18c..=0x1a2=>msg-0x18c+0x40d,
                _=>msg,
            }
        } else {msg};
        let control_string=control_msg!=msg && matches!(msg,
            0x180|0x181|0x18c|0x18f|0x1a2|0x143|0x14a|0x14c|0x14d|0x158);
        let reserve: u32 = if lp != 0 && (control_string || matches!(msg, 1 | 0x81 | 0xc | 0xd | 0x46 | 0x47)) {
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
        } else if (control_string || matches!(msg, 0xc | 0xd)) && lp != 0 {
            if control_string || msg == 0xc {
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
            control_msg
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
            20000..=20255 => {
                let native = state::with(|s| s.win16_native_procs.get((o - 20000) as usize).copied())?;
                return translated_message(h(8), w(6), w(4), d(0), |m, wp, lp| {
                    crate::call_procedure(native, h(8), m, wp, lp, false) as u32
                });
            }
            24 => window::RemovePropA(h(4), string(d(0))?),
            25 => window::GetPropA(h(4), string(d(0))?),
            26 => window::SetPropA(h(6), string(d(2))?, w(0)),
            431 | 432 => {
                let p = d(0);
                let value = if p >> 16 == 0 { p } else { string(p)? };
                let result = if o == 431 { crate::text::CharUpperA(value) } else { crate::text::CharLowerA(value) };
                if p >> 16 == 0 { result } else { p }
            }
            2058 | 2128 => {
                let off=if o==2128 {4}else{0};
                let wide=|p|->Option<Option<alloc::vec::Vec<u16>>> {
                    if p==0 {return Some(None);}
                    let mut v=crate::text::read(string(p)?,false);v.push(0);Some(Some(v))
                };
                let section=wide(d(14+off))?;
                let key=wide(d(10+off))?;
                let default=wide(d(6+off))?;
                let path=wide(if o==2128 {d(0)}else{0})?;
                let ptr=|s:&Option<alloc::vec::Vec<u16>>|s.as_ref().map_or(core::ptr::null(),|v|v.as_ptr());
                let cap=w(off) as usize;
                if cap==0 {return Some(0);}
                let out=pointer(d(2+off),cap)? as *mut u8;
                let mut buffer=alloc::vec![0u16;cap];
                let n=GetPrivateProfileStringW(ptr(&section),ptr(&key),ptr(&default),buffer.as_mut_ptr(),cap as u32,ptr(&path)) as usize;
                let bytes=crate::text::ansi(&buffer[..n]);
                let list=section.is_none()||key.is_none();
                let reserve=if list && bytes.len()>=cap {2}else{1};
                let n=bytes.len().min(cap.saturating_sub(reserve));
                core::ptr::copy_nonoverlapping(bytes.as_ptr(),out,n);out.add(n).write(0);
                if list && n+1<cap {out.add(n+1).write(0);}
                n as u32
            }
            2127 => {
                let mut section=crate::text::read(string(d(10))?,false);section.push(0);
                let mut key=crate::text::read(string(d(6))?,false);key.push(0);
                let mut path=crate::text::read(string(d(0))?,false);path.push(0);
                GetPrivateProfileIntW(section.as_ptr(),key.as_ptr(),i(4),path.as_ptr())
            }
            2057 => {
                let mut section=crate::text::read(string(d(6))?,false); section.push(0);
                let mut key=crate::text::read(string(d(2))?,false); key.push(0);
                GetPrivateProfileIntW(section.as_ptr(),key.as_ptr(),i(0),core::ptr::null())
            }
            447 => {
                let (wp,lp)=to32(w(6),w(4),d(0));
                crate::mdi::DefMDIChildProcA(h(8),w(6),wp,lp) as u32
            }
            451 => crate::mdi::TranslateMDISysAccel(h(4),&read_message(d(0))?) as u32,

            1075 => GetBkColor(h(0)),
            1090 => GetTextColor(h(0)),
            1345 => GetTextAlign(h(0)),
            1363 => {
                let out=if d(0)==0 {0} else {pointer(d(0),w(4) as usize*4)?};
                GetPaletteEntries(h(8),w(6),w(4),out as *mut u32)
            },
            1468 => {
                let out=pointer(d(0),4)?;let mut size=[0;2];
                let result=GetBitmapDimensionEx(h(4),&mut size);
                if result!=0 {putw(out,0,size[0] as u32);putw(out,2,size[1] as u32);}
                result as u32
            },
            1346 => SetTextAlign(h(2),w(0)),
            1372 => ExtFloodFill(h(10),i(8),i(6),d(2),w(0)) as u32,
            268 => GlobalAddAtomA(string(d(0))?),
            269 => GlobalDeleteAtom(w(0)),
            270 => GlobalFindAtomA(string(d(0))?),
            271 => GlobalGetAtomNameA(w(6), pointer(d(2), w(0) as usize)?, i(0) as u32),
            1029 => PatBlt(h(12),i(10),i(8),i(6),i(4),d(0)) as u32,
            1351 => {
                let rect=if d(10)!=0 {Some(rectangle(d(10))?)} else {None};
                let count=w(4);
                let advances=if d(0)!=0 {
                    let p=pointer(d(0),count as usize*2)?;
                    Some((0..count as usize).map(|n|(p as *const i16).add(n).read_unaligned() as i32).collect::<alloc::vec::Vec<_>>())
                } else {None};
                ExtTextOutA(h(20),i(18),i(16),w(14),rect.as_ref().map_or(core::ptr::null(),|r|r),if count==0 {0} else {pointer(d(6),count as usize)?},count,advances.as_ref().map_or(core::ptr::null(),|v|v.as_ptr())) as u32
            }
            1128 => MulDiv(i(4),i(2),i(0)) as u32,
            2135 => GetSystemDirectoryA(pointer(d(2), w(0) as usize)?, w(0)),
            2134 => GetWindowsDirectoryA(pointer(d(2), w(0) as usize)?, w(0)),
            3001 => LZCopy(w(2), w(0)) as u32,
            2097 => {
                let mut path = [0u8; 260];
                let drive = w(10) as u8;
                if drive & 0x80 != 0 {
                    let letter = drive & 0x7f;
                    if letter == 0 {
                        GetCurrentDirectoryA(260, path.as_mut_ptr() as u32);
                    } else {
                        path[0] = letter;
                    }
                    path[1] = b':';
                    path[2] = b'\\';
                    path[3] = 0;
                } else {
                    GetTempPathA(260, path.as_mut_ptr() as u32);
                    let attr = GetFileAttributesA(path.as_ptr() as u32);
                    if attr == u32::MAX || attr & 16 == 0 {
                        GetCurrentDirectoryA(260, path.as_mut_ptr() as u32);
                        path[1] = b':';
                        path[2] = b'\\';
                        path[3] = 0;
                    }
                }
                let mut prefix = [b'~', 0, 0, 0];
                if d(6) != 0 {
                    let p = string(d(6))? as *const u8;
                    for j in 0..2 {
                        let c = p.add(j).read();
                        if c == 0 {
                            break;
                        }
                        prefix[j + 1] = c;
                    }
                }
                let mut out = [0u8; 260];
                let result = GetTempFileNameA(
                    path.as_ptr() as u32,
                    prefix.as_ptr() as u32,
                    w(4),
                    out.as_mut_ptr() as u32,
                );
                if result == 0 {
                    0
                } else {
                    let n = out.iter().position(|&c| c == 0)? + 1;
                    let dst = pointer(d(0), n)?;
                    core::ptr::copy_nonoverlapping(out.as_ptr(), dst as *mut u8, n);
                    result
                }
            }

            421 => {
                let out = pointer(d(8), 1)?;
                let fmt = string(d(4))?;
                let mut args = d(0);
                let mut valid = true;
                let mut output = [0u8; 1024];
                let result = crate::format::format_with(
                    output.as_mut_ptr() as u32,
                    fmt,
                    false,
                    |kind, length, _| {
                        let far = matches!(kind as u8, b's' | b'S' | b'p');
                        let bytes = if far || length == b'l' as u16 { 4 } else { 2 };
                        let Some(p) = pointer(args, bytes) else {
                            valid = false;
                            return 0;
                        };
                        let raw = if bytes == 4 { long(p, 0) } else { word(p, 0) };
                        args = args.wrapping_add(bytes as u32);
                        if matches!(kind as u8, b's' | b'S') {
                            if raw == 0 {
                                0
                            } else {
                                match string(raw) {
                                    Some(p) => u64::from(p),
                                    None => {
                                        valid = false;
                                        0
                                    }
                                }
                            }
                        } else if bytes == 2 && matches!(kind as u8, b'd' | b'i') {
                            u64::from(raw as i16 as i32 as u32)
                        } else {
                            u64::from(raw)
                        }
                    },
                );
                if !valid || pointer(d(8), result.max(0) as usize + 1).is_none() {
                    0
                } else {
                    core::ptr::copy_nonoverlapping(
                        output.as_ptr(),
                        out as *mut u8,
                        result as usize + 1,
                    );
                    result as u32
                }
            }

            2166 => WinExec(string(d(2))?, w(0)),
            // KERNEL's legacy file calls use DOS-sized handles, not USER/GDI aliases.
            2081 => {
                if CloseHandle(w(0)) != 0 {
                    0
                } else {
                    u32::MAX
                }
            }
            2083 | 2085 => {
                let mode = w(0);
                let access = if o == 2083 {
                    0xc0000000
                } else {
                    match mode & 3 {
                        0 => 0x80000000,
                        1 => 0x40000000,
                        2 => 0xc0000000,
                        _ => return Some(u32::MAX),
                    }
                };
                let share = if o == 2083 {
                    3
                } else {
                    match mode & 0x70 {
                        0 | 0x40 => 3,
                        0x10 => 0,
                        0x20 => 1,
                        0x30 => 2,
                        _ => return Some(u32::MAX),
                    }
                };
                let Some(path) = string(d(2)) else {
                    return Some(u32::MAX);
                };
                let file = CreateFileA(
                    path,
                    access,
                    share,
                    0,
                    if o == 2083 { 2 } else { 3 },
                    if o == 2083 { mode } else { 0 },
                    0,
                );
                if file != u32::MAX && file >= 0x8000 {
                    CloseHandle(file);
                    u32::MAX
                } else {
                    file
                }
            }
            2348 => {
                let n = d(0) as usize;
                if n != 0 {
                    core::ptr::copy(huge_pointer(d(4), n)? as *const u8,
                        huge_pointer(d(8), n)? as *mut u8, n);
                }
                0
            }
            2349 | 2350 => {
                let n = d(0);
                if n > i32::MAX as u32 { return Some(u32::MAX); }
                let Some(buffer) = huge_pointer(d(4), n as usize) else { return Some(u32::MAX); };
                let mut done = 0;
                let ok = if o == 2349 { ReadFile(w(8), buffer, n, &mut done, 0) }
                    else { WriteFile(w(8), buffer, n, &mut done, 0) };
                if ok != 0 { done } else { u32::MAX }
            }
            2084 => SetFilePointer(w(6), d(2) as i32, 0, w(0)),
            2082 | 2086 => {
                let count = w(0);
                let handle = w(6);
                if o == 2086 && count == 0 {
                    if SetEndOfFile(handle) != 0 {
                        0
                    } else {
                        u32::MAX
                    }
                } else {
                    let Some(buffer) = (if count == 0 {
                        Some(0)
                    } else {
                        pointer(d(2), count as usize)
                    }) else {
                        return Some(u32::MAX);
                    };
                    let mut done = 0;
                    let ok = if o == 2082 {
                        ReadFile(handle, buffer, count, &mut done, 0)
                    } else {
                        WriteFile(handle, buffer, count, &mut done, 0)
                    };
                    if ok != 0 { done } else { u32::MAX }
                }
            }

            1 => crate::messagebox::MessageBoxA(h(10), string(d(6))?, string(d(2))?, w(0)) as u32,
            5 => 1,
            6 => {
                message::PostQuitMessage(w(0));
                0
            }
            10 => message::SetTimer(h(8), w(6), w(4), procedure(d(0))),
            12 => message::KillTimer(h(2), w(0)) as u32,
            13 | 15 | 3607 => crate::runtime::GetTickCount(),
            // The underlying clock already has millisecond resolution. Keep
            // begin/end requests balanced without changing the hardware timer.
            3605 | 3606 => {
                let period=w(0) as u16;
                if period==0 {97} else {state::with(|s| {
                    if o==3605 {s.timer_periods.push(period);0}
                    else if let Some(i)=s.timer_periods.iter().position(|&p|p==period) {s.timer_periods.remove(i);0}
                    else {97}
                })}
            },
            3604 => {
                if w(0)<4 {11} else {
                    let p=pointer(d(2),4)?;
                    putw(p,0,1);putw(p,2,65535);0
                }
            },
            3601 => {
                if w(0)>=8 && d(2)!=0 {
                    let p=pointer(d(2),8)?;
                    putw(p,0,1);putl(p,2,crate::runtime::GetTickCount());
                }
                0
            },
            2036 => { let id=crate::runtime::GetCurrentThreadId() & 0xffff; id | (id<<16) },
            258 => {
                let count=w(0) as usize;
                if count==0 {return Some(window::MapWindowPoints(h(8),h(6),core::ptr::null_mut(),0));}
                let p=pointer(d(2),count*4)?;
                let mut points=alloc::vec::Vec::with_capacity(count);
                for n in 0..count {points.push(rect::Point {
                    x:word(p,n*4) as i16 as i32,y:word(p,n*4+2) as i16 as i32,
                });}
                let result=window::MapWindowPoints(h(8),h(6),points.as_mut_ptr(),count as u32);
                for (n,point) in points.into_iter().enumerate() {
                    putw(p,n*4,point.x as u32);putw(p,n*4+2,point.y as u32);
                }
                result
            },
            251 => message::InSendMessage() as u32,
            266 => message::SetMessageQueue(w(0) as i16 as i32) as u32,
            224 => window::GetWindowThreadProcessId(h(0),core::ptr::null_mut()) & 0xffff,
            54 | 55 | 225 => {
                let context=[d(4),d(0)];
                let data=&context as *const [u32;2] as u32;
                match o {
                    54 => window::EnumWindows(enum_window_callback,data) as u32,
                    55 => window::EnumChildWindows(h(8),enum_window_callback,data) as u32,
                    _ => input::EnumThreadWindows(w(8),enum_window_callback as *const () as u32,data) as u32,
                }
            },
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
            17 => {
                let out = pointer(d(0), 4)?;
                let mut point = [0; 2];
                let result = input::GetCursorPos(&mut point);
                putw(out, 0, point[0] as u32);
                putw(out, 2, point[1] as u32);
                result as u32
            }
            28 | 29 => {
                let p = pointer(d(0), 4)?;
                let mut point = rect::Point {
                    x: word(p, 0) as i16 as i32,
                    y: word(p, 2) as i16 as i32,
                };
                let result = if o == 28 {
                    window::ClientToScreen(h(4), &mut point)
                } else {
                    window::ScreenToClient(h(4), &mut point)
                };
                putw(p, 0, point.x as u32);
                putw(p, 2, point.y as u32);
                result as u32
            }
            31 => window::IsIconic(h(0)) as u32,
            69 => encode(input::SetCursor(h(0))),
            71 => input::ShowCursor(i(0)) as u32,
            173 => encode(crate::resource::LoadCursorA(w(4), string(d(0))?)),
            70 => input::SetCursorPos(i(2), i(0)) as u32,
            106 => GetKeyState(w(0)) as u32,
            232 => {
                let after = w(10);
                window::SetWindowPos(
                    h(12),
                    if after >= 0xfffe {
                        after as i16 as i32 as u32
                    } else {
                        decode(after)
                    },
                    i(8),
                    i(6),
                    i(4),
                    i(2),
                    w(0),
                ) as u32
            }
            196 => {
                let count = i(6);
                if count < 0 {
                    return Some(0);
                }
                let p = if count == 0 {
                    0
                } else {
                    pointer(d(2), count as usize * 2)?
                };
                let tabs: alloc::vec::Vec<i32> = (0..count as usize)
                    .map(|j| word(p, j * 2) as i16 as i32)
                    .collect();
                crate::drawing::TabbedTextOutA(
                    h(18),
                    i(16),
                    i(14),
                    pointer(d(10), w(8) as usize)?,
                    i(8),
                    count,
                    tabs.as_ptr(),
                    i(0),
                )
            }
            1148 => {
                let mut old = [0; 2];
                if SetBrushOrgEx(h(4), i(2), i(0), &mut old) == 0 {
                    0
                } else {
                    (old[0] as u32 & 0xffff) | ((old[1] as u32 & 0xffff) << 16)
                }
            }
            1150 => UnrealizeObject(h(0)) as u32,
            58 => {
                let count=i(0);
                if count<=0 {0} else {window::GetClassNameA(h(6),pointer(d(2),count as usize)?,count)}
            },
            267 => crate::scrollbar::ShowScrollBar(h(4),i(2),i(0)) as u32,
            63 => crate::scrollbar::GetScrollPos(h(2),i(0)) as u32,
            73 => {let out=pointer(d(0),8)?;for n in 0..4 {putw(out,n*2,0);}1},
            75 => rect::IsRectEmpty(&rectangle(d(0))?) as u32,
            80 => {
                let left=rectangle(d(4))?;let right=rectangle(d(0))?;
                let mut out=rect::Rect {left:0,top:0,right:0,bottom:0};
                let result=rect::UnionRect(&mut out,&left,&right);
                write_rect(d(8),&out)?;result as u32
            },
            129 => {
                let index=i(0);
                let value=if index<0 {class::GetClassLongA(h(2),index)} else {class::GetClassWord(h(2),index)};
                if matches!(index,-14|-12|-16) {encode(value)} else {value}
            },
            230 | 262 => encode(window::GetWindow(h(2),w(0))),
            263 => menu::GetMenuItemCount(h(0)) as u32,
            264 => menu::GetMenuItemID(h(2),i(0)),
            403 => class::UnregisterClassA(string(d(2))?,h(0)) as u32,
            415 => encode(menu::CreatePopupMenu()),
            34 => window::EnableWindow(h(2), i(0)) as u32,
            35 => window::IsWindowEnabled(h(0)) as u32,
            36 => window::GetWindowTextA(h(6), pointer(d(2), w(0) as usize)?, i(0)) as u32,
            37 => window::SetWindowTextA(h(4), string(d(0))?) as u32,
            38 => window::GetWindowTextLengthA(h(0)) as u32,
            48 => window::IsChild(h(2), h(0)) as u32,
            49 => window::IsWindowVisible(h(0)) as u32,
            90 => input::IsDialogMessageA(h(4), &read_message(d(0))?) as u32,
            112 => message::WaitMessage() as u32,
            228 => encode(input::GetNextDlgTabItem(h(4), h(2), w(0))),
            65 => {
                let mut low = 0; let mut high = 0;
                let result = crate::scrollbar::GetScrollRange(h(10), i(8), &mut low, &mut high);
                (pointer(d(4), 2)? as *mut i16).write_unaligned(low as i16);
                (pointer(d(0), 2)? as *mut i16).write_unaligned(high as i16);
                result as u32
            }
            89 => encode(crate::dialog::CreateDialogParamA(w(10), string(d(6))?, h(4), procedure(d(0)), 0)),
            243 => crate::dialog::GetDialogBaseUnits(),
            239 => crate::dialog::DialogBoxParamA(w(14), string(d(10))?, h(8), procedure(d(4)), d(0)) as u32,
            241 => encode(crate::dialog::CreateDialogParamA(w(14), string(d(10))?, h(8), procedure(d(4)), d(0))),
            250 => menu::GetMenuState(h(4), w(2), w(0)),
            272 => window::IsZoomed(h(0)) as u32,
            284 => state::with(|s| (0x8000usize.saturating_sub(s.win16_handles.len()) * 100 / 0x8000) as u32),
            308 => {
                let (wp, lp) = to32(w(6), w(4), d(0));
                crate::dialog::DefDlgProcA(h(8), w(6), wp, lp) as u32
            }
            404 => {
                let out = pointer(d(0), 26)?;
                let mut wc = [0u32; 10];
                let result = class::GetClassInfoA(w(8), string(d(4))?, wc.as_mut_ptr() as u32);
                if result == 0 { return Some(0); }
                putw(out,0,wc[0]); putl(out,2,original(wc[1]));
                for (at, value) in [(6,wc[2]),(8,wc[3]),(10,wc[4]),(12,encode(wc[5])),(14,encode(wc[6])),(16,encode(wc[7]))] {
                    putw(out,at,value);
                }
                putl(out,18,far_pointer(wc[8])?);
                putl(out,22,d(4));
                result as u32
            }

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
            41 | 452 => {
                let size = |v: i32| if v == i16::MIN as i32 { i32::MIN } else { v };
                encode(crate::CreateWindowExA(
                    if o == 452 { d(30) } else { 0 },
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
            61 => {
                let area = if d(4) == 0 {
                    None
                } else {
                    let r = rectangle(d(4))?;
                    Some([r.left, r.top, r.right, r.bottom])
                };
                let clip = if d(0) == 0 {
                    None
                } else {
                    let r = rectangle(d(0))?;
                    Some([r.left, r.top, r.right, r.bottom])
                };
                paint::ScrollWindow(
                    h(12),
                    i(10),
                    i(8),
                    area.as_ref().map_or(core::ptr::null(), |r| r),
                    clip.as_ref().map_or(core::ptr::null(), |r| r),
                ) as u32
            }
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
            84 => crate::resource::DrawIcon(h(6), i(4), i(2), h(0)) as u32,
            83 => {
                let r = rectangle(d(2))?;
                crate::drawing::FrameRect(h(6), &[r.left, r.top, r.right, r.bottom], h(0)) as u32
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
            92 => {
                let child = window::GetDlgItem(h(6), w(4) as i32);
                let icon = state::with(|s| {
                    s.windows
                        .iter()
                        .any(|v| v.hwnd == child && v.class == 0xc002 && v.style & 0x1f == 3)
                });
                if icon && d(0) <= 0xffff {
                    crate::SendMessageA(child, 0x170, decode(d(0)), 0);
                    1
                } else {
                    crate::dialog::SetDlgItemTextA(h(6), w(4), string(d(0))?) as u32
                }
            }
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
                // Native control procedures have real Win16 entry thunks.
                // Forward directly when called through CallWindowProc.
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
            153 => {
                let flags = w(0);
                let id = if flags & 0x10 != 0 { h(2) } else { w(2) };
                if flags & 0x100 != 0 {
                    menu::AppendMenuA(h(10), flags & !0x100, id, string(d(4))?) as u32
                } else if flags & 0x200 != 0 {
                    menu::DeleteMenu(h(10), w(8), flags & !0x200) as u32
                } else if flags & 0x1000 != 0 {
                    menu::RemoveMenu(h(10), w(8), flags & !0x1000) as u32
                } else if flags & 0x80 != 0 {
                    menu::ModifyMenuA(h(10), w(8), flags & !0x80, id, string(d(4))?) as u32
                } else {
                    menu::InsertMenuA(h(10), w(8), flags, id, string(d(4))?) as u32
                }
            }
            174 => encode(crate::resource::LoadIconA(w(4), string(d(0))?)),
            457 => crate::resource::DestroyIcon(h(0)) as u32,
            179 => GetSystemMetrics(w(0)),
            286 => encode(window::GetDesktopWindow()),
            236 => encode(input::GetCapture()),
            219 | 242 => {
                let shift = if o == 219 { 0 } else { 4 };
                let p = d(6 + shift);
                let (_, limit) = segment(p >> 16)?;
                let at = pointer(p, 1)?;
                let bytes = core::slice::from_raw_parts(
                    at as *const u8,
                    (limit - (p & 0xffff) + 1) as usize,
                );
                let converted = crate::win16_resource::dialog(bytes)?;
                encode(crate::dialog::CreateDialogIndirectParamA(
                    w(10 + shift),
                    converted.as_ptr() as u32,
                    h(4 + shift),
                    procedure(d(shift)),
                    if o == 219 { 0 } else { d(0) },
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
            282 => encode(SelectPalette(h(4),h(2),w(0))),
            163 => crate::caret::CreateCaret(h(6),h(4),w(2) as i16 as i32,w(0) as i16 as i32) as u32,
            164 => crate::caret::DestroyCaret() as u32,
            165 => crate::caret::SetCaretPos(w(2) as i16 as i32,w(0) as i16 as i32) as u32,
            166 => crate::caret::HideCaret(h(0)) as u32,
            167 => crate::caret::ShowCaret(h(0)) as u32,
            168 => crate::caret::SetCaretBlinkTime(w(0)) as u32,
            169 => crate::caret::GetCaretBlinkTime(),
            183 => {
                let out=pointer(d(0),4)? as *mut i16;
                let mut pos=[0;2];
                let result=crate::caret::GetCaretPos(&mut pos);
                if result!=0 {out.write_unaligned(pos[0] as i16);out.add(1).write_unaligned(pos[1] as i16);}
                result as u32
            }
            1091 | 1471 => {
                let shift=if o==1471 {4} else {0};
                let count=i(shift);
                if count<0 {return Some(0);}
                let text=if count==0 {0} else {pointer(d(shift+2),count as usize)?};
                let out=if o==1471 {pointer(d(0),4)?} else {0};
                let mut size=[0;2];
                let result=GetTextExtentPoint32A(h(shift+6),text as *const u8,count,&mut size);
                if result==0 {0} else if o==1091 {(size[0] as u32 & 0xffff) | ((size[1] as u32)<<16)}
                else {putw(out,0,size[0] as u32);putw(out,2,size[1] as u32);result as u32}
            },
            1483 => {
                let out=if d(0)==0 {0} else {pointer(d(0),4)?};
                let mut old=[0;2];
                let result=MoveToEx(h(8),i(6),i(4),&mut old);
                if result!=0 && out!=0 {putw(out,0,old[0] as u32);putw(out,2,old[1] as u32);}
                result as u32
            },
            1370 => GetNearestPaletteIndex(h(4),d(0)),
            283 => RealizePalette(h(0)),
            1006 => SetPolyFillMode(h(2),i(0)) as u32,
            1036 => {
                let count = i(0);
                if count < 2 { return Some(0); }
                let source = pointer(d(2), count as usize * 4)?;
                let points: alloc::vec::Vec<[i32; 2]> = (0..count as usize).map(|n| {
                    [word(source, n * 4) as i16 as i32, word(source, n * 4 + 2) as i16 as i32]
                }).collect();
                Polygon(h(6), points.as_ptr(), count) as u32
            }
            1037 => {
                let count=w(0) as usize;
                let points=pointer(d(2),count.checked_mul(4)?)?;
                if count<2 {return Some(0);}
                let mut old=[0;2];
                MoveToEx(h(6),word(points,0) as i16 as i32,word(points,2) as i16 as i32,&mut old);
                for n in 1..count {LineTo(h(6),word(points,n*4) as i16 as i32,word(points,n*4+2) as i16 as i32);}
                MoveToEx(h(6),old[0],old[1],core::ptr::null_mut());1
            }
            1048 => {
                let width=i(10);let height=i(8);let depth=w(4);let planes=w(6);
                if width<0 || height<0 {return Some(0);}
                let bytes=(width as usize).checked_mul(depth as usize)?.div_ceil(16)
                    .checked_mul(2)?.checked_mul(height as usize)?;
                let source=if d(0)==0 {0}else{huge_pointer(d(0),bytes)?};
                encode(CreateBitmap(width,height,planes,depth,source as *const u8))
            }
            1056 | 1057 => {
                let mut font=[0u8;60];
                if o==1057 {
                    let src=pointer(d(0),50)?;
                    for n in 0..5 {font[n*4..n*4+4].copy_from_slice(&(word(src,n*2) as i16 as i32).to_le_bytes());}
                    core::ptr::copy_nonoverlapping((src+10) as *const u8,font.as_mut_ptr().add(20),40);
                } else {
                    for n in 0..5 {font[n*4..n*4+4].copy_from_slice(&i(28-n*2).to_le_bytes());}
                    for n in 0..8 {font[20+n]=w(18-n*2) as u8;}
                    let face=string(d(0))? as *const u8;
                    for n in 0..31 {let c=face.add(n).read();font[28+n]=c;if c==0 {break;}}
                }
                encode(CreateFontIndirectA(font.as_ptr()))
            }
            1076 => GetBkMode(h(0)) as u32,
            // No external font resource loader or enumeration provider yet.
            1119 | 1136 | 1330 => 0,
            1106 => SetBitmapBits(h(8),d(4),huge_pointer(d(0),d(4) as usize)? as *const u8) as u32,
            1074 => {
                let total = GetBitmapBits(h(8), 0, core::ptr::null_mut());
                if d(0) == 0 { total as u32 } else {
                    let count = (d(4) as i32).max(0).min(total.max(0));
                    if count == 0 { return Some(0); }
                    GetBitmapBits(h(8), count, huge_pointer(d(0), count as usize)? as *mut u8) as u32
                }
            }
            1082 => {
                let mut object = [0u32; 24];
                let size = GetObjectW(h(6), 96, object.as_mut_ptr());
                if size == 24 {
                    if i(4) < 14 { return Some(0); }
                    let n = 14;
                    let mut bitmap = [0u8; 14];
                    for (i, v) in object[..4].iter().enumerate() {
                        bitmap[i * 2..i * 2 + 2].copy_from_slice(&(*v as u16).to_le_bytes());
                    }
                    bitmap[8] = object[4] as u8;
                    bitmap[9] = (object[4] >> 16) as u8;
                    let out = pointer(d(0), n)?;
                    core::ptr::copy_nonoverlapping(bitmap.as_ptr(), out as *mut u8, n);
                    n as u32
                } else if size == 92 {
                    if i(4) < 50 { return Some(0); }
                    let mut font = [0u8; 50];
                    for (n, value) in object[..5].iter().enumerate() {
                        font[n * 2..n * 2 + 2].copy_from_slice(&(*value as u16).to_le_bytes());
                    }
                    let bytes = core::slice::from_raw_parts(object.as_ptr().cast::<u8>(), 92);
                    font[10..18].copy_from_slice(&bytes[20..28]);
                    for n in 0..32 {
                        let c = u16::from_le_bytes([bytes[28 + n * 2], bytes[29 + n * 2]]);
                        font[18 + n] = u8::try_from(c).unwrap_or(b'?');
                    }
                    core::ptr::copy_nonoverlapping(font.as_ptr(), pointer(d(0), 50)? as *mut u8, 50);
                    50
                } else { 0 }
            }
            1162 | 1163 => {
                let mut size=[0;2];
                if o==1162 {GetBitmapDimensionEx(h(0),&mut size);}
                else {SetBitmapDimensionEx(h(4),i(2),i(0),&mut size);}
                size[0] as u16 as u32 | ((size[1] as u16 as u32)<<16)
            }
            1360 => {
                let p=pointer(d(0),4)?;let n=word(p,2) as usize;
                encode(CreatePalette(pointer(d(0),4+n*4)? as *const u8))
            }
            1367 => AnimatePalette(h(8),w(6),w(4),pointer(d(0),w(4) as usize*4)? as *const u32),
            1364 => SetPaletteEntries(h(8),w(6),w(4),pointer(d(0),w(4) as usize*4)? as *const u32),
            1375 => GetSystemPaletteEntries(h(8),w(6),w(4),if d(0)==0 {core::ptr::null_mut()}else{pointer(d(0),w(4) as usize*4)? as *mut u32}),
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
            1060 => encode(CreatePatternBrush(h(0))),
            1066 => encode(CreateSolidBrush(d(0))),
            1068 => DeleteDC(h(0)) as u32,
            1069 => DeleteObject(h(0)) as u32,
            1081 => GetMapMode(h(0)) as u32,
            1080 => GetDeviceCaps(h(2), i(0)) as u32,
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
        let wp = if matches!(m, 0x181 | 0x186 | 0x18c | 0x18f | 0x1a2 | 0x14a | 0x14c | 0x14d | 0x14e | 0x158) {
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
            0x180 | 0x181 | 0x18c | 0x18f | 0x1a2 | 0x143 | 0x14a | 0x14c | 0x14d | 0x158
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
