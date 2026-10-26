//! Bounded NE resource adapters. Convert historical encodings, then use the
//! same menu/dialog implementations as PE callers. No window policy here.
use super::win16::Retro16Config;
use alloc::vec::Vec;

pub fn instance(h: u32) -> bool {
    unsafe { h != 0 && h == Retro16Config[10] }
}
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let b = self.data.get(self.at..end)?;
        self.at = end;
        Some(b)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn word(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn dword(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn name(&mut self, out: &mut Vec<u8>, ordinal: bool) -> Option<()> {
        let b = self.byte()?;
        if b == 0xff && ordinal {
            put(out, 0xffff);
            put(out, self.word()?);
            return Some(());
        }
        if b == 0 {
            put(out, 0);
            return Some(());
        }
        let start = self.at - 1;
        while self.byte()? != 0 {}
        // Decode using the process ANSI code page, just like PE A entry points.
        let text = unsafe { crate::text::read(self.data[start..].as_ptr() as u32, false) };
        for c in text {
            put(out, c);
        }
        put(out, 0);
        Some(())
    }
}
fn put(v: &mut Vec<u8>, n: u16) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn put32(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn align(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}
pub unsafe fn bytes(kind: u16, name: u32, wide: bool) -> Option<&'static [u8]> {
    unsafe {
        let data =
            core::slice::from_raw_parts(Retro16Config[8] as *const u8, Retro16Config[9] as usize);
        let mut r = Reader { data, at: 0x3c };
        let ne = r.dword()? as usize;
        r.at = ne.checked_add(0x24)?;
        let table = ne.checked_add(r.word()? as usize)?;
        r.at = table;
        let shift = r.word()? as u32;
        let wanted = if name > 0xffff {
            Some(crate::text::read(name, wide))
        } else {
            None
        };
        loop {
            let ty = r.word()?;
            if ty == 0 {
                return None;
            }
            let count = r.word()?;
            r.take(4)?;
            for _ in 0..count {
                let off = (r.word()? as usize).checked_shl(shift)?;
                let len = (r.word()? as usize).checked_shl(shift)?;
                r.take(2)?;
                let id = r.word()?;
                r.take(4)?;
                if ty != 0x8000 | kind {
                    continue;
                }
                let matches = if let Some(ref wanted) = wanted {
                    if id & 0x8000 != 0 {
                        false
                    } else {
                        let at = table.checked_add(id as usize)?;
                        let n = *data.get(at)? as usize;
                        let text = data.get(at + 1..at + 1 + n)?;
                        let mut terminated = text.to_vec();
                        terminated.push(0);
                        crate::text::same(
                            wanted,
                            &crate::text::read(terminated.as_ptr() as u32, false),
                        )
                    }
                } else {
                    id == 0x8000 | name as u16
                };
                if matches {
                    return data.get(off..off.checked_add(len)?);
                }
            }
        }
    }
}
pub fn menu(data: &[u8]) -> Option<Vec<u8>> {
    fn items(r: &mut Reader<'_>, out: &mut Vec<u8>, depth: usize) -> Option<()> {
        if depth > 64 {
            return None;
        }
        loop {
            let flags = r.word()?;
            put(out, flags);
            if flags & 0x10 == 0 {
                put(out, r.word()?);
            }
            r.name(out, false)?;
            if flags & 0x10 != 0 {
                items(r, out, depth + 1)?;
            }
            if flags & 0x80 != 0 {
                return Some(());
            }
        }
    }
    let mut r = Reader { data, at: 0 };
    if r.word()? != 0 {
        return None;
    }
    let skip = r.word()? as usize;
    r.take(skip)?;
    let mut out = alloc::vec![0;4];
    items(&mut r, &mut out, 0)?;
    Some(out)
}
pub fn dialog(data: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader { data, at: 0 };
    let style = r.dword()?;
    let count = r.byte()?;
    let mut out = Vec::new();
    put32(&mut out, style);
    put32(&mut out, 0);
    put(&mut out, count as u16);
    out.extend_from_slice(r.take(8)?);
    r.name(&mut out, true)?;
    r.name(&mut out, false)?;
    r.name(&mut out, false)?;
    if style & 0x40 != 0 {
        put(&mut out, r.word()?);
        r.name(&mut out, false)?;
    }
    for _ in 0..count {
        align(&mut out);
        let position = r.take(8)?;
        let id = r.word()?;
        let style = r.dword()?;
        put32(&mut out, style);
        put32(&mut out, 0);
        out.extend_from_slice(position);
        put(&mut out, id);
        let class = *r.data.get(r.at)?;
        if class & 0x80 != 0 {
            r.at += 1;
            put(&mut out, 0xffff);
            put(&mut out, class as u16);
        } else {
            r.name(&mut out, false)?;
        }
        r.name(&mut out, true)?;
        let extra = r.byte()? as usize;
        put(&mut out, if extra == 0 { 0 } else { extra as u16 + 2 });
        out.extend_from_slice(r.take(extra)?);
    }
    Some(out)
}
