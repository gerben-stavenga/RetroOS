//! Parser for 16-bit Windows New Executable images.
//!
//! NE is intentionally kept at the personality boundary.  The generic exec
//! layer only recognizes the signature; selectors, chained fixups and the
//! Win16 loader contract belong here.

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadImage,
    Overflow,
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub auto_data: u16,
    pub heap_size: u16,
    pub stack_size: u16,
    pub entry_segment: u16,
    pub entry_offset: u16,
    pub stack_segment: u16,
    pub stack_offset: u16,
    pub segment_count: u16,
    pub module_count: u16,
    pub align_shift: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub number: u16,
    pub file_offset: usize,
    pub file_size: usize,
    pub alloc_size: usize,
    pub flags: u16,
}

impl Segment {
    pub fn is_code(self) -> bool { self.flags & 1 == 0 }
    pub fn has_relocations(self) -> bool { self.flags & 0x0100 != 0 }
}

#[derive(Clone, Debug)]
pub enum Target {
    Internal { segment: u8, offset: u16 },
    ImportOrdinal { module: Vec<u8>, ordinal: u16 },
    ImportName { module: Vec<u8>, name: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Relocation {
    pub source_type: u8,
    pub flags: u8,
    pub source_offset: u16,
    pub target: Target,
}

pub struct Image<'a> {
    data: &'a [u8],
    ne: usize,
    pub header: Header,
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, Error> {
    let b = data.get(at..at.checked_add(2).ok_or(Error::Overflow)?).ok_or(Error::BadImage)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, Error> {
    let b = data.get(at..at.checked_add(4).ok_or(Error::Overflow)?).ok_or(Error::BadImage)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn counted(data: &[u8], at: usize) -> Result<Vec<u8>, Error> {
    let len = *data.get(at).ok_or(Error::BadImage)? as usize;
    Ok(data.get(at + 1..at + 1 + len).ok_or(Error::BadImage)?.to_vec())
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.get(0..2) != Some(b"MZ") { return Err(Error::BadImage); }
        let ne = u32_at(data, 0x3c)? as usize;
        if data.get(ne..ne + 2) != Some(b"NE") { return Err(Error::BadImage); }
        let h16 = |off| u16_at(data, ne + off);
        let header = Header {
            auto_data: h16(0x0e)?,
            heap_size: h16(0x10)?,
            stack_size: h16(0x12)?,
            entry_offset: h16(0x14)?,
            entry_segment: h16(0x16)?,
            stack_offset: h16(0x18)?,
            stack_segment: h16(0x1a)?,
            segment_count: h16(0x1c)?,
            module_count: h16(0x1e)?,
            align_shift: h16(0x32)?,
        };
        if header.segment_count == 0 {
            return Err(Error::BadImage);
        }
        Ok(Self { data, ne, header })
    }

    pub fn segment(&self, number: u16) -> Result<Segment, Error> {
        if number == 0 || number > self.header.segment_count { return Err(Error::BadImage); }
        let table = self.ne + u16_at(self.data, self.ne + 0x22)? as usize;
        let at = table.checked_add((number as usize - 1) * 8).ok_or(Error::Overflow)?;
        let sector = u16_at(self.data, at)? as usize;
        let stored = u16_at(self.data, at + 2)? as usize;
        let flags = u16_at(self.data, at + 4)?;
        let minimum = u16_at(self.data, at + 6)? as usize;
        let file_size = if stored == 0 { 0x10000 } else { stored };
        let alloc_size = if minimum == 0 { 0x10000 } else { minimum }.max(file_size);
        let file_offset = sector.checked_shl(self.header.align_shift as u32).ok_or(Error::Overflow)?;
        self.data.get(file_offset..file_offset.checked_add(file_size).ok_or(Error::Overflow)?)
            .ok_or(Error::BadImage)?;
        Ok(Segment { number, file_offset, file_size, alloc_size, flags })
    }

    pub fn segment_bytes(&self, segment: Segment) -> Result<&'a [u8], Error> {
        self.data.get(segment.file_offset..segment.file_offset + segment.file_size)
            .ok_or(Error::BadImage)
    }

    pub fn modules(&self) -> Result<Vec<Vec<u8>>, Error> {
        let refs = self.ne + u16_at(self.data, self.ne + 0x28)? as usize;
        let names = self.ne + u16_at(self.data, self.ne + 0x2a)? as usize;
        let mut out = Vec::with_capacity(self.header.module_count as usize);
        for n in 0..self.header.module_count as usize {
            out.push(counted(self.data, names + u16_at(self.data, refs + n * 2)? as usize)?);
        }
        Ok(out)
    }

    pub fn entry(&self, wanted: u16) -> Result<(u8, u16), Error> {
        let mut at = self.ne + u16_at(self.data, self.ne + 4)? as usize;
        let end = at + u16_at(self.data, self.ne + 6)? as usize;
        let mut ordinal = 1u16;
        while at < end {
            let count = *self.data.get(at).ok_or(Error::BadImage)? as u16;
            let kind = *self.data.get(at + 1).ok_or(Error::BadImage)?;
            at += 2;
            if count == 0 { break; }
            if kind == 0 {
                ordinal = ordinal.checked_add(count).ok_or(Error::Overflow)?;
                continue;
            }
            for _ in 0..count {
                let (segment, offset, bytes) = if kind == 0xff {
                    (*self.data.get(at + 3).ok_or(Error::BadImage)?, u16_at(self.data, at + 4)?, 6)
                } else {
                    (kind, u16_at(self.data, at + 1)?, 3)
                };
                if ordinal == wanted { return Ok((segment, offset)); }
                ordinal = ordinal.checked_add(1).ok_or(Error::Overflow)?;
                at = at.checked_add(bytes).ok_or(Error::Overflow)?;
            }
        }
        Err(Error::BadImage)
    }

    fn named_ordinal(&self, mut at: usize, end: usize, wanted: &[u8]) -> Result<Option<u16>, Error> {
        while at < end {
            let len = *self.data.get(at).ok_or(Error::BadImage)? as usize;
            at += 1;
            if len == 0 { return Ok(None); }
            let name = self.data.get(at..at.checked_add(len).ok_or(Error::Overflow)?)
                .ok_or(Error::BadImage)?;
            at += len;
            let ordinal = u16_at(self.data, at)?;
            at += 2;
            if name.eq_ignore_ascii_case(wanted) { return Ok(Some(ordinal)); }
        }
        Ok(None)
    }

    /// Resolve an exported name through the resident and non-resident name
    /// tables, then decode its ordinary NE entry-table target.
    pub fn entry_by_name(&self, wanted: &[u8]) -> Result<(u8, u16), Error> {
        let resident = self.ne + u16_at(self.data, self.ne + 0x26)? as usize;
        if let Some(ordinal) = self.named_ordinal(resident, self.data.len(), wanted)? {
            return self.entry(ordinal);
        }
        let nonresident = u32_at(self.data, self.ne + 0x2c)? as usize;
        let length = u16_at(self.data, self.ne + 0x20)? as usize;
        let end = nonresident.checked_add(length).ok_or(Error::Overflow)?;
        if let Some(ordinal) = self.named_ordinal(nonresident, end, wanted)? {
            return self.entry(ordinal);
        }
        Err(Error::BadImage)
    }

    pub fn relocations(&self, segment: Segment) -> Result<Vec<Relocation>, Error> {
        if !segment.has_relocations() { return Ok(Vec::new()); }
        let modules = self.modules()?;
        let imported_names = self.ne + u16_at(self.data, self.ne + 0x2a)? as usize;
        let at = segment.file_offset.checked_add(segment.file_size).ok_or(Error::Overflow)?;
        let count = u16_at(self.data, at)? as usize;
        let mut out = Vec::with_capacity(count);
        for n in 0..count {
            let p = at + 2 + n * 8;
            let source_type = *self.data.get(p).ok_or(Error::BadImage)?;
            let flags = *self.data.get(p + 1).ok_or(Error::BadImage)?;
            let source_offset = u16_at(self.data, p + 2)?;
            let first = u16_at(self.data, p + 4)?;
            let second = u16_at(self.data, p + 6)?;
            let target = match flags & 3 {
                0 => {
                    let (segment, offset) = if first == 0xff {
                        self.entry(second)?
                    } else {
                        (first as u8, second)
                    };
                    Target::Internal { segment, offset }
                }
                1 => Target::ImportOrdinal {
                    module: modules.get(first.wrapping_sub(1) as usize).ok_or(Error::BadImage)?.clone(),
                    ordinal: second,
                },
                2 => Target::ImportName {
                    module: modules.get(first.wrapping_sub(1) as usize).ok_or(Error::BadImage)?.clone(),
                    name: counted(self.data, imported_names + second as usize)?,
                },
                _ => return Err(Error::BadImage),
            };
            out.push(Relocation { source_type, flags, source_offset, target });
        }
        Ok(out)
    }

    /// Return one numeric Windows resource by numeric type and id.
    pub fn resource(&self, wanted_type: u16, wanted_id: u16) -> Result<&'a [u8], Error> {
        let mut at = self.ne + u16_at(self.data, self.ne + 0x24)? as usize;
        let shift = u16_at(self.data, at)? as u32;
        at += 2;
        loop {
            let kind = u16_at(self.data, at)?;
            if kind == 0 { return Err(Error::BadImage); }
            let count = u16_at(self.data, at + 2)? as usize;
            at += 8;
            for _ in 0..count {
                let offset = (u16_at(self.data, at)? as usize)
                    .checked_shl(shift).ok_or(Error::Overflow)?;
                let length = (u16_at(self.data, at + 2)? as usize)
                    .checked_shl(shift).ok_or(Error::Overflow)?;
                let id = u16_at(self.data, at + 6)?;
                if kind == (0x8000 | wanted_type) && id == (0x8000 | wanted_id) {
                    return self.data.get(offset..offset.checked_add(length).ok_or(Error::Overflow)?)
                        .ok_or(Error::BadImage);
                }
                at += 12;
            }
        }
    }

    /// Return one numeric-type resource whose identifier is a resource-table name.
    pub fn named_resource(&self, wanted_type: u16, wanted_name: &[u8]) -> Result<&'a [u8], Error> {
        let resource_table = self.ne + u16_at(self.data, self.ne + 0x24)? as usize;
        let mut at = resource_table;
        let shift = u16_at(self.data, at)? as u32;
        at += 2;
        loop {
            let kind = u16_at(self.data, at)?;
            if kind == 0 { return Err(Error::BadImage); }
            let count = u16_at(self.data, at + 2)? as usize;
            at += 8;
            for _ in 0..count {
                let offset = (u16_at(self.data, at)? as usize)
                    .checked_shl(shift).ok_or(Error::Overflow)?;
                let length = (u16_at(self.data, at + 2)? as usize)
                    .checked_shl(shift).ok_or(Error::Overflow)?;
                let id = u16_at(self.data, at + 6)?;
                if kind == (0x8000 | wanted_type) && id & 0x8000 == 0 {
                    let name_at = resource_table.checked_add(id as usize).ok_or(Error::Overflow)?;
                    let name_len = *self.data.get(name_at).ok_or(Error::BadImage)? as usize;
                    let name = self.data.get(name_at + 1..name_at + 1 + name_len)
                        .ok_or(Error::BadImage)?;
                    if name.eq_ignore_ascii_case(wanted_name) {
                        return self.data.get(offset..offset.checked_add(length)
                            .ok_or(Error::Overflow)?).ok_or(Error::BadImage);
                    }
                }
                at += 12;
            }
        }
    }

    pub fn string_resource(&self, id: u16) -> Result<&'a [u8], Error> {
        let block = id / 16 + 1;
        let index = id % 16;
        let data = self.resource(6, block)?;
        let mut at = 0usize;
        for current in 0..16 {
            let len = *data.get(at).ok_or(Error::BadImage)? as usize;
            let text = data.get(at + 1..at + 1 + len).ok_or(Error::BadImage)?;
            if current == index { return Ok(text); }
            at += 1 + len;
        }
        Err(Error::BadImage)
    }
}

pub fn is_ne(data: &[u8]) -> bool { Image::parse(data).is_ok() }
