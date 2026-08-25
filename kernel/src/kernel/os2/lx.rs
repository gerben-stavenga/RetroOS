//! Parser for the 32-bit OS/2 Linear Executable (LX) format.
//!
//! LX loader-table offsets are relative to the LX header. Enumerated page
//! data and the non-resident name table are file-relative. This module only
//! validates and describes the image; mapping and linking live in `os2`.

extern crate alloc;

use alloc::{vec, vec::Vec};

pub const PAGE_VALID: u16 = 0;
pub const PAGE_ITERATED: u16 = 1;
pub const PAGE_INVALID: u16 = 2;
pub const PAGE_ZEROED: u16 = 3;

pub const OBJ_WRITABLE: u32 = 0x0002;
pub const OBJ_EXECUTABLE: u32 = 0x0004;
pub const OBJ_ALIAS: u32 = 0x1000;
pub const OBJ_BIG: u32 = 0x2000;
pub const MOD_DLL: u32 = 0x8000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    Unsupported,
    BadTable,
}

fn u16_at(data: &[u8], off: usize) -> Result<u16, Error> {
    let s = data.get(off..off + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn i16_at(data: &[u8], off: usize) -> Result<i16, Error> {
    Ok(u16_at(data, off)? as i16)
}

fn u32_at(data: &[u8], off: usize) -> Result<u32, Error> {
    let s = data.get(off..off + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub at: usize,
    pub flags: u32,
    pub num_pages: u32,
    pub start_object: u32,
    pub eip: u32,
    pub stack_object: u32,
    pub esp: u32,
    pub page_size: u32,
    pub page_shift: u32,
    pub object_table: u32,
    pub object_count: u32,
    pub page_map: u32,
    pub resident_names: u32,
    pub resource_table: u32,
    pub resource_count: u32,
    pub entry_table: u32,
    pub fixup_pages: u32,
    pub fixup_records: u32,
    pub import_modules: u32,
    pub import_module_count: u32,
    pub import_procedures: u32,
    pub data_pages: u32,
    pub nonresident_names: u32,
    pub nonresident_name_size: u32,
    pub stack_size: u32,
}

impl Header {
    fn rel(self, off: u32) -> Result<usize, Error> {
        self.at.checked_add(off as usize).ok_or(Error::BadTable)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Object {
    pub size: u32,
    pub address: u32,
    pub flags: u32,
    /// One-based index of the object's first page-map entry.
    pub map_index: u32,
    pub map_count: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Page {
    pub file_offset: u32,
    pub data_size: u16,
    pub flags: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: Vec<u8>,
    pub ordinal: u16,
    pub object: u16,
    pub offset: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Internal { object: u16, offset: u32 },
    ImportOrdinal { module: u16, ordinal: u16 },
    ImportName { module: u16, name_offset: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixup {
    pub page: u32,
    pub source_type: u8,
    pub source_offset: i16,
    pub target: Target,
    pub additive: u32,
}

pub struct Image<'a> {
    data: &'a [u8],
    pub header: Header,
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let at = if data.get(0..2) == Some(b"LX") {
            0
        } else if data.get(0..2) == Some(b"MZ") {
            u32_at(data, 0x3c)? as usize
        } else {
            return Err(Error::BadMagic);
        };
        if data.get(at..at + 2) != Some(b"LX") {
            return Err(Error::BadMagic);
        }
        // The defined header is 196 bytes. OS/2/i386 LX is little-endian,
        // format level zero, CPU >= 386, target OS 1.
        data.get(at..at + 196).ok_or(Error::Truncated)?;
        if data[at + 2] != 0
            || data[at + 3] != 0
            || u32_at(data, at + 4)? != 0
            || u16_at(data, at + 8)? < 2
            || u16_at(data, at + 10)? != 1
        {
            return Err(Error::Unsupported);
        }
        let header = Header {
            at,
            flags: u32_at(data, at + 0x10)?,
            num_pages: u32_at(data, at + 0x14)?,
            start_object: u32_at(data, at + 0x18)?,
            eip: u32_at(data, at + 0x1c)?,
            stack_object: u32_at(data, at + 0x20)?,
            esp: u32_at(data, at + 0x24)?,
            page_size: u32_at(data, at + 0x28)?,
            page_shift: u32_at(data, at + 0x2c)?,
            object_table: u32_at(data, at + 0x40)?,
            object_count: u32_at(data, at + 0x44)?,
            page_map: u32_at(data, at + 0x48)?,
            resident_names: u32_at(data, at + 0x58)?,
            resource_table: u32_at(data, at + 0x50)?,
            resource_count: u32_at(data, at + 0x54)?,
            entry_table: u32_at(data, at + 0x5c)?,
            fixup_pages: u32_at(data, at + 0x68)?,
            fixup_records: u32_at(data, at + 0x6c)?,
            import_modules: u32_at(data, at + 0x70)?,
            import_module_count: u32_at(data, at + 0x74)?,
            import_procedures: u32_at(data, at + 0x78)?,
            data_pages: u32_at(data, at + 0x80)?,
            nonresident_names: u32_at(data, at + 0x88)?,
            nonresident_name_size: u32_at(data, at + 0x8c)?,
            stack_size: u32_at(data, at + 0xac)?,
        };
        if header.page_size == 0 || !header.page_size.is_power_of_two() {
            return Err(Error::Unsupported);
        }
        let image = Self { data, header };
        // Validate the fixed-size tables now, so later iterators cannot wrap.
        let obj_end = header.rel(header.object_table)?
            .checked_add(header.object_count as usize * 24).ok_or(Error::BadTable)?;
        let map_end = header.rel(header.page_map)?
            .checked_add(header.num_pages as usize * 8).ok_or(Error::BadTable)?;
        if obj_end > data.len() || map_end > data.len() {
            return Err(Error::Truncated);
        }
        Ok(image)
    }

    pub fn is_dll(&self) -> bool { self.header.flags & MOD_DLL != 0 }

    pub fn object(&self, one_based: u32) -> Result<Object, Error> {
        if one_based == 0 || one_based > self.header.object_count {
            return Err(Error::BadTable);
        }
        let at = self.header.rel(self.header.object_table)? + (one_based as usize - 1) * 24;
        Ok(Object {
            size: u32_at(self.data, at)?,
            address: u32_at(self.data, at + 4)?,
            flags: u32_at(self.data, at + 8)?,
            map_index: u32_at(self.data, at + 12)?,
            map_count: u32_at(self.data, at + 16)?,
        })
    }

    pub fn objects(&self) -> Result<Vec<Object>, Error> {
        (1..=self.header.object_count).map(|n| self.object(n)).collect()
    }

    pub fn page(&self, one_based: u32) -> Result<Page, Error> {
        if one_based == 0 || one_based > self.header.num_pages {
            return Err(Error::BadTable);
        }
        let at = self.header.rel(self.header.page_map)? + (one_based as usize - 1) * 8;
        let encoded = u32_at(self.data, at)?;
        let relative = encoded.checked_shl(self.header.page_shift).ok_or(Error::BadTable)?;
        let file_offset = self.header.data_pages.checked_add(relative).ok_or(Error::BadTable)?;
        Ok(Page {
            file_offset,
            data_size: u16_at(self.data, at + 4)?,
            flags: u16_at(self.data, at + 6)?,
        })
    }

    pub fn page_data(&self, page: Page) -> Result<&'a [u8], Error> {
        if page.flags != PAGE_VALID {
            return Ok(&[]);
        }
        let at = page.file_offset as usize;
        self.data.get(at..at + page.data_size as usize).ok_or(Error::Truncated)
    }

    pub fn import_modules(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut at = self.header.rel(self.header.import_modules)?;
        let mut out = Vec::with_capacity(self.header.import_module_count as usize);
        for _ in 0..self.header.import_module_count {
            let len = *self.data.get(at).ok_or(Error::Truncated)? as usize;
            at += 1;
            out.push(self.data.get(at..at + len).ok_or(Error::Truncated)?.to_vec());
            at += len;
        }
        Ok(out)
    }

    pub fn resources(&self) -> Result<Vec<Resource>, Error> {
        let mut out = Vec::with_capacity(self.header.resource_count as usize);
        let table = self.header.rel(self.header.resource_table)?;
        for index in 0..self.header.resource_count as usize {
            let at = table.checked_add(index * 14).ok_or(Error::BadTable)?;
            out.push(Resource {
                kind: u16_at(self.data, at)?,
                id: u16_at(self.data, at + 2)?,
                size: u32_at(self.data, at + 4)?,
                object: u16_at(self.data, at + 8)?,
                offset: u32_at(self.data, at + 10)?,
            });
        }
        Ok(out)
    }

    /// Return a resource's bytes from its object page stream. Resource data
    /// can cross page records and need not have a mapped virtual address.
    pub fn resource_data(&self, resource: Resource) -> Result<Vec<u8>, Error> {
        let object = self.object(resource.object as u32)?;
        let end = resource.offset.checked_add(resource.size).ok_or(Error::BadTable)?;
        if end > object.size { return Err(Error::BadTable); }
        let mut out = Vec::with_capacity(resource.size as usize);
        let mut offset = resource.offset;
        while offset < end {
            let page_in_object = offset / self.header.page_size;
            let within = offset % self.header.page_size;
            let page = self.page(object.map_index + page_in_object)?;
            if page.flags != PAGE_VALID { return Err(Error::BadTable); }
            let bytes = self.page_data(page)?;
            let available = (bytes.len() as u32).saturating_sub(within);
            let take = available.min(end - offset);
            if take == 0 { return Err(Error::BadTable); }
            out.extend_from_slice(&bytes[within as usize..(within + take) as usize]);
            offset += take;
        }
        Ok(out)
    }

    pub fn import_name(&self, offset: u32) -> Result<Vec<u8>, Error> {
        let at = self.header.rel(self.header.import_procedures)?
            .checked_add(offset as usize).ok_or(Error::BadTable)?;
        let len = *self.data.get(at).ok_or(Error::Truncated)? as usize;
        Ok(self.data.get(at + 1..at + 1 + len).ok_or(Error::Truncated)?.to_vec())
    }

    fn entry_points(&self) -> Result<Vec<Option<(u16, u32)>>, Error> {
        let mut at = self.header.rel(self.header.entry_table)?;
        let mut entries = vec![None]; // ordinal zero has no entry
        loop {
            let count = *self.data.get(at).ok_or(Error::Truncated)? as usize;
            at += 1;
            if count == 0 { break; }
            let kind = *self.data.get(at).ok_or(Error::Truncated)?;
            at += 1;
            if kind == 0 {
                entries.resize(entries.len() + count, None);
                continue;
            }
            let object = u16_at(self.data, at)?;
            at += 2;
            for _ in 0..count {
                let _flags = *self.data.get(at).ok_or(Error::Truncated)?;
                at += 1;
                let offset = match kind {
                    1 => { let v = u16_at(self.data, at)? as u32; at += 2; v }
                    3 => { let v = u32_at(self.data, at)?; at += 4; v }
                    // Call gates and forwarded exports are deliberately left
                    // for the 16-bit/mixed-module phase.
                    _ => return Err(Error::Unsupported),
                };
                entries.push(Some((object, offset)));
            }
        }
        Ok(entries)
    }

    pub fn exports(&self) -> Result<Vec<Export>, Error> {
        let entries = self.entry_points()?;
        let mut out = Vec::new();
        let resident = self.header.rel(self.header.resident_names)?;
        let mut tables = vec![resident];
        if self.header.nonresident_names != 0 && self.header.nonresident_name_size != 0 {
            let at = self.header.nonresident_names as usize;
            self.data.get(at..at + self.header.nonresident_name_size as usize)
                .ok_or(Error::Truncated)?;
            tables.push(at);
        }
        for mut at in tables {
            loop {
                let len = *self.data.get(at).ok_or(Error::Truncated)? as usize;
                at += 1;
                if len == 0 { break; }
                let name = self.data.get(at..at + len).ok_or(Error::Truncated)?.to_vec();
                at += len;
                let ordinal = u16_at(self.data, at)?;
                at += 2;
                if ordinal == 0 { continue; } // module name/description
                let (object, offset) = entries.get(ordinal as usize)
                    .and_then(|v| *v).ok_or(Error::BadTable)?;
                out.push(Export { name, ordinal, object, offset });
            }
        }
        Ok(out)
    }

    fn read_index(&self, at: &mut usize, wide: bool) -> Result<u16, Error> {
        if wide {
            let v = u16_at(self.data, *at)?;
            *at += 2;
            Ok(v)
        } else {
            let v = *self.data.get(*at).ok_or(Error::Truncated)? as u16;
            *at += 1;
            Ok(v)
        }
    }

    fn read_offset(&self, at: &mut usize, wide: bool) -> Result<u32, Error> {
        if wide {
            let v = u32_at(self.data, *at)?;
            *at += 4;
            Ok(v)
        } else {
            let v = u16_at(self.data, *at)? as u32;
            *at += 2;
            Ok(v)
        }
    }

    pub fn fixups(&self) -> Result<Vec<Fixup>, Error> {
        let page_table = self.header.rel(self.header.fixup_pages)?;
        let records = self.header.rel(self.header.fixup_records)?;
        let page_table_len = (self.header.num_pages as usize + 1) * 4;
        self.data.get(page_table..page_table + page_table_len).ok_or(Error::Truncated)?;
        let mut out = Vec::new();
        for page in 0..self.header.num_pages {
            let first = u32_at(self.data, page_table + page as usize * 4)? as usize;
            let end = u32_at(self.data, page_table + (page as usize + 1) * 4)? as usize;
            if end < first { return Err(Error::BadTable); }
            let mut at = records.checked_add(first).ok_or(Error::BadTable)?;
            let limit = records.checked_add(end).ok_or(Error::BadTable)?;
            if limit > self.data.len() { return Err(Error::Truncated); }
            while at < limit {
                let source = *self.data.get(at).ok_or(Error::Truncated)?;
                let target_flags = *self.data.get(at + 1).ok_or(Error::Truncated)?;
                at += 2;
                if source & 0x20 != 0 { return Err(Error::Unsupported); }
                let source_offset = i16_at(self.data, at)?;
                at += 2;
                let wide_index = target_flags & 0x40 != 0;
                let wide_offset = target_flags & 0x10 != 0;
                let module_or_object = self.read_index(&mut at, wide_index)?;
                let target = match target_flags & 0x03 {
                    0 => Target::Internal {
                        object: module_or_object,
                        offset: self.read_offset(&mut at, wide_offset)?,
                    },
                    1 => Target::ImportOrdinal {
                        module: module_or_object,
                        ordinal: self.read_index(&mut at, target_flags & 0x80 == 0)?,
                    },
                    2 => Target::ImportName {
                        module: module_or_object,
                        name_offset: self.read_offset(&mut at, wide_offset)?,
                    },
                    _ => return Err(Error::Unsupported),
                };
                let additive = if target_flags & 0x04 != 0 {
                    self.read_offset(&mut at, target_flags & 0x20 != 0)?
                } else { 0 };
                out.push(Fixup {
                    page,
                    source_type: source & 0x0f,
                    source_offset,
                    target,
                    additive,
                });
            }
            if at != limit { return Err(Error::BadTable); }
        }
        Ok(out)
    }

    /// Object and offset corresponding to a zero-based global module page.
    pub fn page_location(&self, page: u32) -> Result<(u32, u32), Error> {
        for n in 1..=self.header.object_count {
            let object = self.object(n)?;
            let first = object.map_index.checked_sub(1).ok_or(Error::BadTable)?;
            if page >= first && page < first + object.map_count {
                return Ok((n, (page - first) * self.header.page_size));
            }
        }
        Err(Error::BadTable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    pub kind: u16,
    pub id: u16,
    pub size: u32,
    pub object: u16,
    pub offset: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(v: &mut [u8], at: usize, n: u16) { v[at..at + 2].copy_from_slice(&n.to_le_bytes()); }
    fn put32(v: &mut [u8], at: usize, n: u32) { v[at..at + 4].copy_from_slice(&n.to_le_bytes()); }

    #[test]
    fn rejects_mz_without_lx() {
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        put32(&mut data, 0x3c, 64);
        assert_eq!(Image::parse(&data).err(), Some(Error::BadMagic));
    }

    #[test]
    fn parses_minimal_lx_header_and_object() {
        let mut data = vec![0u8; 232];
        data[0..2].copy_from_slice(b"LX");
        put16(&mut data, 8, 2);
        put16(&mut data, 10, 1);
        put32(&mut data, 0x14, 1);
        put32(&mut data, 0x28, 4096);
        put32(&mut data, 0x40, 196);
        put32(&mut data, 0x44, 1);
        put32(&mut data, 0x48, 220);
        put32(&mut data, 196, 7);
        put32(&mut data, 200, 0x10000);
        put32(&mut data, 204, 0x2005);
        put32(&mut data, 208, 1);
        put32(&mut data, 212, 1);
        let image = Image::parse(&data).unwrap();
        let object = image.object(1).unwrap();
        assert_eq!(object.size, 7);
        assert_eq!(object.address, 0x10000);
        assert_eq!(object.map_index, 1);
    }
}
