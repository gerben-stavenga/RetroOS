//! Bounds-checked parser for 32-bit Windows PE images.

extern crate alloc;

use alloc::{vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Truncated, BadMagic, Unsupported, BadTable }

fn u16_at(data: &[u8], at: usize) -> Result<u16, Error> {
    let b = data.get(at..at + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn put16(v: &mut [u8], at: usize, n: u16) { v[at..at + 2].copy_from_slice(&n.to_le_bytes()); }
    fn put32(v: &mut [u8], at: usize, n: u32) { v[at..at + 4].copy_from_slice(&n.to_le_bytes()); }

    #[test]
    fn rejects_mz_without_pe() {
        let mut data = vec![0u8; 128];
        data[..2].copy_from_slice(b"MZ");
        put32(&mut data, 0x3c, 64);
        assert_eq!(Image::parse(&data).err(), Some(Error::BadMagic));
    }

    #[test]
    fn parses_minimal_pe32_section() {
        let mut data = vec![0u8; 512];
        data[..4].copy_from_slice(b"PE\0\0");
        put16(&mut data, 4, 0x14c);
        put16(&mut data, 6, 1);
        put16(&mut data, 20, 224);
        put16(&mut data, 22, 0x102);
        let opt = 24;
        put16(&mut data, opt, 0x10b);
        put32(&mut data, opt + 16, 0x1000);
        put32(&mut data, opt + 28, 0x0040_0000);
        put32(&mut data, opt + 32, 4096);
        put32(&mut data, opt + 56, 0x2000);
        put32(&mut data, opt + 60, 512);
        put32(&mut data, opt + 72, 0x10000);
        put32(&mut data, opt + 92, 16);
        let section = opt + 224;
        put32(&mut data, section + 8, 16);
        put32(&mut data, section + 12, 0x1000);
        put32(&mut data, section + 16, 16);
        put32(&mut data, section + 20, 480);
        put32(&mut data, section + 36, 0x6000_0020);
        let image = Image::parse(&data).unwrap();
        assert_eq!(image.header.image_base, 0x0040_0000);
        assert_eq!(image.header.entry_rva, 0x1000);
        assert_eq!(image.section(0).unwrap().rva, 0x1000);
    }
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, Error> {
    let b = data.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[derive(Clone, Copy, Debug)]
pub struct Directory { pub rva: u32, pub size: u32 }

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub at: usize,
    pub sections: u16,
    pub characteristics: u16,
    pub entry_rva: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub size_image: u32,
    pub size_headers: u32,
    pub subsystem: u16,
    pub stack_reserve: u32,
    pub export: Directory,
    pub import: Directory,
    pub reloc: Directory,
    section_table: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Section {
    pub virtual_size: u32,
    pub rva: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug)]
pub enum ImportSymbol { Name(Vec<u8>), Ordinal(u16) }

#[derive(Clone, Debug)]
pub struct Import { pub module: Vec<u8>, pub symbol: ImportSymbol, pub iat_rva: u32 }

#[derive(Clone, Debug)]
pub struct Export { pub name: Vec<u8>, pub ordinal: u16, pub rva: u32 }

pub struct Image<'a> { data: &'a [u8], pub header: Header }

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let at = if data.get(0..4) == Some(b"PE\0\0") {
            0
        } else if data.get(0..2) == Some(b"MZ") {
            u32_at(data, 0x3c)? as usize
        } else { return Err(Error::BadMagic) };
        if data.get(at..at + 4) != Some(b"PE\0\0") { return Err(Error::BadMagic); }
        if u16_at(data, at + 4)? != 0x14c { return Err(Error::Unsupported); }
        let sections = u16_at(data, at + 6)?;
        let optional_size = u16_at(data, at + 20)? as usize;
        let characteristics = u16_at(data, at + 22)?;
        let opt = at.checked_add(24).ok_or(Error::BadTable)?;
        if optional_size < 96 || u16_at(data, opt)? != 0x10b { return Err(Error::Unsupported); }
        data.get(opt..opt + optional_size).ok_or(Error::Truncated)?;
        let dir_count = u32_at(data, opt + 92)?.min(16) as usize;
        let directory = |n: usize| -> Result<Directory, Error> {
            if n >= dir_count { return Ok(Directory { rva: 0, size: 0 }); }
            Ok(Directory { rva: u32_at(data, opt + 96 + n * 8)?, size: u32_at(data, opt + 100 + n * 8)? })
        };
        let section_table = opt.checked_add(optional_size).ok_or(Error::BadTable)?;
        let table_size = sections as usize * 40;
        data.get(section_table..section_table.checked_add(table_size).ok_or(Error::BadTable)?)
            .ok_or(Error::Truncated)?;
        let header = Header {
            at, sections, characteristics,
            entry_rva: u32_at(data, opt + 16)?,
            image_base: u32_at(data, opt + 28)?,
            section_alignment: u32_at(data, opt + 32)?,
            size_image: u32_at(data, opt + 56)?,
            size_headers: u32_at(data, opt + 60)?,
            subsystem: u16_at(data, opt + 68)?,
            stack_reserve: u32_at(data, opt + 72)?,
            export: directory(0)?, import: directory(1)?, reloc: directory(5)?,
            section_table,
        };
        if header.size_image == 0 || header.size_image >= 0xc000_0000
            || header.section_alignment == 0 || !header.section_alignment.is_power_of_two()
        { return Err(Error::Unsupported); }
        Ok(Self { data, header })
    }

    pub fn is_dll(&self) -> bool { self.header.characteristics & 0x2000 != 0 }

    pub fn is_windows_application(&self) -> bool {
        !self.is_dll() && matches!(self.header.subsystem, 2 | 3)
    }

    pub fn section(&self, n: usize) -> Result<Section, Error> {
        if n >= self.header.sections as usize { return Err(Error::BadTable); }
        let at = self.header.section_table + n * 40;
        Ok(Section {
            virtual_size: u32_at(self.data, at + 8)?, rva: u32_at(self.data, at + 12)?,
            raw_size: u32_at(self.data, at + 16)?, raw_offset: u32_at(self.data, at + 20)?,
            characteristics: u32_at(self.data, at + 36)?,
        })
    }

    pub fn sections(&self) -> Result<Vec<Section>, Error> {
        (0..self.header.sections as usize).map(|n| self.section(n)).collect()
    }

    fn rva_offset(&self, rva: u32, size: usize) -> Result<usize, Error> {
        if rva < self.header.size_headers {
            let at = rva as usize;
            return self.data.get(at..at.checked_add(size).ok_or(Error::BadTable)?)
                .map(|_| at).ok_or(Error::Truncated);
        }
        for section in self.sections()? {
            let extent = section.virtual_size.max(section.raw_size);
            if rva >= section.rva && rva.checked_add(size as u32).is_some_and(|end| end <= section.rva.saturating_add(extent)) {
                let within = rva - section.rva;
                if within.checked_add(size as u32).is_none_or(|end| end > section.raw_size) { return Err(Error::Truncated); }
                let at = section.raw_offset as usize + within as usize;
                return self.data.get(at..at + size).map(|_| at).ok_or(Error::Truncated);
            }
        }
        Err(Error::BadTable)
    }

    pub fn bytes_at_rva(&self, rva: u32, size: usize) -> Result<&'a [u8], Error> {
        let at = self.rva_offset(rva, size)?;
        self.data.get(at..at + size).ok_or(Error::Truncated)
    }

    pub fn c_string(&self, rva: u32) -> Result<Vec<u8>, Error> {
        let at = self.rva_offset(rva, 1)?;
        let tail = &self.data[at..];
        let n = tail.iter().position(|&b| b == 0).ok_or(Error::Truncated)?;
        if n > 1024 { return Err(Error::BadTable); }
        Ok(tail[..n].to_vec())
    }

    pub fn imports(&self) -> Result<Vec<Import>, Error> {
        let mut out = Vec::new();
        if self.header.import.rva == 0 { return Ok(out); }
        for descriptor in 0..4096usize {
            let d = self.bytes_at_rva(self.header.import.rva + descriptor as u32 * 20, 20)?;
            let get = |n| u32::from_le_bytes([d[n], d[n + 1], d[n + 2], d[n + 3]]);
            let lookup = get(0); let name_rva = get(12); let iat = get(16);
            if lookup == 0 && name_rva == 0 && iat == 0 { return Ok(out); }
            let module = self.c_string(name_rva)?;
            let table = if lookup != 0 { lookup } else { iat };
            for n in 0..65536u32 {
                let raw = self.bytes_at_rva(table + n * 4, 4)?;
                let value = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                if value == 0 { break; }
                let symbol = if value & 0x8000_0000 != 0 {
                    ImportSymbol::Ordinal(value as u16)
                } else {
                    ImportSymbol::Name(self.c_string(value.checked_add(2).ok_or(Error::BadTable)?)?)
                };
                out.push(Import { module: module.clone(), symbol, iat_rva: iat + n * 4 });
            }
        }
        Err(Error::BadTable)
    }

    pub fn exports(&self) -> Result<Vec<Export>, Error> {
        let mut out = Vec::new();
        if self.header.export.rva == 0 { return Ok(out); }
        let d = self.bytes_at_rva(self.header.export.rva, 40)?;
        let get = |n| u32::from_le_bytes([d[n], d[n + 1], d[n + 2], d[n + 3]]);
        let ordinal_base = get(16);
        let function_count = get(20);
        let name_count = get(24);
        let functions = get(28); let names = get(32); let ordinals = get(36);
        for n in 0..name_count {
            let nr = self.bytes_at_rva(names + n * 4, 4)?;
            let name_rva = u32::from_le_bytes([nr[0], nr[1], nr[2], nr[3]]);
            let oi = self.bytes_at_rva(ordinals + n * 2, 2)?;
            let index = u16::from_le_bytes([oi[0], oi[1]]) as u32;
            if index >= function_count { return Err(Error::BadTable); }
            let fr = self.bytes_at_rva(functions + index * 4, 4)?;
            let rva = u32::from_le_bytes([fr[0], fr[1], fr[2], fr[3]]);
            out.push(Export { name: self.c_string(name_rva)?, ordinal: (ordinal_base + index) as u16, rva });
        }
        Ok(out)
    }

    pub fn reloc_blocks(&self) -> Result<Vec<(u32, Vec<u16>)>, Error> {
        let mut out = Vec::new();
        if self.header.reloc.rva == 0 { return Ok(out); }
        let mut consumed = 0u32;
        while consumed < self.header.reloc.size {
            let h = self.bytes_at_rva(self.header.reloc.rva + consumed, 8)?;
            let page = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
            if size < 8 || size > self.header.reloc.size - consumed { return Err(Error::BadTable); }
            let mut entries = Vec::new();
            for n in 0..(size - 8) / 2 {
                let e = self.bytes_at_rva(self.header.reloc.rva + consumed + 8 + n * 2, 2)?;
                entries.push(u16::from_le_bytes([e[0], e[1]]));
            }
            out.push((page, entries));
            consumed += size;
        }
        Ok(out)
    }
}
