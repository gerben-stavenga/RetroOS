//! Session-global string atoms shared by Win16 and Win32 clients.
use alloc::{string::{String, ToString}, vec::Vec};
use crate::kernel::media::Shared;

pub(super) static GLOBAL: Shared<Table> = Shared::new(Table(Vec::new()));
struct Entry { name: String, key: String, references: u32 }
pub(super) struct Table(Vec<Option<Entry>>);

impl Table {
    pub fn lookup(&mut self, name: &str, add: bool) -> Result<u16, u32> {
        if name.is_empty() || name.encode_utf16().count() > 255 { return Err(87); }
        if let Some(number) = name.strip_prefix('#')
            && !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit())
        {
            let atom = number.parse::<u16>().map_err(|_| 87u32)?;
            return if (1..0xc000).contains(&atom) { Ok(atom) } else { Err(87) };
        }
        let key = name.to_uppercase();
        if let Some((index, entry)) = self.0.iter_mut().enumerate()
            .find_map(|(i, e)| e.as_mut().filter(|e| e.key == key).map(|e| (i, e)))
        {
            if add { entry.references = entry.references.checked_add(1).ok_or(8u32)?; }
            return Ok(0xc000 + index as u16);
        }
        if !add { return Err(2); }
        let index = self.0.iter().position(Option::is_none).unwrap_or(self.0.len());
        if index == 0x4000 { return Err(8); }
        let entry = Some(Entry { name: name.to_string(), key, references: 1 });
        if index == self.0.len() { self.0.push(entry); } else { self.0[index] = entry; }
        Ok(0xc000 + index as u16)
    }
    pub fn delete(&mut self, atom: u16) -> Result<(), u32> {
        if (1..0xc000).contains(&atom) { return Ok(()); }
        let slot = self.0.get_mut(atom.wrapping_sub(0xc000) as usize).ok_or(6u32)?;
        let entry = slot.as_mut().ok_or(6u32)?;
        entry.references -= 1;
        if entry.references == 0 { *slot = None; }
        Ok(())
    }
    pub fn name(&self, atom: u16) -> Result<String, u32> {
        if (1..0xc000).contains(&atom) { return Ok(alloc::format!("#{atom}")); }
        self.0.get(atom.wrapping_sub(0xc000) as usize).and_then(Option::as_ref)
            .map(|e| e.name.clone()).ok_or(6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn references_case_and_reuse() {
        let mut table = Table(Vec::new());
        let a = table.lookup("Installer", true).unwrap();
        assert!(a >= 0xc000);
        assert_eq!(table.lookup("INSTALLER", true), Ok(a));
        assert_eq!(table.name(a).unwrap(), "Installer");
        table.delete(a).unwrap();
        assert_eq!(table.lookup("installer", false), Ok(a));
        table.delete(a).unwrap();
        assert_eq!(table.lookup("Installer", false), Err(2));
        assert_eq!(table.name(a), Err(6));
        assert_eq!(table.lookup("Next", true), Ok(a));
    }
    #[test]
    fn integer_and_invalid_names() {
        let mut table = Table(Vec::new());
        assert_eq!(table.lookup("#1234", true), Ok(1234));
        assert_eq!(table.name(1234).unwrap(), "#1234");
        assert_eq!(table.delete(1234), Ok(()));
        for name in ["", "#0", "#49152", "#99999999"] {
            assert_eq!(table.lookup(name, true), Err(87));
        }
        assert_eq!(table.lookup(&"x".repeat(256), true), Err(87));
    }
}
