//! Session-global string atoms shared by Win16 and Win32 clients.
use crate::kernel::media::Shared;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

pub(super) static USER: Shared<Table> = Shared::new(Table(Vec::new()));

pub(super) static GLOBAL: Shared<Table> = Shared::new(Table(Vec::new()));
struct Entry {
    name: String,
    key: String,
    references: u32,
}
pub(super) struct Table(Vec<Option<Entry>>);

impl Table {
    pub fn lookup(&mut self, name: &str, add: bool) -> Result<u16, u32> {
        if name.is_empty() || name.encode_utf16().count() > 255 {
            return Err(87);
        }
        if let Some(number) = name.strip_prefix('#')
            && !number.is_empty()
            && number.bytes().all(|c| c.is_ascii_digit())
        {
            let atom = number.parse::<u16>().map_err(|_| 87u32)?;
            return if (1..0xc000).contains(&atom) {
                Ok(atom)
            } else {
                Err(87)
            };
        }
        self.lookup_string(name, add)
    }
    fn lookup_string(&mut self, name: &str, add: bool) -> Result<u16, u32> {
        if name.is_empty() || name.encode_utf16().count() > 255 {
            return Err(87);
        }
        let key = name.to_uppercase();
        if let Some((index, entry)) = self
            .0
            .iter_mut()
            .enumerate()
            .find_map(|(i, e)| e.as_mut().filter(|e| e.key == key).map(|e| (i, e)))
        {
            if add {
                entry.references = entry.references.checked_add(1).ok_or(8u32)?;
            }
            return Ok(0xc000 + index as u16);
        }
        if !add {
            return Err(2);
        }
        let index = self
            .0
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.0.len());
        if index == 0x4000 {
            return Err(8);
        }
        let entry = Some(Entry {
            name: name.to_string(),
            key,
            references: 1,
        });
        if index == self.0.len() {
            self.0.push(entry);
        } else {
            self.0[index] = entry;
        }
        Ok(0xc000 + index as u16)
    }
    pub fn delete(&mut self, atom: u16) -> Result<(), u32> {
        if (1..0xc000).contains(&atom) {
            return Ok(());
        }
        let slot = self
            .0
            .get_mut(atom.wrapping_sub(0xc000) as usize)
            .ok_or(6u32)?;
        let entry = slot.as_mut().ok_or(6u32)?;
        entry.references -= 1;
        if entry.references == 0 {
            *slot = None;
        }
        Ok(())
    }
    pub fn name(&self, atom: u16) -> Result<String, u32> {
        if (1..0xc000).contains(&atom) {
            return Ok(alloc::format!("#{atom}"));
        }
        self.0
            .get(atom.wrapping_sub(0xc000) as usize)
            .and_then(Option::as_ref)
            .map(|e| e.name.clone())
            .ok_or(6)
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

/// NT layout marshalling remains in RETROOS.DLL; reuse the shared atom table.
pub(super) fn call<A: crate::Arch>(machine: &mut A, args: [u32; 5]) -> u32 {
    let [op, atom, name, length, out] = args;
    if length > 510 || length & 1 != 0 {
        return 0xc000000d;
    }
    // USER atoms (registered messages/classes) share a distinct namespace from
    // the NT global atom table. Keep the marshalling common to both.
    let user = op & 0x100 != 0;
    let mut table = if user { USER.lock() } else { GLOBAL.lock() };
    let op = op & !0x100;
    let translate = |e| match e {
        2 => 0xc0000034,
        6 => 0xc0000008,
        8 => 0xc000009a,
        _ => 0xc000000d,
    };
    let atom = if op <= 1 {
        let units: Vec<u16> = (0..length / 2)
            .map(|i| machine.read::<u16>((name + i * 2) as usize))
            .collect();
        let Ok(name) = String::from_utf16(&units) else {
            return 0xc0000033;
        };
        match if user { table.lookup_string(&name, op == 0) } else { table.lookup(&name, op == 0) } {
            Ok(a) => a,
            Err(e) => return translate(e),
        }
    } else {
        if atom > 65535 {
            return 0xc0000008;
        }
        atom as u16
    };
    if op == 2 {
        return table.delete(atom).map_or_else(translate, |_| 0);
    }
    if op > 3 {
        return 0xc000000d;
    }
    let name = match table.name(atom) {
        Ok(n) => n,
        Err(e) => return translate(e),
    };
    let refs = if atom < 0xc000 {
        1
    } else {
        table.0[(atom - 0xc000) as usize]
            .as_ref()
            .unwrap()
            .references
    };
    let units: Vec<u16> = name.encode_utf16().collect();
    machine.write::<u32>(out as usize, u32::from(atom));
    machine.write::<u32>(out as usize + 4, refs);
    machine.write::<u32>(out as usize + 8, units.len() as u32 * 2);
    for (i, c) in units.iter().enumerate() {
        machine.write::<u16>(out as usize + 12 + i * 2, *c);
    }
    0
}
