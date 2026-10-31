//! Per-process window classes. Wine's portable code owns procedures and menus.
use super::*;
use alloc::sync::Arc;
pub(super) struct Class {
    pub(super) id: u64,
    name: Vec<u16>,
    atom: u32,
    local: bool,
    instance: u64,
    pub(super) client: u64,
    pub(super) win_extra: u32,
    pub(super) offset: u64,
    _atoms: Vec<Atom>,
}
impl Drop for Class {
    fn drop(&mut self) {
        session::release_object(self.offset);
    }
}
#[derive(Default)]
pub(super) struct State {
    entries: Vec<Arc<Class>>,
}
struct Atom(u32);
impl Drop for Atom {
    fn drop(&mut self) {
        let _ = atoms::USER.lock().delete(self.0 as u16);
    }
}
fn atom_for(name: &[u16]) -> Option<Atom> {
    let name = alloc::string::String::from_utf16(name).ok()?;
    atoms::USER
        .lock()
        .lookup(&name, true)
        .ok()
        .map(|a| Atom(u32::from(a)))
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 5],
) -> u32 {
    let [op, name, length, params, out] = args;
    if length > 510 || length & 1 != 0 {
        return 0xc000000d;
    }
    let p: [u32; 10] = core::array::from_fn(|i| machine.read::<u32>(params as usize + i * 4));
    let mut name: Vec<u16> = (0..length / 2)
        .map(|i| machine.read::<u16>((name + i * 2) as usize))
        .collect();
    if name.is_empty() && p[1] != 0 {
        name = alloc::format!("#{}", p[1]).encode_utf16().collect();
    }
    let canonical: Vec<u16> = alloc::string::String::from_utf16_lossy(&name)
        .to_lowercase()
        .encode_utf16()
        .collect();
    let instance = p[3] as u64 | ((p[4] as u64) << 32);
    if op == 1 {
        let Some(i) = state.classes.entries.iter().position(|c| {
            (if p[1] != 0 {
                c.atom == p[1]
            } else {
                c.name == canonical
            }) && (!c.local || c.instance == instance)
        }) else {
            return 0xc0010583;
        };
        if Arc::strong_count(&state.classes.entries[i]) != 1 {
            return 0xc0010584; // STATUS_CLASS_HAS_WINDOWS
        }
        machine.write::<u64>(out as usize + 24, state.classes.entries[i].client);
        state.classes.entries.remove(i);
        return 0;
    }
    if op != 0 || name.is_empty() || p[7] > 4096 || p[8] > 4096 || p[9] as usize > name.len() {
        return 0xc000000d;
    }
    let mut atoms = Vec::new();
    let atom = if p[1] != 0 {
        p[1]
    } else {
        let Some(a) = atom_for(&canonical) else {
            return 0xc000009a;
        };
        let id = a.0;
        atoms.push(a);
        id
    };
    if state
        .classes
        .entries
        .iter()
        .any(|c| c.atom == atom && c.local == (p[0] != 0) && (!c.local || c.instance == instance))
    {
        return 0xc0010582;
    }
    let base_atom = if p[9] != 0 {
        let Some(a) = atom_for(&canonical[p[9] as usize..]) else {
            return 0xc000009a;
        };
        let id = a.0;
        atoms.push(a);
        id
    } else {
        atom
    };
    let id = user_objects::next_id();
    let offset = session::allocate_object(machine, id);
    let mut data = vec![0u8; 544 + p[7] as usize];
    for (i, n) in [
        base_atom,
        p[2],
        p[7],
        p[8],
        p[3],
        p[4],
        p[9],
        name.len() as u32 * 2,
    ]
    .into_iter()
    .enumerate()
    {
        data[i * 4..i * 4 + 4].copy_from_slice(&n.to_le_bytes());
    }
    for (i, n) in name.iter().enumerate() {
        data[32 + i * 2..34 + i * 2].copy_from_slice(&n.to_le_bytes());
    }
    session::write_object(offset, &data);
    state.classes.entries.push(Arc::new(Class {
        id,
        name: canonical,
        atom,
        local: p[0] != 0,
        instance,
        win_extra: p[8],
        client: p[5] as u64 | ((p[6] as u64) << 32),
        offset,
        _atoms: atoms,
    }));
    machine.write::<u64>(out as usize, id);
    machine.write::<u64>(out as usize + 8, offset);
    machine.write::<u32>(out as usize + 16, base_atom);
    0
}

impl State {
    pub(super) fn desktop_classes(&self) -> Option<[Arc<Class>; 2]> {
        let top = self.entries.iter().find(|c| !c.local && c.atom == 32769)?;
        let message = self
            .entries
            .iter()
            .find(|c| !c.local && c.name == "message".encode_utf16().collect::<Vec<_>>())?;
        Some([top.clone(), message.clone()])
    }
}

impl Class {
    pub(super) fn is_desktop(&self) -> bool {
        self.atom == 32769 && !self.local
    }
}

impl State {
    pub(super) fn find(&self, atom: u32, name: &[u16], instance: u64) -> Option<Arc<Class>> {
        let name: Vec<u16> = alloc::string::String::from_utf16_lossy(name)
            .to_lowercase()
            .encode_utf16()
            .collect();
        self.entries
            .iter()
            .filter(|c| {
                if atom != 0 {
                    c.atom == atom
                } else {
                    c.name == name
                }
            })
            .find(|c| c.local && c.instance == instance)
            .or_else(|| {
                self.entries.iter().find(|c| {
                    !c.local
                        && if atom != 0 {
                            c.atom == atom
                        } else {
                            c.name == name
                        }
                })
            })
            .cloned()
    }
}
