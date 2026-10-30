//! Palette-device state shared by the Win16 and Win32 GDI entry points.
//! Logical entries are mapped to device slots, not used as device indices.
//! https://learn.microsoft.com/en-us/windows/win32/gdi/system-palette-and-static-colors
extern crate alloc;
use alloc::vec::Vec;

const STATIC: [u32; 20] = [
    0x000000, 0x000080, 0x008000, 0x008080, 0x800000, 0x800080, 0x808000, 0xc0c0c0, 0xc0dcc0,
    0xf0caa6, 0xf0fbff, 0xa4a0a0, 0x808080, 0x0000ff, 0x00ff00, 0x00ffff, 0xff0000, 0xff00ff,
    0xffff00, 0xffffff,
];

#[derive(Clone, Copy, PartialEq)]
enum Use {
    Free,
    Static,
    Shared,
    Reserved,
}

pub struct Device {
    pub colors: [u32; 256],
    usage: [Use; 256],
    owner: [u32; 256],
    mappings: Vec<(u32, Vec<u8>)>,
}

impl Device {
    pub const fn new() -> Self {
        let mut colors = [0; 256];
        let mut usage = [Use::Free; 256];
        let mut i = 0;
        while i < 20 {
            let slot = if i < 10 { i } else { i + 236 };
            colors[slot] = STATIC[i];
            usage[slot] = Use::Static;
            i += 1;
        }
        Self {
            colors,
            usage,
            owner: [0; 256],
            mappings: Vec::new(),
        }
    }

    fn referenced_by_other(&self, palette: u32, slot: usize) -> bool {
        self.mappings
            .iter()
            .any(|(id, slots)| *id != palette && slots.contains(&(slot as u8)))
    }

    pub fn remove(&mut self, palette: u32) {
        self.mappings.retain(|(id, _)| *id != palette);
        for slot in 10..246 {
            if !self
                .mappings
                .iter()
                .any(|(_, slots)| slots.contains(&(slot as u8)))
            {
                self.usage[slot] = Use::Free;
                self.owner[slot] = 0;
            }
        }
    }

    fn nearest(&self, color: u32) -> u8 {
        (0..256)
            .filter(|&i| matches!(self.usage[i], Use::Static | Use::Shared))
            .min_by_key(|&i| {
                [0, 8, 16]
                    .iter()
                    .map(|shift| {
                        let difference = ((color >> shift) & 255) as i32
                            - ((self.colors[i] >> shift) & 255) as i32;
                        difference * difference
                    })
                    .sum::<i32>()
            })
            .unwrap_or(0) as u8
    }

    pub fn realize(&mut self, palette: u32, entries: &[u32], foreground: bool) -> u32 {
        for slot in 10..246 {
            if foreground
                || (self.owner[slot] == palette && !self.referenced_by_other(palette, slot))
            {
                self.usage[slot] = Use::Free;
                self.owner[slot] = 0;
            }
        }
        let mut mapping = Vec::with_capacity(entries.len());
        for &entry in entries {
            let flags = entry >> 24;
            let color = entry & 0xffffff;
            let matched = if flags & 5 == 0 {
                (0..256).find(|&i| {
                    self.colors[i] == color && matches!(self.usage[i], Use::Static | Use::Shared)
                })
            } else {
                None
            };
            let slot = if flags & 2 != 0 {
                // PC_EXPLICIT's low WORD names a device slot directly.
                (entry & 0xffff).min(255) as u8
            } else if let Some(slot) = matched {
                slot as u8
            } else if let Some(slot) = (10..246).find(|&i| self.usage[i] == Use::Free) {
                self.colors[slot] = color;
                self.usage[slot] = if flags & 1 != 0 {
                    Use::Reserved
                } else {
                    Use::Shared
                };
                self.owner[slot] = palette;
                slot as u8
            } else {
                self.nearest(color)
            };
            mapping.push(slot);
        }
        if let Some((_, old)) = self.mappings.iter_mut().find(|(id, _)| *id == palette) {
            let changed = mapping
                .iter()
                .enumerate()
                .filter(|(i, slot)| old.get(*i) != Some(*slot))
                .count();
            *old = mapping;
            changed as u32
        } else {
            let changed = mapping.len() as u32;
            self.mappings.push((palette, mapping));
            changed
        }
    }

    pub fn animate(&mut self, palette: u32, logical: &mut [u32], start: usize, entries: &[u32]) {
        let mapping = self
            .mappings
            .iter()
            .find(|(id, _)| *id == palette)
            .map(|(_, m)| m);
        for (i, &color) in entries.iter().enumerate() {
            let Some(old) = logical.get_mut(start + i) else {
                break;
            };
            if *old & 0x01000000 == 0 {
                continue;
            }
            *old = (*old & 0xff000000) | (color & 0xffffff);
            if let Some(&slot) = mapping.and_then(|m| m.get(start + i)) {
                let slot = slot as usize;
                if self.owner[slot] == palette && self.usage[slot] == Use::Reserved {
                    self.colors[slot] = color & 0xffffff;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_colors_are_distinct_and_leave_static_slots_untouched() {
        let mut device = Device::new();
        let initial = device.colors;
        let mut entries = alloc::vec![0x01000000; 236];
        assert_eq!(device.realize(1, &entries, true), 236);
        assert_eq!(device.mappings[0].1, (10..246).collect::<Vec<u8>>());
        entries[0] = 0x010000ff;
        entries[235] = 0x0100ff00;
        assert_eq!(device.realize(1, &entries, true), 0);
        assert_eq!(device.colors[10], 0xff);
        assert_eq!(device.colors[245], 0xff00);
        assert_eq!(&device.colors[..10], &initial[..10]);
        assert_eq!(&device.colors[246..], &initial[246..]);
    }

    #[test]
    fn animation_changes_only_reserved_entries_and_explicit_indices_are_not_colors() {
        let mut device = Device::new();
        let mut logical = [0x01000000, 0x000000ff, 0x020000ff];
        device.realize(7, &logical, true);
        assert_eq!(device.mappings[0].1, [10, 249, 255]);
        device.animate(7, &mut logical, 0, &[0xabcdef, 0x123456, 0x567890]);
        assert_eq!(logical, [0x01abcdef, 0xff, 0x020000ff]);
        assert_eq!(device.colors[10], 0xabcdef);
        assert_eq!(device.colors[255], 0xffffff);
    }

    #[test]
    fn background_realization_does_not_take_another_palettes_reserved_slots() {
        let mut device = Device::new();
        device.realize(1, &[0x010000ff], true);
        device.realize(2, &[0x0100ff00], false);
        assert_eq!(device.mappings[1].1, [11]);
        assert_eq!(device.colors[10], 0xff);
        device.remove(1);
        device.realize(3, &[0x01ff0000], false);
        assert_eq!(device.mappings[1].1, [10]);
    }
}
