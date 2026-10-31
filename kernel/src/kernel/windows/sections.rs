//! Read-only file sections. The DLL supplies NT policy; views own their pages.
use super::*;
use crate::kernel::vfs;
use alloc::sync::Arc;
struct Section {
    data: Vec<u8>,
    image: bool,
}
#[derive(Default)]
pub(super) struct State {
    handles: Vec<Option<Arc<Section>>>,
    views: Vec<u32>,
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    args: [u32; 6],
) -> u32 {
    let [op, handle, offset, size, flags, out] = args;
    if op == 0 {
        let Some(thread::FdKind::Vfs(file)) = kt.fds.get(handle as usize).copied() else {
            return 0xc0000008;
        };
        let length = vfs::file_size_by_handle(file);
        if length == 0 {
            return 0xc000011e;
        }
        if size != 0 && size > length {
            return 0xc0000040;
        }
        let length = if size == 0 { length } else { size };
        let saved = vfs::seek_by_handle(file, 0, 1);
        if saved < 0 || vfs::seek_by_handle(file, 0, 0) < 0 {
            return 0xc0000001;
        }
        let mut data = Vec::new();
        if data.try_reserve_exact(length as usize).is_err() {
            vfs::seek_by_handle(file, saved, 0);
            return 0xc0000017;
        }
        data.resize(length as usize, 0);
        let mut read = 0;
        while read < data.len() {
            let n = vfs::read_by_handle(file, &mut data[read..]);
            if n <= 0 {
                break;
            }
            read += n as usize;
        }
        vfs::seek_by_handle(file, saved, 0);
        if read != data.len() {
            return 0xc0000011;
        }
        let slot = state
            .sections
            .handles
            .iter()
            .position(Option::is_none)
            .unwrap_or(state.sections.handles.len());
        if slot == state.sections.handles.len() {
            state.sections.handles.push(None);
        }
        let image = flags & 0x1000000 != 0;
        if image {
            let Ok(parsed) = pe::Image::parse(&data) else {
                return 0xc000007b;
            };
            if parsed.header.section_alignment < 4096 {
                return 0xc00000bb;
            }
            if parsed.header.size_headers > parsed.header.size_image
                || parsed.header.size_headers as usize > data.len()
            {
                return 0xc000007b;
            }
            let Ok(sections) = parsed.sections() else {
                return 0xc000007b;
            };
            for section in sections {
                if section
                    .rva
                    .checked_add(section.virtual_size.max(section.raw_size))
                    .is_none_or(|end| end > parsed.header.size_image)
                    || section
                        .raw_offset
                        .checked_add(section.raw_size)
                        .is_none_or(|end| end as usize > data.len())
                {
                    return 0xc000007b;
                }
            }
        }
        state.sections.handles[slot] = Some(Arc::new(Section { data, image }));
        machine.write::<u32>(out as usize, 0x76000000 | slot as u32 * 4);
        return 0;
    }
    if op == 3 {
        let Some(index) = state.sections.views.iter().position(|&base| base == handle) else {
            return 0xc0000019;
        };
        memory::call(machine, state, Api::MemoryRelease, handle, 0, 1);
        state.sections.views.swap_remove(index);
        return 0;
    }
    let Some(index) = handle
        .checked_sub(0x76000000)
        .filter(|h| h % 4 == 0)
        .map(|h| h as usize / 4)
        .filter(|&i| state.sections.handles.get(i).is_some_and(Option::is_some))
    else {
        return 0xc0000008;
    };
    if op == 2 {
        state.sections.handles[index] = None;
        return 0;
    }
    let section = state.sections.handles[index].as_ref().unwrap().clone();
    if op == 4 {
        if !section.image {
            return 0xc0000049;
        }
        let image = pe::Image::parse(&section.data).unwrap();
        let opt = image.header.at + 24;
        let word = |at| u16::from_le_bytes(section.data[at..at + 2].try_into().unwrap()) as u32;
        let long = |at| u32::from_le_bytes(section.data[at..at + 4].try_into().unwrap());
        let info = [
            image.header.image_base.wrapping_add(image.header.entry_rva),
            0,
            image.header.stack_reserve,
            long(opt + 76),
            image.header.subsystem as u32,
            word(opt + 50) | (word(opt + 48) << 16),
            word(opt + 40) | (word(opt + 42) << 16),
            image.header.characteristics as u32 | (word(opt + 70) << 16),
            0x14c | ((long(opt + 4) != 0) as u32) << 16,
            0,
            section.data.len() as u32,
            long(opt + 64),
        ];
        for (i, value) in info.into_iter().enumerate() {
            machine.write::<u32>(out as usize + i * 4, value);
        }
        return 0;
    }
    if section.image {
        if op != 1 || offset != 0 {
            return 0xc000000d;
        }
        let image = pe::Image::parse(&section.data).unwrap();
        let Some(length) = image.header.size_image.checked_add(4095).map(|n| n & !4095) else {
            return 0xc000007b;
        };
        if size != 0 && size < length {
            return 0xc000001f;
        }
        let requested = machine.read::<u32>(out as usize);
        let mut base = memory::call(
            machine,
            state,
            Api::MemoryReserve,
            if requested == 0 {
                image.header.image_base
            } else {
                requested
            },
            length,
            0,
        );
        if base == 0 && requested == 0 {
            base = memory::call(machine, state, Api::MemoryReserve, 0, length, 0);
        }
        if base == 0 {
            return 0xc0000018;
        }
        if memory::call(machine, state, Api::MemoryCommit, base, length, 1) == 0 {
            memory::call(machine, state, Api::MemoryRelease, base, 0, 0);
            return 0xc0000017;
        }
        machine.copy_to(
            base as usize,
            &section.data[..image.header.size_headers as usize],
        );
        for part in image.sections().unwrap() {
            machine.copy_to(
                (base + part.rva) as usize,
                &section.data[part.raw_offset as usize..(part.raw_offset + part.raw_size) as usize],
            );
        }
        let _ = super::change_protection(machine, state, base, length, 2);
        for part in image.sections().unwrap() {
            let count = part.virtual_size.max(part.raw_size);
            if count == 0 {
                continue;
            }
            let access = match (
                part.characteristics & 0x80000000 != 0,
                part.characteristics & 0x20000000 != 0,
            ) {
                (false, false) => 2,
                (true, false) => 4,
                (false, true) => 0x20,
                (true, true) => 0x40,
            };
            let _ = super::change_protection(machine, state, base + part.rva, count, access);
        }
        memory::mark_image(state, base);
        state.sections.views.push(base);
        machine.write::<u32>(out as usize, base);
        machine.write::<u32>(out as usize + 4, length);
        return if base == image.header.image_base {
            0
        } else {
            0x40000003
        };
    }
    if op != 1 || offset & 65535 != 0 || !matches!(flags, 2 | 8) {
        return 0xc000000d;
    }
    let data = &section.data;
    if offset as usize >= data.len() {
        return 0xc0000020;
    }
    let available = (data.len() as u32 - offset + 4095) & !4095;
    let length = if size == 0 {
        available
    } else {
        let Some(n) = size
            .checked_add(4095)
            .map(|n| n & !4095)
            .filter(|&n| n <= available)
        else {
            return 0xc000001f;
        };
        n
    };
    let requested = machine.read::<u32>(out as usize);
    let base = memory::call(machine, state, Api::MemoryReserve, requested, length, 0);
    if base == 0 {
        return 0xc0000018;
    }
    if memory::call(machine, state, Api::MemoryCommit, base, length, 1) == 0 {
        memory::call(machine, state, Api::MemoryRelease, base, 0, 0);
        return 0xc0000017;
    }
    let count = (length as usize).min(data.len() - offset as usize);
    machine.copy_to(
        base as usize,
        &data[offset as usize..offset as usize + count],
    );
    let _ = super::change_protection(machine, state, base, length, if flags == 8 { 4 } else { 2 });
    memory::mark_mapped(state, base);
    state.sections.views.push(base);
    machine.write::<u32>(out as usize, base);
    machine.write::<u32>(out as usize + 4, length);
    0
}
