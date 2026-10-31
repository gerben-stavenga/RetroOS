//! File primitives for RETROOS.DLL. NT layouts and policy live in the DLL.
use super::*;
use crate::kernel::vfs;

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    args: [u32; 7],
) -> u32 {
    let [op, fd, data, length, offset, flags, out] = args;
    if op == 0 || op == 4 || op == 6 {
        let disposition = if op == 0 || op == 6 { 1 } else { flags >> 24 };
        if disposition > 5 {
            return 0xc000000d;
        }
        let can_create = matches!(disposition, 0 | 2 | 3 | 5);
        if length > 32766 || length & 1 != 0 {
            return 0xc000000d;
        }
        let units: Vec<u16> = (0..length / 2)
            .map(|i| machine.read::<u16>((data + i * 2) as usize))
            .collect();
        let Ok(path) = alloc::string::String::from_utf16(&units) else {
            return 0xc0000033;
        };
        let Ok(path) = windows_path(state, path.as_bytes(), can_create) else {
            return 0xc0000034;
        };
        let stat = vfs::stat(&path, true);
        if op == 6 {
            let Some(stat) = stat else {
                return 0xc0000034;
            };
            for (i, value) in [
                stat.size,
                if stat.is_dir { 0x10 } else { 0x20 },
                stat.mtime.unwrap_or(0),
            ]
            .into_iter()
            .enumerate()
            {
                machine.write::<u32>(out as usize + i * 4, value);
            }
            return 0;
        }
        let existed = stat.is_some();
        let directory = stat.as_ref().is_some_and(|s| s.is_dir);
        if !existed && !can_create {
            return 0xc0000034;
        }
        if existed && disposition == 2 {
            return 0xc0000035;
        }
        if flags & 1 != 0 && !directory {
            return if existed { 0xc0000103 } else { 0xc00000bb };
        }
        if flags & 0x40 != 0 && directory {
            return 0xc00000ba;
        }
        let truncate = existed && matches!(disposition, 0 | 4 | 5);
        if truncate && (directory || fd & (0x40000000 | 2) == 0) {
            return 0xc0000022;
        }
        let Some(slot) = kt.alloc_fd(3) else {
            return 0xc000011f;
        };
        let kind = if directory {
            let handle = vfs::open_dir_handle(&path);
            if handle < 0 {
                return 0xc000009a;
            }
            thread::FdKind::Dir { handle, next: 0 }
        } else {
            let handle = if existed {
                vfs::open_to_handle(&path)
            } else {
                vfs::create_to_handle(&path)
            };
            if handle < 0 {
                return 0xc0000022;
            }
            thread::FdKind::Vfs(handle)
        };
        kt.fds[slot] = kind;
        if !directory {
            let access = match (fd & (0x80000000 | 1) != 0, fd & (0x40000000 | 6) != 0) {
                (true, true) => vfs::OpenAccess::ReadWrite,
                (false, true) => vfs::OpenAccess::Write,
                _ => vfs::OpenAccess::Read,
            };
            let share = match offset & 3 {
                0 => vfs::SharePolicy::DenyAll,
                1 => vfs::SharePolicy::DenyWrite,
                2 => vfs::SharePolicy::DenyRead,
                _ => vfs::SharePolicy::DenyNone,
            };
            if vfs::configure_open(slot as i32, access, share, &kt.fds) < 0 {
                kt.close_fd(slot);
                return 0xc0000043;
            }
        }
        if truncate && let thread::FdKind::Vfs(handle) = kind {
            if vfs::resize_by_handle(handle, 0) < 0 {
                kt.close_fd(slot);
                return 0xc0000022;
            }
        }
        machine.write::<u32>(out as usize, slot as u32);
        machine.write::<u32>(
            out as usize + 4,
            if !existed {
                2
            } else if truncate {
                if disposition == 0 { 0 } else { 3 }
            } else {
                1
            },
        );
        return 0;
    }
    let Some(kind) = kt.fds.get(fd as usize).copied().filter(|f| !f.is_none()) else {
        return 0xc0000008;
    };
    // Stateless enumeration: userspace owns the NT mask and cursor.
    if op == 5 {
        let thread::FdKind::Dir { handle, .. } = kind else {
            return 0xc0000103;
        };
        let mut path = [0; vfs::DIR_PATH_MAX];
        let Some(n) = vfs::dir_handle_path(handle, &mut path) else {
            return 0xc0000008;
        };
        let Some(entry) = vfs::readdir(&path[..n], offset as usize) else {
            return 0x80000006;
        };
        let name = encoding::encode(&entry.name[..entry.name_len], true);
        let short: Vec<u16> = entry
            .short_name
            .as_ref()
            .map(|s| {
                crate::kernel::text::Encoding::oem()
                    .decode(s.as_bytes(), false)
                    .unwrap()
                    .encode_utf16()
                    .collect()
            })
            .unwrap_or_default();
        if name.len() > 255 || short.len() > 12 {
            return 0xc0000106;
        }
        machine.zero(out as usize, 556);
        let attributes =
            u32::from(
                entry
                    .dos_attributes
                    .unwrap_or(if entry.is_dir { 0x10 } else { 0x20 }),
            );
        for (i, value) in [
            entry.size,
            attributes,
            entry.mtime,
            name.len() as u32 * 2,
            short.len() as u32 * 2,
        ]
        .into_iter()
        .enumerate()
        {
            machine.write::<u32>(out as usize + i * 4, value);
        }
        for (i, value) in name.into_iter().enumerate() {
            machine.write::<u16>(out as usize + 20 + i * 2, value);
        }
        for (i, value) in short.into_iter().enumerate() {
            machine.write::<u16>(out as usize + 532 + i * 2, value);
        }
        return 0;
    }
    if op == 1 {
        kt.close_fd(fd as usize);
        return 0;
    }
    if matches!(op, 7 | 8 | 9 | 10) {
        let thread::FdKind::Vfs(handle) = kind else {
            return 0xc0000008;
        };
        if matches!(op, 8 | 9)
            && matches!(
                vfs::handle_open_access(handle),
                Some(vfs::OpenAccess::Read) | None
            )
        {
            return 0xc0000022;
        }
        let result = match op {
            7 => {
                if offset > i32::MAX as u32 {
                    return 0xc000000d;
                }
                vfs::seek_by_handle(handle, offset as i32, 0)
            }
            8 => {
                if length > 16 * 1024 * 1024 {
                    return 0xc000000d;
                }
                if flags & 1 != 0 {
                    if vfs::seek_by_handle(handle, 0, 2) < 0 {
                        return 0xc000000d;
                    }
                } else if offset != u32::MAX
                    && (offset > i32::MAX as u32
                        || vfs::seek_by_handle(handle, offset as i32, 0) < 0)
                {
                    return 0xc000000d;
                }
                let mut buffer = vec![0; length as usize];
                machine.copy_from(data as usize, &mut buffer);
                let n = vfs::write_by_handle(machine, handle, &buffer);
                if n >= 0 {
                    machine.write::<u32>(out as usize, n as u32);
                }
                n
            }
            9 => {
                if offset > i32::MAX as u32 {
                    return 0xc000000d;
                }
                vfs::resize_by_handle(handle, offset)
            }
            _ => vfs::flush_by_handle(handle),
        };
        return match result {
            n if n >= 0 => 0,
            -13 | -30 | -9 => 0xc0000022,
            -28 => 0xc000007f,
            -16 => 0xc0000243,
            -22 => 0xc000000d,
            _ => 0xc0000001,
        };
    }
    if op == 2 {
        let thread::FdKind::Vfs(handle) = kind else {
            return 0xc0000008;
        };
        if matches!(
            vfs::handle_open_access(handle),
            Some(vfs::OpenAccess::Write) | None
        ) {
            return 0xc0000022;
        }
        if length > 16 * 1024 * 1024 {
            return 0xc000000d;
        }
        if offset != u32::MAX && vfs::seek_by_handle(handle, offset as i32, 0) < 0 {
            return 0xc000000d;
        }
        let mut buffer = vec![0; length as usize];
        let n = vfs::read_by_handle(handle, &mut buffer);
        if n < 0 {
            return 0xc0000001;
        }
        machine.copy_to(data as usize, &buffer[..n as usize]);
        machine.write::<u32>(out as usize, n as u32);
        return if n == 0 && length != 0 { 0xc0000011 } else { 0 };
    }
    if op == 3 {
        let (size, position, directory) = match kind {
            thread::FdKind::Vfs(handle) => (
                vfs::file_size_by_handle(handle),
                vfs::seek_by_handle(handle, 0, 1) as u32,
                0,
            ),
            thread::FdKind::Dir { .. } => (0, 0, 1),
            _ => return 0xc0000008,
        };
        for (i, word) in [size, position, directory].into_iter().enumerate() {
            machine.write::<u32>(out as usize + i * 4, word);
        }
        return 0;
    }
    0xc000000d
}
