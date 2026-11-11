//! Linux filesystem-type/accounting queries used before opening SQLite pools.
use super::*;

pub(super) fn call<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &LinuxState,
    a: &Args, wide: bool, descriptor: bool, large32: bool) -> SyscallResult
{
    let size = if wide { 120 } else if large32 { 84 } else { 64 };
    if large32 && a.a1 != size { return SyscallResult::val(-EINVAL); }
    let pointer = if large32 { a.a2 } else { a.a1 };
    if pointer == 0 || pointer.checked_add(size).is_none_or(|end| end > 0xc0000000) {
        return SyscallResult::val(-EFAULT);
    }
    let stats = if descriptor {
        match kt.fds.get(a.a0 as usize) {
            Some(thread::FdKind::Vfs(handle)) => vfs::fstatfs(*handle),
            Some(thread::FdKind::Dir { handle, .. }) => {
                let mut path = [0; vfs::DIR_PATH_MAX];
                vfs::dir_handle_path(*handle, &mut path).ok_or(-EBADF).and_then(|n| vfs::statfs(&path[..n]))
            },
            _ => Err(-EBADF),
        }
    } else {
        let mut raw = [0; vfs::PATH_KEY_MAX];
        let n = machine.copy_cstr(a.a0 as usize, &mut raw);
        if n == raw.len() { return SyscallResult::val(-36); }
        if n == 0 { return SyscallResult::val(-ENOENT); }
        let mut path = [0; vfs::PATH_KEY_MAX];
        vfs::statfs(resolve_path(&raw[..n], linux.cwd_str(), &mut path))
    };
    let stats = match stats { Ok(stats) => stats, Err(error) => return SyscallResult::val(error) };
    if !wide && !large32 && [stats.blocks, stats.free_blocks, stats.available_blocks, stats.files, stats.free_files]
        .iter().any(|value| *value > u64::from(u32::MAX)) { return SyscallResult::val(-75); }
    let pointer = pointer as usize;
    machine.zero(pointer, size as usize);
    if wide {
        for (i, value) in [stats.kind, stats.block_size, stats.blocks, stats.free_blocks,
            stats.available_blocks, stats.files, stats.free_files, stats.id, stats.name_max,
            stats.block_size, stats.flags].into_iter().enumerate() {
            machine.write::<u64>(pointer + i * 8, value);
        }
    } else {
        machine.write::<u32>(pointer, stats.kind as u32);
        machine.write::<u32>(pointer + 4, stats.block_size as u32);
        for (i, value) in [stats.blocks, stats.free_blocks, stats.available_blocks, stats.files, stats.free_files].into_iter().enumerate() {
            if large32 { machine.write::<u64>(pointer + 8 + i * 8, value); }
            else { machine.write::<u32>(pointer + 8 + i * 4, value as u32); }
        }
        let id_at = if large32 { 48 } else { 28 };
        machine.write::<u64>(pointer + id_at, stats.id);
        machine.write::<u32>(pointer + id_at + 8, stats.name_max as u32);
        machine.write::<u32>(pointer + id_at + 12, stats.block_size as u32);
        machine.write::<u32>(pointer + id_at + 16, stats.flags as u32);
    }
    SyscallResult::val(0)
}
