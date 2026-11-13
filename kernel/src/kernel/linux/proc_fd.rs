//! Process descriptor views must describe RetroOS, even when / is remote.
use super::{LinuxState, async_io, thread, vfs};
use alloc::{format, vec::Vec};
pub(super) type Metadata = (u32, u32, u64, Option<u32>);
const PREFIXES: [&[u8]; 3] = [b"proc/self/fd", b"proc/thread-self/fd", b"dev/fd"];
pub(super) fn is_dir(path: &[u8]) -> bool {
    PREFIXES.contains(&path)
}
fn fd_path(path: &[u8]) -> Option<Option<usize>> {
    match path {
        b"dev/stdin" => return Some(Some(0)),
        b"dev/stdout" => return Some(Some(1)),
        b"dev/stderr" => return Some(Some(2)),
        _ => {},
    }
    for prefix in PREFIXES {
        if let Some(name) = path
            .strip_prefix(prefix)
            .and_then(|tail| tail.strip_prefix(b"/"))
        {
            let mut number = 0usize;
            if name.is_empty() {
                return Some(None);
            }
            for &digit in name {
                if !digit.is_ascii_digit() {
                    return Some(None);
                }
                number = match number
                    .checked_mul(10)
                    .and_then(|n| n.checked_add((digit - b'0') as usize))
                {
                    Some(number) => number,
                    None => return Some(None),
                };
            }
            return Some(Some(number));
        }
    }
    None
}

/// Reopen the pipe object behind a descriptor link, retaining an endpoint
/// independently of the descriptor that named it. Bash process substitution
/// uses these opens rather than dup().
pub(super) fn open_pipe<A: crate::Arch>(
    kt: &mut thread::KernelThread<A>, path: &[u8], flags: u32,
) -> Option<i32> {
    let fd = fd_path(path)?;
    let Some(kind) = fd.and_then(|fd| kt.fds.get(fd)).copied().filter(|kind| !kind.is_none()) else {
        return Some(-2);
    };
    if flags & 0x20000 != 0 { return Some(-40); } // O_NOFOLLOW: descriptor links are symlinks.
    if flags & 0xc0 == 0xc0 { return Some(-17); } // O_CREAT | O_EXCL
    let pipe = match kind {
        thread::FdKind::PipeRead(pipe) | thread::FdKind::PipeWrite(pipe) => pipe,
        _ => return None,
    };
    if flags & 0x10000 != 0 { return Some(-20); } // O_DIRECTORY
    let writer = match flags & 3 { 0 => false, 1 => true, _ => return Some(-22) };
    let Some(newfd) = kt.alloc_fd(3) else { return Some(-24); };
    if writer {
        crate::kernel::kpipe::add_writer(pipe);
        kt.fds[newfd] = thread::FdKind::PipeWrite(pipe);
    } else {
        crate::kernel::kpipe::add_reader(pipe);
        kt.fds[newfd] = thread::FdKind::PipeRead(pipe);
    }
    kt.cloexec.set(newfd, flags & 0x80000 != 0);
    Some(newfd as i32)
}
fn absolute(path: &[u8]) -> Vec<u8> {
    [b"/".as_slice(), path].concat()
}
fn target<A: crate::Arch>(
    kt: &thread::KernelThread<A>,
    linux: &LinuxState,
    fd: usize,
) -> Option<Vec<u8>> {
    if fd >= thread::MAX_FDS {
        return async_io::proc_target(&linux.async_io, fd);
    }
    match kt.fds[fd] {
        thread::FdKind::None => None,
        thread::FdKind::Vfs(handle) => vfs::file_path_by_handle(handle).map(|path| absolute(&path)),
        thread::FdKind::Dir { handle, .. } => {
            let mut path = [0; vfs::DIR_PATH_MAX];
            vfs::dir_handle_path(handle, &mut path).map(|n| absolute(&path[..n]))
        }
        thread::FdKind::PipeRead(id) if id == thread::console_pipe() => Some(b"/dev/console".to_vec()),
        thread::FdKind::PipeRead(id) | thread::FdKind::PipeWrite(id) => {
            Some(format!("pipe:[{}]", id).into_bytes())
        }
        thread::FdKind::Socket(id) => Some(format!("socket:[{}]", id).into_bytes()),
        thread::FdKind::ConsoleOut => Some(b"/dev/console".to_vec()),
    }
}
pub(super) fn readlink<A: crate::Arch>(
    kt: &thread::KernelThread<A>,
    linux: &LinuxState,
    path: &[u8],
) -> Option<Option<Vec<u8>>> {
    fd_path(path).map(|fd| fd.and_then(|fd| target(kt, linux, fd)))
}
pub(super) fn stat<A: crate::Arch>(
    kt: &thread::KernelThread<A>,
    linux: &LinuxState,
    path: &[u8],
    follow: bool,
) -> Option<Option<Metadata>> {
    if is_dir(path) {
        return Some(Some((0o40500, 0, 0xf0000, None)));
    }
    let fd = fd_path(path)?;
    Some((|| {
        let fd = fd?;
        let path = target(kt, linux, fd)?;
        let ino = 0xf0001 + fd as u64;
        if !follow {
            return Some((0o120700, path.len() as u32, ino, None));
        }
        Some(match kt.fds.get(fd) {
            Some(thread::FdKind::Vfs(h)) => (
                super::mode_with_type(vfs::file_mode_by_handle(*h), 0o100000),
                vfs::file_size_by_handle(*h),
                vfs::file_ino_by_handle(*h),
                super::fd_mtime(kt, fd),
            ),
            Some(thread::FdKind::Dir { .. }) => (0o40500, 0, ino, None),
            Some(thread::FdKind::PipeRead(id)) if *id == thread::console_pipe() => (0o20666, 0, ino, None),
            Some(thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_)) => {
                (0o10600, 0, ino, None)
            }
            Some(thread::FdKind::Socket(_)) => (0o140600, 0, ino, None),
            _ => (0o20600, 0, ino, None),
        })
    })())
}

pub(super) fn getdents<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    linux: &LinuxState,
    cursor: &mut usize,
    out: usize,
    count: usize,
) -> i32 {
    let limit = 2 + thread::MAX_FDS + async_io::proc_slots(&linux.async_io);
    let mut written = 0;
    while *cursor < limit {
        let slot = *cursor;
        let name = if slot < 2 {
            if slot == 0 {
                b".".to_vec()
            } else {
                b"..".to_vec()
            }
        } else {
            let fd = if slot - 2 < thread::MAX_FDS {
                slot - 2
            } else {
                1024 + slot - 2 - thread::MAX_FDS
            };
            if target(kt, linux, fd).is_none() {
                *cursor += 1;
                continue;
            }
            format!("{}", fd).into_bytes()
        };
        let size = (19 + name.len() + 1 + 7) & !7;
        if size > count - written {
            return if written == 0 { -22 } else { written as i32 };
        }
        machine.zero(out + written, size);
        machine.write::<u64>(out + written, 0xf0000 + slot as u64);
        machine.write::<u64>(out + written + 8, (slot + 1) as u64);
        machine.write::<u16>(out + written + 16, size as u16);
        machine.write::<u8>(out + written + 18, if slot < 2 { 4 } else { 10 });
        machine.copy_to(out + written + 19, &name);
        written += size;
        *cursor += 1;
    }
    written as i32
}
