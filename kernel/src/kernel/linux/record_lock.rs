//! Linux fcntl record-lock layouts; ownership and intervals live in VFS.
use super::{Args, EINVAL, SyscallResult, thread, vfs};
use crate::kernel::fs::record_locks::Kind;

#[derive(Clone, Copy)]
pub(super) struct Request {
    handle: i32,
    owner: i32,
    kind: Option<Kind>,
    start: u64,
    end: u64,
    query: bool,
    blocking: bool,
    pointer: usize,
    layout: Layout,
}
#[derive(Clone, Copy)]
enum Layout {
    Native64,
    Packed64,
    Native32,
}
impl Request {
    pub fn read<A: crate::Arch>(
        machine: &A,
        kt: &thread::KernelThread<A>,
        args: &Args,
        native64: bool,
    ) -> Result<Self, i32> {
        let handle = match kt.fds.get(args.a0 as usize) {
            Some(thread::FdKind::Vfs(h)) => *h,
            _ => return Err(-9),
        };
        let cmd = args.a1 as u32;
        let layout = if native64 {
            Layout::Native64
        } else if matches!(cmd, 12..=14) {
            Layout::Packed64
        } else {
            Layout::Native32
        };
        let size = match layout {
            Layout::Native64 => 32,
            Layout::Packed64 => 24,
            Layout::Native32 => 16,
        };
        if args.a2 == 0 || args.a2.checked_add(size).is_none_or(|end| end > 0xc0000000) {
            return Err(-14);
        }
        let p = args.a2 as usize;
        let kind = match machine.read::<u16>(p) {
            0 => Some(Kind::Read),
            1 => Some(Kind::Write),
            2 => None,
            _ => return Err(-EINVAL),
        };
        let (offset, size) = vfs::record_lock_origin(handle)?;
        let origin = match machine.read::<u16>(p + 2) {
            0 => 0,
            1 => i64::from(offset),
            2 => i64::from(size),
            _ => return Err(-EINVAL),
        };
        let (start, length) = match layout {
            Layout::Native64 => (machine.read::<i64>(p + 8), machine.read::<i64>(p + 16)),
            Layout::Packed64 => (machine.read::<i64>(p + 4), machine.read::<i64>(p + 12)),
            Layout::Native32 => (
                i64::from(machine.read::<i32>(p + 4)),
                i64::from(machine.read::<i32>(p + 8)),
            ),
        };
        let start = origin.checked_add(start).ok_or(-75)?;
        let (start, end) = match length.cmp(&0) {
            core::cmp::Ordering::Equal => (start, u64::MAX),
            core::cmp::Ordering::Greater => (start, start.checked_add(length).ok_or(-75)? as u64),
            core::cmp::Ordering::Less => (start.checked_add(length).ok_or(-75)?, start as u64),
        };
        if start < 0 {
            return Err(-EINVAL);
        }
        let query = matches!(cmd, 5 | 12);
        if query && kind.is_none() {
            return Err(-EINVAL);
        }
        Ok(Self {
            handle,
            owner: kt.tid,
            kind,
            start: start as u64,
            end,
            query,
            blocking: matches!(cmd, 7 | 14),
            pointer: p,
            layout,
        })
    }
    /// Pending setters never access user memory, so another process can
    /// wake them while its own address space is active.
    pub fn acquire(self) -> Option<i32> {
        match vfs::record_lock(
            self.handle,
            self.owner,
            self.kind,
            self.start,
            self.end,
            false,
        ) {
            Err(-11) if self.blocking => None,
            Err(e) => Some(e),
            Ok(_) => Some(0),
        }
    }
    pub fn step<A: crate::Arch>(self, machine: &mut A) -> Option<i32> {
        if !self.query {
            return self.acquire();
        }
        match vfs::record_lock(
            self.handle,
            self.owner,
            self.kind,
            self.start,
            self.end,
            self.query,
        ) {
            Err(-11) if self.blocking => None,
            Err(e) => Some(e),
            Ok(conflict) => {
                if self.query {
                    if let Some(lock) = conflict {
                        let length = if lock.end == u64::MAX {
                            0
                        } else {
                            (lock.end - lock.start) as i64
                        };
                        let p = self.pointer;
                        if matches!(self.layout, Layout::Native32)
                            && (lock.start > i32::MAX as u64 || length > i64::from(i32::MAX))
                        {
                            return Some(-75);
                        }
                        machine.write::<u16>(p, if lock.kind == Kind::Read { 0 } else { 1 });
                        machine.write::<u16>(p + 2, 0);
                        match self.layout {
                            Layout::Native64 => {
                                machine.write::<i64>(p + 8, lock.start as i64);
                                machine.write::<i64>(p + 16, length);
                                machine.write::<i32>(p + 24, lock.owner);
                            }
                            Layout::Packed64 => {
                                machine.write::<i64>(p + 4, lock.start as i64);
                                machine.write::<i64>(p + 12, length);
                                machine.write::<i32>(p + 20, lock.owner);
                            }
                            Layout::Native32 => {
                                machine.write::<i32>(p + 4, lock.start as i32);
                                machine.write::<i32>(p + 8, length as i32);
                                machine.write::<i32>(p + 12, lock.owner);
                            }
                        }
                    } else {
                        machine.write::<u16>(self.pointer, 2);
                    }
                }
                Some(0)
            }
        }
    }
}

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    linux: &mut super::LinuxState,
    args: &Args,
    native64: bool,
) -> SyscallResult {
    match Request::read(machine, kt, args, native64) {
        Err(e) => SyscallResult::val(e),
        Ok(request) => match request.step(machine) {
            Some(n) => SyscallResult::val(n),
            None => {
                linux.pending_record_lock = Some(request);
                kt.state = thread::ThreadState::Blocked;
                SyscallResult::val(0)
            }
        },
    }
}
