//! Bounded vectored reads with an iovec snapshot retained across pipe waits.
use super::*;

#[derive(Clone, Copy)]
enum Source { File(i32), Pipe(u8) }

pub(super) struct Request {
    source: Source,
    regions: alloc::vec::Vec<(usize, usize)>,
    length: usize,
}

impl Request {
    pub fn new<A: crate::Arch>(machine: &A, kt: &thread::KernelThread<A>, a: &Args, wide: bool) -> Result<Self, i32> {
        let source = match kt.fds.get(a.a0 as usize) {
            Some(FdKind::Vfs(handle)) => Source::File(*handle),
            Some(FdKind::PipeRead(pipe)) => Source::Pipe(*pipe),
            Some(FdKind::Socket(_)) => return Err(-95),
            Some(FdKind::Dir { .. }) => return Err(-21),
            _ => return Err(-EBADF),
        };
        let count = usize::try_from(a.a2).map_err(|_| -EINVAL)?;
        if count > 1024 { return Err(-EINVAL); }
        let stride = if wide { 16 } else { 8 };
        if count != 0 && (a.a1 == 0 || a.a1.checked_add((count * stride) as u64).is_none_or(|end| end > 0xc0000000)) {
            return Err(-EFAULT);
        }
        let mut regions = alloc::vec::Vec::new();
        let mut length = 0usize;
        for index in 0..count {
            let entry = a.a1 as usize + index * stride;
            let (pointer, size) = if wide {
                (machine.read::<u64>(entry), machine.read::<u64>(entry + 8))
            } else {
                (u64::from(machine.read::<u32>(entry)), u64::from(machine.read::<u32>(entry + 4)))
            };
            if size == 0 { continue; }
            if pointer == 0 || pointer.checked_add(size).is_none_or(|end| end > 0xc0000000) { return Err(-EFAULT); }
            length = length.checked_add(size as usize).filter(|n| *n <= file_io::MAX_WRITE).ok_or(-EINVAL)?;
            regions.push((pointer as usize, size as usize));
        }
        // A concurrent fd close must not destroy the open description while
        // this read is blocked. Fork does not inherit another thread's wait.
        match source {
            Source::File(handle) => vfs::add_vfs_ref(handle),
            Source::Pipe(pipe) => crate::kernel::kpipe::add_reader(pipe),
        }
        Ok(Self { source, regions, length })
    }

    pub fn step<A: crate::Arch>(&self, machine: &mut A) -> Option<i32> {
        if self.length == 0 { return Some(0); }
        if let Source::Pipe(pipe) = self.source
            && !crate::kernel::kpipe::has_data(pipe)
        {
            if !crate::kernel::kpipe::has_writers(pipe) { return Some(0); }
            return if crate::kernel::kpipe::nonblocking(pipe, false) { Some(-11) } else { None };
        }
        // One real read, then scatter its bytes. A large request can return a
        // legal short read without allocating its entire user buffer size.
        let mut bytes = alloc::vec![0; self.length.min(65536)];
        let result = match self.source {
            Source::File(handle) => vfs::read_by_handle(handle, &mut bytes),
            Source::Pipe(pipe) => crate::kernel::kpipe::read_event(pipe, &mut bytes)? as i32,
        };
        if result > 0 {
            let mut offset = 0;
            for &(pointer, size) in &self.regions {
                let count = size.min(result as usize - offset);
                machine.copy_to(pointer, &bytes[offset..offset + count]);
                offset += count;
                if offset == result as usize { break; }
            }
        }
        Some(result)
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        match self.source {
            Source::File(handle) => { vfs::close_vfs_handle(handle); }
            Source::Pipe(pipe) => crate::kernel::kpipe::close_reader(pipe),
        }
    }
}

pub(super) fn call<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args, wide: bool) -> SyscallResult {
    let request = match Request::new(machine, kt, a, wide) {
        Ok(request) => request,
        Err(error) => return SyscallResult::val(error),
    };
    if let Some(result) = request.step(machine) { return SyscallResult::val(result); }
    linux.pending_readv = Some(request);
    kt.state = thread::ThreadState::Blocked;
    SyscallResult::val(0)
}
