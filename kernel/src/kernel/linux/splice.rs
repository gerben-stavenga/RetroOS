//! Pipe-to-discard-sink transfers. Other endpoint combinations report EINVAL
//! until their backend supplies splice support; pipe bytes remain untouched.
use super::{Args, EINVAL, EBADF, ESPIPE, thread, vfs};
use crate::kernel::kpipe;

pub(super) struct Request { pipe: u8, length: usize, nonblocking: bool }
impl Request {
    pub fn new<A: crate::Arch>(kt: &thread::KernelThread<A>, a: &Args) -> Result<Self, i32> {
        if a.a5 & !15 != 0 { return Err(EINVAL); }
        let pipe = match kt.fds.get(a.a0 as usize) {
            Some(thread::FdKind::PipeRead(pipe)) => *pipe,
            Some(thread::FdKind::PipeWrite(_)) => return Err(EBADF),
            Some(thread::FdKind::None) | None => return Err(EBADF),
            _ => return Err(EINVAL),
        };
        if a.a1 != 0 { return Err(ESPIPE); }
        let handle = match kt.fds.get(a.a2 as usize) {
            Some(thread::FdKind::Vfs(handle)) => *handle,
            Some(thread::FdKind::PipeRead(_)) => return Err(EBADF),
            Some(thread::FdKind::None) | None => return Err(EBADF),
            _ => return Err(EINVAL),
        };
        let flags = vfs::handle_status_flags(handle);
        if flags < 0 || flags & 3 == 0 { return Err(EBADF); }
        if flags & 0x400 != 0 { return Err(EINVAL); } // O_APPEND
        if a.a3 != 0 { return Err(ESPIPE); }
        if !vfs::discard_sink(handle) { return Err(EINVAL); }
        kpipe::add_reader(pipe);
        Ok(Self { pipe, length: a.a4.min(65536) as usize, nonblocking: a.a5 & 2 != 0 })
    }
    pub fn step(&self) -> Option<i32> {
        kpipe::discard_event(self.pipe, self.length).map(|n| n as i32).or_else(|| {
            (self.nonblocking || kpipe::nonblocking(self.pipe, false)).then_some(-11)
        })
    }
}
impl Drop for Request {
    fn drop(&mut self) { kpipe::close_reader(self.pipe); }
}
