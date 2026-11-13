//! pselect6 descriptor sets and waits, shared by both Linux word sizes.
use super::{Args, EBADF, EINVAL, LinuxState, SyscallResult, thread};
#[derive(Clone, Copy)]
pub(super) struct Request {
    sets: [thread::FdSet; 3],
    pointers: [usize; 3],
    nfds: usize,
    wide: bool,
    deadline: u64,
    pub(super) signal_mask: Option<u64>,
}
impl Request {
    pub(super) fn deadline(&self) -> Option<u64> { (self.deadline != u64::MAX).then_some(self.deadline) }
    pub(super) fn read<A: crate::Arch>(
        machine: &mut A,
        args: &Args,
        wide: bool,
    ) -> Result<Self, i32> {
        if args.a0 > thread::MAX_FDS as u64 {
            return Err(-EINVAL);
        }
        let nfds = args.a0 as usize;
        let mut request = Self {
            sets: [thread::FdSet::empty(); 3],
            pointers: [args.a1 as usize, args.a2 as usize, args.a3 as usize],
            nfds,
            wide,
            deadline: u64::MAX,
            signal_mask: None,
        };
        let size = request.size();
        for (index, &pointer) in request.pointers.iter().enumerate() {
            if pointer != 0 && size != 0 {
                let mut bytes = [0; thread::FD_SET_BYTES];
                machine.copy_from(pointer, &mut bytes[..size]);
                request.sets[index] = thread::FdSet::from_le_bytes(&bytes[..size]);
            }
        }
        if args.a4 != 0 {
            let at = args.a4 as usize;
            let (sec, nsec) = if wide {
                (machine.read::<i64>(at), machine.read::<i64>(at + 8))
            } else {
                (
                    i64::from(machine.read::<i32>(at)),
                    i64::from(machine.read::<i32>(at + 4)),
                )
            };
            if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                return Err(-EINVAL);
            }
            request.deadline = machine
                .now()
                .saturating_add((sec as u64).saturating_mul(1_000_000_000))
                .saturating_add(nsec as u64);
        }
        if args.a5 != 0 {
            let mut descriptor = [0u8; 16];
            let word = if wide { 8 } else { 4 };
            if !super::high_memory::copy_from(machine, args.a5, &mut descriptor[..word * 2]) {
                return Err(-super::EFAULT);
            }
            let (pointer, length) = if wide {
                (u64::from_le_bytes(descriptor[..8].try_into().unwrap()), u64::from_le_bytes(descriptor[8..].try_into().unwrap()))
            } else {
                (u32::from_le_bytes(descriptor[..4].try_into().unwrap()) as u64, u32::from_le_bytes(descriptor[4..8].try_into().unwrap()) as u64)
            };
            if pointer != 0 {
                if length != 8 { return Err(-EINVAL); }
                let mut mask = [0u8; 8];
                if !super::high_memory::copy_from(machine, pointer, &mut mask) { return Err(-super::EFAULT); }
                request.signal_mask = Some(u64::from_le_bytes(mask));
            }
        }
        Ok(request)
    }
    fn size(&self) -> usize {
        let unit = if self.wide { 8 } else { 4 };
        self.nfds.div_ceil(unit * 8) * unit
    }
    pub(super) fn step<A: crate::Arch>(
        &self,
        machine: &mut A,
        kt: &thread::KernelThread<A>,
    ) -> Option<i32> {
        let mut output = [thread::FdSet::empty(); 3];
        let mut count = 0;
        for fd in 0..self.nfds {
            if self.sets.iter().all(|set| !set.contains(fd)) {
                continue;
            }
            let events = super::fd_readiness(kt, fd, 1 | 4 | 2);
            if events & 32 != 0 {
                return Some(-EBADF);
            }
            for (i, mask) in [1 | 8 | 16, 4 | 8 | 16, 2].into_iter().enumerate() {
                if self.sets[i].contains(fd) && events & mask != 0 {
                    output[i].set(fd, true);
                    count += 1;
                }
            }
        }
        if count == 0 && machine.now() < self.deadline {
            return None;
        }
        for (index, &pointer) in self.pointers.iter().enumerate() {
            if pointer != 0 {
                machine.copy_to(pointer, &output[index].to_le_bytes()[..self.size()]);
            }
        }
        Some(count)
    }
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    linux: &mut LinuxState,
    args: &Args,
    regs: &mut crate::Regs,
    wide: bool,
) -> SyscallResult {
    let request = match Request::read(machine, args, wide) {
        Ok(r) => r,
        Err(e) => return SyscallResult::val(e),
    };
    if let Some(n) = request.step(machine, kt) {
        return SyscallResult::val(n);
    }
    kt.vcpu.regs = *regs;
    kt.state = thread::ThreadState::Blocked;
    linux.pending_select = Some(request);
    SyscallResult::val(0)
}
