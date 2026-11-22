//! Linux system-memory information from the shared page allocator.
use super::{Args, EFAULT, SyscallResult, async_io, thread};
use core::sync::atomic::{AtomicU16, Ordering};

static TASKS: AtomicU16 = AtomicU16::new(1);

/// The event loop owns the task table; publish a count without retaining a
/// pointer into it while a personality is handling a syscall.
pub(super) fn refresh_tasks<A: crate::Core>(threads: &thread::ThreadTable<A>) {
    let count: usize = threads
        .active_ids()
        .map(|tid| &threads[tid])
        .filter(|task| {
            !matches!(
                task.kernel.state,
                thread::ThreadState::Unused | thread::ThreadState::Zombie
            )
        })
        .map(|task| match &task.personality {
            thread::Personality::Linux(linux) => async_io::live_task_count(&linux.async_io),
            _ => 1,
        })
        .sum();
    TASKS.store(count.min(u16::MAX as usize) as u16, Ordering::Relaxed);
}

pub(super) fn sysinfo<A: crate::Core>(machine: &mut A, args: &Args, wide: bool) -> SyscallResult {
    let size = if wide { 112 } else { 64 };
    if args.a0 == 0 || args.a0.checked_add(size).is_none_or(|end| end > 0xc0000000) {
        return SyscallResult::val(-EFAULT);
    }
    let pointer = args.a0;
    let free = crate::kernel::phys_mm::free_page_count() as u64;
    let total = crate::kernel::phys_mm::total_page_count();
    let total = total as u64;
    let uptime = (machine.now() / 1_000_000) / 1000;
    machine.zero(pointer as u64, size as usize);
    // No swap or high-memory zone is exposed. Load averages and the breakdown
    // into shared/buffer RAM are not tracked; total/free include all allocations.
    if wide {
        machine.write::<u64>(pointer as u64, uptime);
        machine.write::<u64>((pointer + 32) as u64, total);
        machine.write::<u64>((pointer + 40) as u64, free);
        machine.write::<u16>((pointer + 80) as u64, TASKS.load(Ordering::Relaxed));
        machine.write::<u32>((pointer + 104) as u64, 4096);
    } else {
        machine.write::<u32>(pointer as u64, uptime as u32);
        machine.write::<u32>((pointer + 16) as u64, total as u32);
        machine.write::<u32>((pointer + 20) as u64, free as u32);
        machine.write::<u16>((pointer + 40) as u64, TASKS.load(Ordering::Relaxed));
        machine.write::<u32>((pointer + 52) as u64, 4096);
    }
    SyscallResult::val(0)
}
