//! The event loop's current thread and live register frame.
//!
//! Switching materializes the old thread and resumes the new one. The event
//! loop calls `Arch::execute` itself; this context only holds registers and
//! caches the personality's I/O policy. Display focus is managed separately.

use crate::kernel::thread;

/// Compile-time toggle: verify the address-space hash across switches
/// (expensive; bring-up diagnostics).
const ASSERT_ADDR_HASH: bool = false;

pub struct ExecutionContext<A: crate::Arch> {
    pub tid: usize,
    /// The running thread's REGISTERS (loop-owned, disjoint from the threads
    /// array). Its ADDRESS SPACE is not here — it lives in the backend as the
    /// single active space ([`crate::Arch::activate`]); guest memory is reached
    /// through `machine`. `PhantomData` keeps `A` in the type.
    pub regs: crate::Regs,
    pub device_cycles: u64,
    io_key: Option<crate::kernel::io_policy::PolicyKey>,
    pub(crate) io_policy: arch_abi::IoPolicy,
    _a: core::marker::PhantomData<A>,
}

impl<A: crate::Arch> ExecutionContext<A> {
    /// Seed the loan from the first thread: take its registers into the loan.
    ///
    /// It does NOT `activate` the thread's space. The first thread runs on the
    /// space that is ALREADY active — the boot-configured constant root on
    /// metal, the init'd page directory on interp — while its own `space` handle
    /// is still the default placeholder from `create_thread`. Activating that
    /// placeholder would, on metal, swap its empty entries into the live root
    /// and unmap the running thread (`swap_and_activate`). The handle is filled
    /// in with the real entries the first time the thread switches out.
    pub fn seed(threads: &mut [thread::Thread<A>], tid: usize) -> Self {
        let t = thread::get_thread(threads, tid).expect("ExecutionContext::seed: invalid thread");
        let regs = t.kernel.vcpu.regs;
        ExecutionContext {
            tid,
            regs,
            device_cycles: 0,
            io_key: None,
            io_policy: arch_abi::IoPolicy::deny_all(),
            _a: core::marker::PhantomData,
        }
    }

    /// The thread currently holding the CPU. The borrow is tied to the passed
    /// `threads` slice (the loop owns it), not to `self`.
    pub fn thread<'a>(&self, threads: &'a mut [thread::Thread<A>]) -> &'a mut thread::Thread<A> {
        thread::get_thread(threads, self.tid).expect("ExecutionContext: current thread vanished")
    }

    /// Reconcile the I/O bitmap with the current personality's capabilities.
    pub fn prepare_io(
        &mut self,
        bios: &crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        personality: &thread::Personality<A>,
    ) {
        let key = crate::kernel::io_policy::key(personality, bios);
        if self.io_key != Some(key) {
            self.io_policy = crate::kernel::io_policy::for_key(key);
            self.io_key = Some(key);
        }
    }

    /// Execution swap: make `new_tid` the running thread. No-op when it already
    /// is. Parks the outgoing thread's registers, loads the incoming thread's,
    /// and `activate`s the incoming address space (the displaced outgoing space
    /// returns and re-parks). Rebuilds the I/O bitmap and runs `on_resume`.
    pub fn switch_to(&mut self, threads: &mut [thread::Thread<A>], machine: &mut A, new_tid: usize) {
        if new_tid == self.tid {
            return;
        }
        crate::kernel::parallel::take_process(machine, threads, new_tid);
        let (old, new) = thread::get_two_threads(threads, self.tid, new_tid);
        if ASSERT_ADDR_HASH { old.kernel.addr_hash = machine.check_address_space(0); }
        old.materialize(machine, self.regs);
        self.regs = new.resume(machine);
        if ASSERT_ADDR_HASH { machine.check_address_space(new.kernel.addr_hash); }
        self.tid = new_tid;
    }

    /// Relabel an unchanged live address space after fork/exec. The fork path
    /// has already parked the parent's registers/FPU and installed the
    /// child's, so no CR3 transition is permitted here.
    pub fn continue_as(&mut self, threads: &mut [thread::Thread<A>], machine: &mut A, tid: usize) {
        thread::get_thread(threads, tid)
            .expect("continue_as: invalid child")
            .personality
            .on_resume(machine);
        self.tid = tid;
    }
}

/// Verify that saved CPU state still matches the hash recorded on the last
/// switch-out. Print a diff-style dump on mismatch.
pub(crate) fn verify_kernel_cpu_hash<A: crate::Arch>(k: &thread::KernelThread<A>, tag: &str) {
    if k.cpu_hash == 0 { return; }
    let actual = thread::hash_regs(&k.vcpu.regs);
    if actual == k.cpu_hash { return; }
    crate::compact_println!(
        "\x1b[91mCPU STATE CORRUPTION [{}] tid={} expected={:#018x} actual={:#018x}\x1b[0m",
        tag, k.tid, k.cpu_hash, actual,
    );
    let r = &k.vcpu.regs;
    crate::compact_println!(
        "  cs:ip={:04x}:{:08x} ss:sp={:04x}:{:08x} flags={:08x}",
        r.code_seg(), r.ip32(), r.stack_seg(), r.sp32(), r.flags32(),
    );
    crate::compact_println!(
        "  ds={:04x} es={:04x} fs={:04x} gs={:04x}",
        r.ds as u16, r.es as u16, r.fs as u16, r.gs as u16,
    );
    crate::compact_println!(
        "  eax={:08x} ebx={:08x} ecx={:08x} edx={:08x}",
        r.rax as u32, r.rbx as u32, r.rcx as u32, r.rdx as u32,
    );
    crate::compact_println!(
        "  esi={:08x} edi={:08x} ebp={:08x} int={:02x} err={:08x}",
        r.rsi as u32, r.rdi as u32, r.rbp as u32, r.int_num as u32, r.err_code as u32,
    );
}
