//! The CPU loan — the live execution context and which thread holds it.
//!
//! The event loop owns exactly one of these: `vcpu` is the live register
//! frame + address-space handle (no global `REGS` on the kernel side), and
//! `tid` names the thread it belongs to. `run` lends the CPU to user code;
//! `switch_to` is a pure EXECUTION swap — registers, FPU, address space,
//! per-thread CPU bindings (`on_resume`), and the I/O bitmap derived from
//! (personality, platform, focus). Console-focus transfer is deliberately
//! NOT here: focus is a separate concept (`kernel::focus`) that today
//! accompanies every switch (see startup's `switch_focus_and_run`) and
//! tomorrow won't.

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
    _a: core::marker::PhantomData<A>,
}

impl<A: crate::Arch> ExecutionContext<A> {
    /// Seed the loan from a thread's saved state (the loop's first thread): take
    /// its registers into the loan and make its space the active one.
    pub fn seed(threads: &mut [thread::Thread<A>], machine: &mut A, tid: usize) -> Self {
        let t = thread::get_thread(threads, tid).expect("ExecutionContext::seed: invalid thread");
        let regs = t.kernel.vcpu.regs;
        // Move the first thread's space into the active slot (discarding the
        // empty placeholder the backend started with); no FPU swap on seed.
        let space = core::mem::take(&mut t.kernel.vcpu.space);
        let _ = machine.activate(space, core::ptr::null_mut(), core::ptr::null_mut());
        ExecutionContext { tid, regs, _a: core::marker::PhantomData }
    }

    /// The thread currently holding the CPU. The borrow is tied to the passed
    /// `threads` slice (the loop owns it), not to `self`.
    pub fn thread<'a>(&self, threads: &'a mut [thread::Thread<A>]) -> &'a mut thread::Thread<A> {
        thread::get_thread(threads, self.tid).expect("ExecutionContext: current thread vanished")
    }

    /// Run user code until it produces a kernel event.
    pub fn run(&mut self, machine: &mut A) -> crate::KernelEvent {
        machine.execute(&mut self.regs)
    }

    /// Execution swap: make `new_tid` the running thread. No-op when it already
    /// is. Parks the outgoing thread's registers, loads the incoming thread's,
    /// and `activate`s the incoming address space (the displaced outgoing space
    /// returns and re-parks). Rebuilds the I/O bitmap and runs `on_resume`.
    pub fn switch_to(&mut self, threads: &mut [thread::Thread<A>], machine: &mut A, new_tid: usize) {
        if new_tid == self.tid {
            return;
        }
        let (old, new) = thread::get_two_threads(threads, self.tid, new_tid);
        verify_cpu_hash(new, "switch-in");
        // Registers are plain data: park the outgoing set, load the incoming.
        old.kernel.vcpu.regs = self.regs;
        self.regs = new.kernel.vcpu.regs;
        // The address space is the moved resource: `activate` swaps the incoming
        // space into the live slot and hands back the displaced (outgoing) one.
        let mut swap_fx = new.kernel.fx_state;
        let incoming = core::mem::take(&mut new.kernel.vcpu.space);
        let old_space = if ASSERT_ADDR_HASH {
            let mut hash = new.kernel.addr_hash;
            let s = machine.activate(incoming, &mut swap_fx, &mut hash);
            old.kernel.addr_hash = hash;
            s
        } else {
            machine.activate(incoming, &mut swap_fx, core::ptr::null_mut())
        };
        old.kernel.vcpu.space = old_space;
        old.kernel.fx_state = swap_fx;
        old.kernel.cpu_hash = thread::hash_regs(&old.kernel.vcpu.regs);
        // The incoming thread's port permissions: rebuilt from (personality,
        // platform, focus) — never inherited from whoever ran last.
        crate::kernel::io_policy::apply(machine,
            &new.personality,
            new_tid == crate::kernel::focus::focused(),
        );
        new.personality.on_resume(machine);
        self.tid = new_tid;
    }
}

/// Verify that a thread's saved cpu_state still matches the hash recorded on
/// the last switch-out. Print a diff-style dump on mismatch.
/// `tag` is printed in the header ("switch-in" / "reblock" / ...).
pub(crate) fn verify_cpu_hash<A: crate::Arch>(t: &thread::Thread<A>, tag: &str) {
    let k = &t.kernel;
    if k.cpu_hash == 0 { return; }
    let actual = thread::hash_regs(&k.vcpu.regs);
    if actual == k.cpu_hash { return; }
    crate::println!(
        "\x1b[91mCPU STATE CORRUPTION [{}] tid={} expected={:#018x} actual={:#018x}\x1b[0m",
        tag, k.tid, k.cpu_hash, actual,
    );
    let r = &k.vcpu.regs;
    crate::println!(
        "  cs:ip={:04x}:{:08x} ss:sp={:04x}:{:08x} flags={:08x}",
        r.code_seg(), r.ip32(), r.stack_seg(), r.sp32(), r.flags32(),
    );
    crate::println!(
        "  ds={:04x} es={:04x} fs={:04x} gs={:04x}",
        r.ds as u16, r.es as u16, r.fs as u16, r.gs as u16,
    );
    crate::println!(
        "  eax={:08x} ebx={:08x} ecx={:08x} edx={:08x}",
        r.rax as u32, r.rbx as u32, r.rcx as u32, r.rdx as u32,
    );
    crate::println!(
        "  esi={:08x} edi={:08x} ebp={:08x} int={:02x} err={:08x}",
        r.rsi as u32, r.rdi as u32, r.rbp as u32, r.int_num as u32, r.err_code as u32,
    );
}
