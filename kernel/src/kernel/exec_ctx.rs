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
    pub vcpu: crate::Vcpu<A::PageTable>,
}

impl<A: crate::Arch> ExecutionContext<A> {
    /// Seed the loan from a thread's saved state (the loop's first thread).
    pub fn seed(threads: &mut [thread::Thread<A>], tid: usize) -> Self {
        let vcpu = thread::get_thread(threads, tid)
            .expect("ExecutionContext::seed: invalid thread")
            .kernel
            .vcpu;
        ExecutionContext { tid, vcpu }
    }

    /// The thread currently holding the CPU. The borrow is tied to the passed
    /// `threads` slice (the loop owns it), not to `self`.
    pub fn thread<'a>(&self, threads: &'a mut [thread::Thread<A>]) -> &'a mut thread::Thread<A> {
        thread::get_thread(threads, self.tid).expect("ExecutionContext: current thread vanished")
    }

    /// Run user code until it produces a kernel event.
    pub fn run(&mut self, machine: &mut A) -> crate::KernelEvent {
        machine.execute(&mut self.vcpu)
    }

    /// Execution swap: make `new_tid` the running thread. No-op when it
    /// already is. Saves the outgoing thread's registers/FPU (and CPU-state
    /// hash), restores the incoming thread's, switches the address space,
    /// rebuilds the I/O bitmap from policy, and runs the personality's
    /// `on_resume` (LDT/TLS rebinding). Does NOT touch console focus.
    pub fn switch_to(&mut self, threads: &mut [thread::Thread<A>], machine: &mut A, new_tid: usize) {
        if new_tid == self.tid {
            return;
        }
        let (old, new) = thread::get_two_threads(threads, self.tid, new_tid);
        verify_cpu_hash(new, "switch-in");
        let mut swap_vcpu = new.kernel.vcpu;
        let mut swap_fx = new.kernel.fx_state;
        if ASSERT_ADDR_HASH {
            let mut hash = new.kernel.addr_hash;
            machine.switch_to(&mut self.vcpu, &mut swap_vcpu, &mut hash, &mut swap_fx);
            old.kernel.addr_hash = hash;
        } else {
            machine.switch_to(&mut self.vcpu, &mut swap_vcpu, core::ptr::null_mut(), &mut swap_fx);
        }
        old.kernel.vcpu = swap_vcpu;
        old.kernel.fx_state = swap_fx;
        old.kernel.cpu_hash = thread::hash_regs(&old.kernel.vcpu.regs);
        // The incoming thread's port permissions: rebuilt from (personality,
        // platform, focus) — never inherited from whoever ran last.
        crate::kernel::io_policy::apply(
            machine,
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
