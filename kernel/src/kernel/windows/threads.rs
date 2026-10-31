//! Windows threads share one address space and switch at API gates and interrupts.
//! Each context owns its registers, stack, stable TEB address, TLS values and last error.
use super::*;
use alloc::boxed::Box;

#[derive(Clone, Copy)]
enum Status {
    Ready,
    Suspended(u32),
    NativeWaiting(u64),
    AlertWaiting(u64),
    Exited(u32),
}
struct Context {
    regs: Regs,
    fx: Box<dyn core::any::Any>,
    id: u32,
    handle: u32,
    status: Status,
    wait_handles: Vec<u32>,
    wait_all: bool,
    // Wine address-wait wakeups are sticky, binary, and separate from object waits.
    alerted: bool,
    tls: [u32; 64],
    teb: u32,
    error: u32,
    stack_base: u32,
    stack_size: u32,
}
struct Event {
    handle: u32,
    manual: bool,
    signaled: bool,
}
struct Semaphore {
    handle: u32,
    count: u32,
    maximum: u32,
}
struct Mutant {
    handle: u32,
    owner: u32,
    recursion: u32,
}
#[derive(Default)]
pub(super) struct State {
    contexts: Vec<Context>,
    events: Vec<Event>,
    semaphores: Vec<Semaphore>,
    mutants: Vec<Mutant>,
    active: usize,
    polling: bool,
}

fn ensure<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, t: &mut State, regs: &Regs) {
    if !t.contexts.is_empty() {
        return;
    }
    let id = machine.read::<u32>((state.teb_base + 0x24) as usize);
    t.contexts.push(Context {
        wait_handles: Vec::new(),
        wait_all: false,
        alerted: false,
        regs: *regs,
        fx: Box::new(machine.clean_fx_template()),
        id,
        handle: 0,
        status: Status::Ready,
        tls: state.tls,
        teb: state.teb_base,
        error: state.last_error,
        stack_base: state.stack_base,
        stack_size: state.stack_size,
    });
}

// USER32 subscribes existing KERNEL32 events; queue policy stays in the DLL.
pub(super) fn signal(t: &mut State, handle: u32) -> bool {
    if let Some(event) = t.events.iter_mut().find(|e| e.handle == handle) {
        event.signaled = true;
        true
    } else {
        false
    }
}

fn signaled(t: &mut State, handle: u32, id: u32) -> Option<bool> {
    if let Some(s) = t.semaphores.iter_mut().find(|s| s.handle == handle) {
        if s.count == 0 {
            return Some(false);
        }
        s.count -= 1;
        return Some(true);
    }
    if let Some(m) = t.mutants.iter_mut().find(|m| m.handle == handle) {
        if m.owner != 0 && m.owner != id {
            return Some(false);
        }
        m.owner = id;
        m.recursion += 1;
        return Some(true);
    }

    if let Some(c) = t
        .contexts
        .iter()
        .find(|c| c.handle == handle && handle != 0)
    {
        return Some(matches!(c.status, Status::Exited(_)));
    }
    if let Some(e) = t.events.iter_mut().find(|e| e.handle == handle) {
        let ready = e.signaled;
        if ready && !e.manual {
            e.signaled = false;
        }
        return Some(ready);
    }
    None
}

// Test readiness without consuming auto-reset events or acquiring mutexes.
fn ready(t: &State, handle: u32, id: u32) -> Option<bool> {
    if let Some(s) = t.semaphores.iter().find(|s| s.handle == handle) {
        return Some(s.count != 0);
    }
    if let Some(m) = t.mutants.iter().find(|m| m.handle == handle) {
        return Some(m.owner == 0 || m.owner == id);
    }

    if let Some(c) = t
        .contexts
        .iter()
        .find(|c| c.handle == handle && handle != 0)
    {
        return Some(matches!(c.status, Status::Exited(_)));
    }
    if let Some(e) = t.events.iter().find(|e| e.handle == handle) {
        return Some(e.signaled);
    }
    None
}
fn multiple(t: &mut State, handles: &[u32], all: bool, id: u32) -> Result<Option<u32>, ()> {
    let mut first = None;
    let mut every = true;
    for (i, &h) in handles.iter().enumerate() {
        let value = ready(t, h, id).ok_or(())?;
        every &= value;
        if value && first.is_none() {
            first = Some(i);
        }
    }
    if all {
        if !every {
            return Ok(None);
        }
        for &h in handles {
            signaled(t, h, id);
        }
        Ok(Some(0))
    } else if let Some(i) = first {
        signaled(t, handles[i], id);
        Ok(Some(i as u32))
    } else {
        Ok(None)
    }
}

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    kt: &mut thread::KernelThread<A>,
    regs: &mut Regs,
    gate: Gate,
) -> Option<thread::KernelAction> {
    if gate.api == Api::RestoreContext {
        let result = exceptions::restore(machine, state, regs, arg(machine, regs, 0));
        if result != 0 {
            finish(machine, regs, gate, result);
        }
        return Some(thread::KernelAction::Done);
    }
    if gate.api == Api::NativeThread {
        let op = arg(machine, regs, 0);
        let params = arg(machine, regs, 1);
        let out = arg(machine, regs, 2);
        let result = native(machine, state, regs, op, params, out);
        finish(machine, regs, gate, result);
        if !schedule(machine, state, regs) {
            if state
                .threads
                .contexts
                .iter()
                .all(|c| matches!(c.status, Status::Exited(_)))
            {
                let code = match state.threads.contexts[state.threads.active].status {
                    Status::Exited(code) => code,
                    _ => result,
                };
                return Some(thread::KernelAction::Exit(code as i32));
            }
            kt.state = thread::ThreadState::Blocked;
        }
        return Some(thread::KernelAction::Done);
    }
    if gate.api == Api::Wait {
        let count = arg(machine, regs, 0) as usize;
        let array = arg(machine, regs, 1) as usize;
        let all = arg(machine, regs, 2) != 0;
        let timeout = u64::from(arg(machine, regs, 3)) | (u64::from(arg(machine, regs, 4)) << 32);
        let mut t = core::mem::take(&mut state.threads);
        ensure(machine, state, &mut t, regs);
        let result = if count > 64 || (count != 0 && array == 0) || (count == 0 && all) {
            0xc000000d
        } else {
            let handles: Vec<u32> = (0..count)
                .map(|i| machine.read::<u32>(array + i * 4))
                .collect();
            let duplicate = handles
                .iter()
                .enumerate()
                .any(|(i, h)| handles[..i].contains(h));
            let id = t.contexts[t.active].id;
            if duplicate {
                0xc000000d
            } else {
                match multiple(&mut t, &handles, all, id) {
                    Err(()) => 0xc0000008,
                    Ok(Some(result)) => result,
                    Ok(None) => {
                        if timeout != 0 {
                            let context = &mut t.contexts[t.active];
                            context.wait_handles = handles;
                            context.wait_all = all;
                            context.status = Status::NativeWaiting(if timeout == u64::MAX {
                                u64::MAX
                            } else {
                                machine
                                    .now()
                                    .saturating_add(timeout.saturating_mul(1_000_000))
                            });
                        }
                        0x102
                    }
                }
            }
        };
        finish(machine, regs, gate, result);
        state.threads = t;
        if !schedule(machine, state, regs) {
            kt.state = thread::ThreadState::Blocked;
        }
        return Some(thread::KernelAction::Done);
    }
    None
}

pub(super) fn schedule<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &mut Regs,
) -> bool {
    if state.threads.contexts.is_empty() || state.callback.is_some() {
        return true;
    }
    let mut t = core::mem::take(&mut state.threads);
    if !t.polling {
        let c = &mut t.contexts[t.active];
        c.regs = *regs;
        c.tls = state.tls;
        c.error = state.last_error;
        c.stack_base = state.stack_base;
        c.stack_size = state.stack_size;
    }
    let now = machine.now();
    for i in 0..t.contexts.len() {
        match t.contexts[i].status {
            Status::AlertWaiting(deadline) => {
                let c = &mut t.contexts[i];
                if c.alerted || now >= deadline {
                    c.regs.rax = if c.alerted { 0x101 } else { 0x102 };
                    c.alerted = false;
                    c.status = Status::Ready;
                }
            }
            Status::NativeWaiting(deadline) => {
                let id = t.contexts[i].id;
                let handles = core::mem::take(&mut t.contexts[i].wait_handles);
                let all = t.contexts[i].wait_all;
                let result = multiple(&mut t, &handles, all, id);
                t.contexts[i].wait_handles = handles;
                let result = match result {
                    Ok(Some(r)) => Some(r),
                    Err(()) => Some(0xc0000008),
                    Ok(None) if now >= deadline => Some(258),
                    _ => None,
                };
                if let Some(result) = result {
                    t.contexts[i].status = Status::Ready;
                    t.contexts[i].regs.rax = u64::from(result);
                }
            }
            _ => {}
        }
    }
    let next = (1..=t.contexts.len())
        .map(|n| (t.active + n) % t.contexts.len())
        .find(|&i| matches!(t.contexts[i].status, Status::Ready));
    if let Some(next) = next {
        if next != t.active {
            let mut fx = *t.contexts[next].fx.downcast_ref::<A::Fx>().unwrap();
            machine.switch_fx(&mut fx);
            *t.contexts[t.active].fx.downcast_mut::<A::Fx>().unwrap() = fx;
        }
        t.active = next;
        t.polling = false;
        let c = &t.contexts[next];
        *regs = c.regs;
        state.tls = c.tls;
        state.last_error = c.error;
        state.stack_base = c.stack_base;
        state.stack_size = c.stack_size;
        state.teb_base = c.teb;
        let index = regs.fs as usize >> 3;
        if index != 0 && index < state.ldt.len() {
            state.ldt[index] = descriptor(c.teb, (TEB_SIZE - 1) as u32);
            machine.load_ldt(&state.ldt);
        }
    } else {
        t.polling = true;
        // Keep the guest continuation parked; after_input checks wakeups.
    }
    // An exited context cannot execute again. Keep its object while a handle
    // exists, then release its private mappings after switching off its stack.
    for i in (0..t.contexts.len()).rev() {
        if i != t.active
            && t.contexts[i].handle == 0
            && matches!(t.contexts[i].status, Status::Exited(_))
        {
            let c = t.contexts.remove(i);
            if i < t.active {
                t.active -= 1;
            }
            memory::call(
                machine,
                state,
                Api::MemoryRelease,
                c.stack_base.saturating_sub(4096),
                0,
                0,
            );
            memory::call(machine, state, Api::MemoryRelease, c.teb, 0, 0);
        }
    }
    let ready = !t.polling;
    state.threads = t;
    ready
}

/// TlsFree clears the released slot in every thread’s stable TEB.
pub(super) fn clear_tls<A: crate::Arch>(machine: &mut A, threads: &mut State, index: u32) -> u32 {
    if index >= 1088 {
        return 0xc000000d;
    }
    let mut bases: Vec<u32> = threads.contexts.iter().map(|c| c.teb).collect();
    if bases.is_empty() {
        bases.push(TEB_BASE);
    }
    for base in bases {
        if index < 64 {
            machine.write::<u32>(base as usize + 0xe10 + index as usize * 4, 0);
        } else {
            let slots = machine.read::<u32>(base as usize + 0xf94);
            if slots != 0 {
                machine.write::<u32>((slots + (index - 64) * 4) as usize, 0);
            }
        }
    }
    0
}

pub(super) fn event<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    op: u32,
    handle: u32,
    flags: u32,
    out: u32,
) -> u32 {
    if op == 0 {
        let handle = create_event(state, flags & 1 != 0, flags & 2 != 0);
        machine.write::<u32>(out as usize, handle);
        return 0;
    }
    if op == 3 {
        if let Some(c) = state
            .threads
            .contexts
            .iter_mut()
            .find(|c| c.handle == handle && handle != 0)
        {
            c.handle = 0;
            return 0;
        }
    }
    let Some(index) = state.threads.events.iter().position(|e| e.handle == handle) else {
        return if op == 3 {
            sync(machine, state, [6, handle, 0, 0, 0, 0])
        } else {
            0xc0000008
        };
    };
    if op == 3 {
        state.threads.events.remove(index);
        return 0;
    }
    let event = &mut state.threads.events[index];
    if out != 0 {
        machine.write::<u32>(
            out as usize,
            if op == 4 {
                (event.manual as u32) | ((event.signaled as u32) << 1)
            } else {
                event.signaled as u32
            },
        );
    }
    match op {
        1 => event.signaled = true,
        2 => event.signaled = false,
        4 => {}
        _ => return 0xc000000d,
    }
    0
}

pub(super) fn poll<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    regs: &mut Regs,
) {
    if state.threads.polling {
        kt.state = if schedule(machine, state, regs) {
            thread::ThreadState::Ready
        } else {
            thread::ThreadState::Blocked
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saved_thread_context_does_not_embed_large_buffers() {
        // Context construction may be inlined into event dispatch. Inlining
        // an 8 KiB TEB here used to exhaust the DOS/SMB kernel stack too.
        assert!(core::mem::size_of::<Context>() <= 2048);
    }
    #[test]
    fn wait_all_preserves_semaphore_and_mutex_until_all_ready() {
        let mut state = State::default();
        state.semaphores.push(Semaphore {
            handle: 1,
            count: 1,
            maximum: 2,
        });
        state.mutants.push(Mutant {
            handle: 2,
            owner: 9,
            recursion: 1,
        });
        assert_eq!(multiple(&mut state, &[1, 2], true, 7), Ok(None));
        assert_eq!(state.semaphores[0].count, 1);
        assert_eq!(state.mutants[0].owner, 9);
        state.mutants[0].owner = 0;
        state.mutants[0].recursion = 0;
        assert_eq!(multiple(&mut state, &[1, 2], true, 7), Ok(Some(0)));
        assert_eq!(state.semaphores[0].count, 0);
        assert_eq!(state.mutants[0].owner, 7);
        assert_eq!(multiple(&mut state, &[2], false, 7), Ok(Some(0)));
        assert_eq!(state.mutants[0].recursion, 2);
        assert_eq!(multiple(&mut state, &[2], false, 9), Ok(None));
    }
    #[test]
    fn wait_all_does_not_consume_auto_events_until_every_object_is_ready() {
        let mut state = State::default();
        state.events.push(Event {
            handle: 1,
            manual: false,
            signaled: true,
        });
        state.events.push(Event {
            handle: 2,
            manual: false,
            signaled: false,
        });
        assert_eq!(multiple(&mut state, &[1, 2], true, 1), Ok(None));
        assert!(state.events[0].signaled);
        assert_eq!(multiple(&mut state, &[1, 999], false, 1), Err(()));
        assert!(state.events[0].signaled);
        state.events[1].signaled = true;
        assert_eq!(multiple(&mut state, &[1, 2], true, 1), Ok(Some(0)));
        assert!(!state.events[0].signaled && !state.events[1].signaled);
    }
}

/// Unnamed native synchronization objects; wait policy remains shared with events.
pub(super) fn sync<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 6],
) -> u32 {
    let [op, handle, value, maximum, out, _] = args;
    let id = machine.read::<u32>((state.teb_base + 0x24) as usize);
    if op <= 1 {
        if op == 0 && (maximum == 0 || maximum > i32::MAX as u32 || value > maximum) {
            return 0xc000000d;
        }
        let handle = 0x72000000 | state.next_object;
        state.next_object += 4;
        if op == 0 {
            state.threads.semaphores.push(Semaphore {
                handle,
                count: value,
                maximum,
            });
        } else {
            state.threads.mutants.push(Mutant {
                handle,
                owner: if value != 0 { id } else { 0 },
                recursion: if value != 0 { 1 } else { 0 },
            });
        }
        machine.write::<u32>(out as usize, handle);
        return 0;
    }
    if let Some(i) = state
        .threads
        .semaphores
        .iter()
        .position(|s| s.handle == handle)
    {
        if op == 6 {
            state.threads.semaphores.remove(i);
            return 0;
        }
        let s = &mut state.threads.semaphores[i];
        match op {
            2 => {
                if value == 0 || value > i32::MAX as u32 {
                    return 0xc000000d;
                }
                if value > s.maximum - s.count {
                    return 0xc0000047;
                }
                if out != 0 {
                    machine.write::<u32>(out as usize, s.count);
                }
                s.count += value;
            }
            4 => {
                machine.write::<u32>(out as usize, s.count);
                machine.write::<u32>(out as usize + 4, s.maximum);
            }
            _ => return 0xc0000024,
        }
        return 0;
    }
    if let Some(i) = state
        .threads
        .mutants
        .iter()
        .position(|m| m.handle == handle)
    {
        if op == 6 {
            state.threads.mutants.remove(i);
            return 0;
        }
        let m = &mut state.threads.mutants[i];
        match op {
            3 => {
                if m.owner != id || m.recursion == 0 {
                    return 0xc0000046;
                }
                if out != 0 {
                    machine.write::<u32>(out as usize, 1u32.wrapping_sub(m.recursion));
                }
                m.recursion -= 1;
                if m.recursion == 0 {
                    m.owner = 0;
                }
            }
            5 => {
                machine.write::<u32>(out as usize, 1u32.wrapping_sub(m.recursion));
                machine.write::<u32>(out as usize + 4, (m.owner == id) as u32);
            }
            _ => return 0xc0000024,
        }
        return 0;
    }
    0xc0000008
}

pub(super) fn create_event(state: &mut WindowsState, manual: bool, signaled: bool) -> u32 {
    let handle = 0x72000000 | state.next_object;
    state.next_object += 4;
    state.threads.events.push(Event {
        handle,
        manual,
        signaled,
    });
    handle
}
pub(super) fn set_signal(t: &mut State, handle: u32, signaled: bool) {
    if let Some(event) = t.events.iter_mut().find(|e| e.handle == handle) {
        event.signaled = signaled;
    }
}

// Execution mechanism only: NT argument/attribute handling and DLL lifecycle
// remain in RETROOS.DLL and Wine respectively.
fn native<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &Regs,
    op: u32,
    params: u32,
    out: u32,
) -> u32 {
    let p: [u32; 6] = core::array::from_fn(|i| machine.read::<u32>(params as usize + i * 4));
    let mut t = core::mem::take(&mut state.threads);
    ensure(machine, state, &mut t, regs);
    state.threads = t;
    if op == 0 {
        if p[0] == 0 || p[1] == 0 || p[4] & !1 != 0 {
            return 0xc000000d;
        }
        let Some(size) = p[3].max(65536).checked_add(4095).map(|s| s & !4095) else {
            return 0xc0000017;
        };
        if size > 16 * 1024 * 1024 {
            return 0xc0000017;
        }
        let stack = memory::call(machine, state, Api::MemoryReserve, 0, size + 4096, 0);
        if stack == 0 {
            return 0xc0000017;
        }
        let teb = memory::call(machine, state, Api::MemoryReserve, 0, TEB_SIZE as u32, 0);
        if teb == 0
            || memory::call(machine, state, Api::MemoryCommit, stack + 4096, size, 1) == 0
            || memory::call(machine, state, Api::MemoryCommit, teb, TEB_SIZE as u32, 1) == 0
        {
            memory::call(machine, state, Api::MemoryRelease, stack, 0, 0);
            if teb != 0 {
                memory::call(machine, state, Api::MemoryRelease, teb, 0, 0);
            }
            return 0xc0000017;
        }
        static NEXT_THREAD: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0x10000);
        let id = NEXT_THREAD.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let pid = machine.read::<u32>((state.teb_base + 0x20) as usize);
        for (offset, value) in [
            (0, u32::MAX),
            (4, stack + 4096 + size),
            (8, stack + 4096),
            (0x18, teb),
            (0x20, pid),
            (0x24, id),
            (0x30, PEB_BASE),
            (0xe0c, stack),
            (TEB_STATIC_STRING + 4, teb + TEB_STATIC_BUFFER),
        ] {
            machine.write::<u32>((teb + offset) as usize, value);
        }
        machine.write::<u16>((teb + TEB_STATIC_STRING + 2) as usize, 522);
        let sp = stack + 4096 + size - 12;
        machine.write::<u32>(sp as usize, 0);
        machine.write::<u32>(sp as usize + 4, p[1]);
        machine.write::<u32>(sp as usize + 8, p[2]);
        let mut child = Regs::empty();
        child.init_user_process(p[0], sp);
        child.fs = regs.fs;
        let handle = 0x72000000 | state.next_object;
        state.next_object += 4;
        state.threads.contexts.push(Context {
            regs: child,
            fx: Box::new(machine.clean_fx_template()),
            id,
            handle,
            status: if p[4] & 1 != 0 {
                Status::Suspended(1)
            } else {
                Status::Ready
            },
            wait_handles: Vec::new(),
            wait_all: false,
            alerted: false,
            tls: [0; 64],
            teb,
            error: 0,
            stack_base: stack + 4096,
            stack_size: size,
        });
        for (i, v) in [handle, id, teb, pid].into_iter().enumerate() {
            machine.write::<u32>(out as usize + i * 4, v);
        }
        return 0;
    }
    let t = &mut state.threads;
    if op == 4 {
        let c = &mut t.contexts[t.active];
        if c.alerted {
            c.alerted = false;
            return 0x101;
        }
        let timeout = u64::from(p[1]) | (u64::from(p[2]) << 32);
        if timeout != 0 {
            c.status = Status::AlertWaiting(if timeout == u64::MAX {
                u64::MAX
            } else {
                machine
                    .now()
                    .saturating_add(timeout.saturating_mul(1_000_000))
            });
        }
        return 0x102;
    }
    if op == 5 {
        let Some(c) = t
            .contexts
            .iter_mut()
            .find(|c| c.id == p[0] && !matches!(c.status, Status::Exited(_)))
        else {
            return 0xc000000b;
        };
        c.alerted = true;
        return 0;
    }
    let index = if p[0] == 0xffff_fffe {
        Some(t.active)
    } else {
        t.contexts
            .iter()
            .position(|c| c.handle == p[0] && p[0] != 0)
    };
    let Some(index) = index else {
        return 0xc0000008;
    };
    let last = t
        .contexts
        .iter()
        .filter(|c| !matches!(c.status, Status::Exited(_)))
        .count()
        == 1;
    let c = &mut t.contexts[index];
    match op {
        1 => {
            let previous = if let Status::Suspended(n) = c.status {
                n
            } else {
                0
            };
            if previous > 0 {
                c.status = if previous == 1 {
                    Status::Ready
                } else {
                    Status::Suspended(previous - 1)
                };
            }
            machine.write::<u32>(out as usize, previous);
        }
        2 => {
            c.status = Status::Exited(p[1]);
            c.wait_handles.clear();
            for m in &mut t.mutants {
                if m.owner == c.id {
                    m.owner = 0;
                    m.recursion = 0;
                }
            }
        }
        3 => {
            let code = if let Status::Exited(code) = c.status {
                code
            } else {
                0x103
            };
            for (i, v) in [
                code,
                c.teb,
                machine.read::<u32>((c.teb + 0x20) as usize),
                c.id,
                last as u32,
                c.stack_base,
                c.stack_size,
            ]
            .into_iter()
            .enumerate()
            {
                machine.write::<u32>(out as usize + i * 4, v);
            }
        }
        _ => return 0xc00000bb,
    }
    0
}
