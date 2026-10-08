//! Win32 threads share one address space and run cooperatively at API gates.
//! Each context owns its registers, stack, TEB image, TLS values and last error.
use super::*;
use alloc::boxed::Box;

const RETURN_STUB: u32 = 0x7ff4_0000;

#[derive(Clone, Copy)]
enum Status {
    Ready,
    Suspended,
    Sleeping(u64),
    Waiting(u32, u64),
    Critical(u32),
    Exited(u32),
}
struct Context {
    regs: Regs,
    fx: Box<dyn core::any::Any>,
    id: u32,
    handle: u32,
    status: Status,
    tls: [u32; 64],
    teb: [u8; 4096],
    error: u32,
    stack_base: u32,
    stack_size: u32,
}
struct Critical {
    address: u32,
    owner: u32,
    count: u32,
}
struct Mutex {
    handle: u32,
    name: Vec<u8>,
    owner: u32,
    count: u32,
}
struct Event {
    handle: u32,
    manual: bool,
    signaled: bool,
}
#[derive(Default)]
pub(super) struct State {
    contexts: Vec<Context>,
    events: Vec<Event>,
    critical: Vec<Critical>,
    mutexes: Vec<Mutex>,
    active: usize,
    polling: bool,
}

fn ensure<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, t: &mut State, regs: &Regs) {
    if !t.contexts.is_empty() {
        return;
    }
    let mut teb = [0; 4096];
    machine.copy_from(TEB_BASE as usize, &mut teb);
    let id = machine.read::<u32>((TEB_BASE + 0x24) as usize);
    t.contexts.push(Context {
        regs: *regs,
        fx: Box::new(machine.clean_fx_template()),
        id,
        handle: 0,
        status: Status::Ready,
        tls: state.tls,
        teb,
        error: state.last_error,
        stack_base: state.stack_base,
        stack_size: state.stack_size,
    });
    {
        machine.zero(RETURN_STUB as usize, 4096);
        machine.copy_to(RETURN_STUB as usize, &[0x50, 0x6a, 0, 0xcd, 0x83]);
        machine.copy_to((RETURN_STUB + 16) as usize, &[0xcd, 0x83, 0xeb, 0xfc]);
        machine.set_page_flags(RETURN_STUB as usize / 4096, 1, false, true);
        state.gates.push(Gate {
            return_ip: RETURN_STUB + 5,
            api: Api::Extension,
            arg_bytes: 4,
            name: b"RetroThreadReturn",
        });
        state.gates.push(Gate {
            return_ip: RETURN_STUB + 18,
            api: Api::Extension,
            arg_bytes: 0,
            name: b"RetroThreadPoll",
        });
    }
}

fn signaled(t: &mut State, handle: u32, id: u32) -> Option<bool> {
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
    if let Some(m) = t.mutexes.iter_mut().find(|m| m.handle == handle) {
        if m.owner == 0 || m.owner == id {
            m.owner = id;
            m.count += 1;
            return Some(true);
        }
        return Some(false);
    }
    None
}

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &mut Regs,
    gate: Gate,
) -> Option<thread::KernelAction> {
    let name = gate.name;
    if !matches!(
        name,
        b"InitializeCriticalSection"
            | b"DeleteCriticalSection"
            | b"EnterCriticalSection"
            | b"LeaveCriticalSection"
            | b"CreateMutexA"
            | b"ReleaseMutex"
            | b"CreateThread"
            | b"ExitThread"
            | b"RetroThreadReturn"
            | b"RetroThreadPoll"
            | b"GetCurrentThreadId"
            | b"GetExitCodeThread"
            | b"ResumeThread"
            | b"TerminateThread"
            | b"CreateEventA"
            | b"SetEvent"
            | b"Sleep"
            | b"WaitForSingleObject"
            | b"WaitForSingleObjectEx"
    ) {
        return None;
    }
    let mut t = core::mem::take(&mut state.threads);
    ensure(machine, state, &mut t, regs);
    if crate::kernel::startup::trace_enabled()
        && !matches!(name, b"GetCurrentThreadId" | b"RetroThreadPoll")
    {
        crate::compact_dbg_println!(
            "[win32-thread] id={} {} a0={:08x} a1={:08x}",
            t.contexts[t.active].id,
            core::str::from_utf8(name).unwrap_or("?"),
            arg(machine, regs, 0),
            arg(machine, regs, 1)
        );
    }
    let result = match name {
        b"RetroThreadPoll" => {
            state.threads = t;
            schedule(machine, state, regs);
            return Some(thread::KernelAction::Done);
        }
        b"InitializeCriticalSection" => {
            let address = arg(machine, regs, 0);
            t.critical.retain(|c| c.address != address);
            t.critical.push(Critical {
                address,
                owner: 0,
                count: 0,
            });
            machine.zero(address as usize, 24);
            machine.write::<i32>(address as usize + 4, -1);
            0
        }
        b"DeleteCriticalSection" => {
            let address = arg(machine, regs, 0);
            t.critical.retain(|c| c.address != address);
            0
        }
        b"EnterCriticalSection" => {
            let address = arg(machine, regs, 0);
            let id = t.contexts[t.active].id;
            if let Some(c) = t.critical.iter_mut().find(|c| c.address == address) {
                if c.owner == 0 || c.owner == id {
                    c.owner = id;
                    c.count += 1;
                } else {
                    t.contexts[t.active].status = Status::Critical(address);
                }
            } else {
                t.critical.push(Critical {
                    address,
                    owner: id,
                    count: 1,
                });
            }
            0
        }
        b"LeaveCriticalSection" => {
            let address = arg(machine, regs, 0);
            let id = t.contexts[t.active].id;
            if let Some(c) = t
                .critical
                .iter_mut()
                .find(|c| c.address == address && c.owner == id)
            {
                c.count -= 1;
                if c.count == 0 {
                    c.owner = 0;
                }
            }
            0
        }
        b"CreateMutexA" => {
            let name = if arg(machine, regs, 2) != 0 {
                c_string(machine, arg(machine, regs, 2)).unwrap_or_default()
            } else {
                Vec::new()
            };
            if let Some(m) = t
                .mutexes
                .iter()
                .find(|m| !name.is_empty() && m.name == name)
            {
                state.last_error = 183;
                m.handle
            } else {
                let handle = state.next_object;
                state.next_object += 1;
                let initial = arg(machine, regs, 1) != 0;
                t.mutexes.push(Mutex {
                    handle,
                    name,
                    owner: if initial { t.contexts[t.active].id } else { 0 },
                    count: u32::from(initial),
                });
                state.last_error = 0;
                handle
            }
        }
        b"ReleaseMutex" => {
            let id = t.contexts[t.active].id;
            if let Some(m) = t
                .mutexes
                .iter_mut()
                .find(|m| m.handle == arg(machine, regs, 0) && m.owner == id)
            {
                m.count -= 1;
                if m.count == 0 {
                    m.owner = 0;
                }
                1
            } else {
                fail(state, 288, 0)
            }
        }
        b"CreateThread" => {
            let size = arg(machine, regs, 1)
                .clamp(64 * 1024, 16 * 1024 * 1024)
                .next_multiple_of(4096);
            let stack = super::extra::thread_stack(machine, state, size);
            if stack == 0 || arg(machine, regs, 2) == 0 {
                state.last_error = ERROR_INVALID_PARAMETER;
                0
            } else {
                let handle = state.next_object;
                state.next_object += 1;
                let id = 0x10000 + t.contexts.len() as u32;
                let mut child = *regs;
                child.set_ip32(arg(machine, regs, 2));
                child.frame.rsp = u64::from(stack + size - 8);
                child.rbp = 0;
                child.rax = 0;
                machine.write::<u32>((stack + size - 8) as usize, RETURN_STUB);
                machine.write::<u32>((stack + size - 4) as usize, arg(machine, regs, 3));
                let mut teb = [0u8; 4096];
                for (off, v) in [
                    (0, u32::MAX),
                    (4, stack + size),
                    (8, stack),
                    (0x18, TEB_BASE),
                    (0x20, 1),
                    (0x24, id),
                    (0x30, PEB_BASE),
                ] {
                    teb[off..off + 4].copy_from_slice(&v.to_le_bytes());
                }
                t.contexts.push(Context {
                    regs: child,
                    fx: Box::new(machine.clean_fx_template()),
                    id,
                    handle,
                    status: if arg(machine, regs, 4) & 4 != 0 {
                        Status::Suspended
                    } else {
                        Status::Ready
                    },
                    tls: [0; 64],
                    teb,
                    error: 0,
                    stack_base: stack,
                    stack_size: size,
                });
                if arg(machine, regs, 5) != 0 {
                    machine.write::<u32>(arg(machine, regs, 5) as usize, id);
                }
                state.last_error = 0;
                handle
            }
        }
        b"ExitThread" | b"RetroThreadReturn" => {
            let code = arg(machine, regs, 0);
            if t.active == 0 {
                state.threads = t;
                return Some(thread::KernelAction::Exit(code as i32));
            }
            t.contexts[t.active].status = Status::Exited(code);
            super::extra::thread_stack_free(state, t.contexts[t.active].stack_base);
            0
        }
        b"GetCurrentThreadId" => t.contexts[t.active].id,
        b"GetExitCodeThread" => {
            if let Some(c) = t
                .contexts
                .iter()
                .find(|c| c.handle == arg(machine, regs, 0))
            {
                machine.write::<u32>(
                    arg(machine, regs, 1) as usize,
                    if let Status::Exited(code) = c.status {
                        code
                    } else {
                        259
                    },
                );
                1
            } else {
                fail(state, ERROR_INVALID_HANDLE, 0)
            }
        }
        b"ResumeThread" => {
            if let Some(c) = t
                .contexts
                .iter_mut()
                .find(|c| c.handle == arg(machine, regs, 0))
            {
                let was = matches!(c.status, Status::Suspended);
                c.status = Status::Ready;
                u32::from(was)
            } else {
                fail(state, ERROR_INVALID_HANDLE, u32::MAX)
            }
        }
        b"TerminateThread" => {
            if let Some(c) = t
                .contexts
                .iter_mut()
                .find(|c| c.handle == arg(machine, regs, 0))
            {
                c.status = Status::Exited(arg(machine, regs, 1));
                1
            } else {
                fail(state, ERROR_INVALID_HANDLE, 0)
            }
        }
        b"CreateEventA" => {
            let handle = state.next_object;
            state.next_object += 1;
            t.events.push(Event {
                handle,
                manual: arg(machine, regs, 1) != 0,
                signaled: arg(machine, regs, 2) != 0,
            });
            handle
        }
        b"SetEvent" => {
            if let Some(e) = t
                .events
                .iter_mut()
                .find(|e| e.handle == arg(machine, regs, 0))
            {
                e.signaled = true;
                1
            } else {
                fail(state, ERROR_INVALID_HANDLE, 0)
            }
        }
        b"Sleep" => {
            if arg(machine, regs, 0) != 0 {
                t.contexts[t.active].status = Status::Sleeping(
                    machine
                        .now()
                        .saturating_add(u64::from(arg(machine, regs, 0)) * 1_000_000),
                );
            }
            0
        }
        b"WaitForSingleObject" | b"WaitForSingleObjectEx" => {
            let handle = arg(machine, regs, 0);
            let timeout = arg(machine, regs, 1);
            let id = t.contexts[t.active].id;
            match signaled(&mut t, handle, id) {
                Some(true) => 0,
                Some(false) if timeout == 0 => 258,
                Some(false) => {
                    let deadline = if timeout == u32::MAX {
                        u64::MAX
                    } else {
                        machine.now().saturating_add(u64::from(timeout) * 1_000_000)
                    };
                    t.contexts[t.active].status = Status::Waiting(handle, deadline);
                    258
                }
                None if handle >= 0x10000 => 0, // existing mutex/process handles
                None => fail(state, ERROR_INVALID_HANDLE, u32::MAX),
            }
        }
        _ => unreachable!(),
    };
    if !matches!(name, b"ExitThread" | b"RetroThreadReturn") {
        finish(machine, regs, gate, result);
    }
    state.threads = t;
    schedule(machine, state, regs);
    Some(thread::KernelAction::Done)
}

pub(super) fn schedule<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, regs: &mut Regs) {
    if state.threads.contexts.is_empty() || state.callback.is_some() {
        return;
    }
    let mut t = core::mem::take(&mut state.threads);
    if !t.polling {
        let c = &mut t.contexts[t.active];
        c.regs = *regs;
        c.tls = state.tls;
        c.error = state.last_error;
        c.stack_base = state.stack_base;
        c.stack_size = state.stack_size;
        machine.copy_from(TEB_BASE as usize, &mut c.teb);
    }
    let now = machine.now();
    for i in 0..t.contexts.len() {
        match t.contexts[i].status {
            Status::Sleeping(deadline) if now >= deadline => t.contexts[i].status = Status::Ready,
            Status::Waiting(handle, deadline) => {
                let id = t.contexts[i].id;
                let ready = signaled(&mut t, handle, id) == Some(true);
                if ready || now >= deadline {
                    t.contexts[i].status = Status::Ready;
                    t.contexts[i].regs.rax = if ready { 0 } else { 258 };
                }
            }
            Status::Critical(address) => {
                if let Some(c) = t
                    .critical
                    .iter_mut()
                    .find(|c| c.address == address && c.owner == 0)
                {
                    c.owner = t.contexts[i].id;
                    c.count = 1;
                    t.contexts[i].status = Status::Ready;
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
        machine.copy_to(TEB_BASE as usize, &c.teb);
    } else {
        t.polling = true;
        regs.set_ip32(RETURN_STUB + 16);
    }
    state.threads = t;
}
