//! Linux x86-64 signal frames, masks and rt_sigreturn ABI.
use super::{Args, LinuxState, SyscallResult, async_io, thread};
use crate::Regs;
use alloc::{collections::BTreeMap, vec::Vec};

const USER_END: u64 = 0xc0000000;
const UNBLOCKABLE: u64 = (1 << 8) | (1 << 18);
const SA_RESTORER: u64 = 0x04000000;
const SA_ONSTACK: u64 = 0x08000000;
const SA_NODEFER: u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;
const UC: usize = 8;
const MC: usize = UC + 40;
const MASK: usize = UC + 296;
const INFO: usize = UC + 304;
const FP: usize = 440;
const FRAME_SIZE: usize = FP + 512;

#[derive(Clone, Copy, Default)]
struct Action {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}
#[derive(Clone, Copy, Default)]
struct Local {
    mask: u64,
    saved_wait_mask: Option<u64>,
    stack: u64,
    size: u64,
}
/// pselect installs its mask atomically with entering the wait. Keep the
/// original mask for normal completion or the signal frame's rt_sigreturn.
pub(super) fn begin_wait(state: &mut State, tid: i32, mask: Option<u64>) {
    if let Some(mask) = mask {
        let local = state.locals.entry(tid).or_default();
        assert!(local.saved_wait_mask.is_none());
        local.saved_wait_mask = Some(local.mask);
        local.mask = mask & !UNBLOCKABLE;
    }
}
pub(super) fn finish_wait(state: &mut State, tid: i32) {
    if let Some(local) = state.locals.get_mut(&tid)
        && let Some(mask) = local.saved_wait_mask.take() { local.mask = mask; }
}
#[derive(Clone)]
struct Frame {
    tid: i32,
    base: usize,
    regs: Regs,
}
#[derive(Clone)]
pub(super) struct State {
    actions: [Action; 65],
    locals: BTreeMap<i32, Local>,
    frames: Vec<Frame>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            actions: [Action::default(); 65],
            locals: BTreeMap::new(),
            frames: Vec::new(),
        }
    }
}
fn valid(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr.checked_add(len).is_some_and(|end| end <= USER_END)
}
fn on_stack(local: Local, rsp: u64) -> bool {
    local.size != 0 && rsp.wrapping_sub(local.stack) < local.size
}
pub(super) fn inherit(state: &mut State, parent: i32, child: i32) {
    let mask = state.locals.get(&parent).map_or(0, |local| local.mask);
    state.locals.insert(
        child,
        Local {
            mask,
            ..Local::default()
        },
    );
}
pub(super) fn fork(state: &State, parent: i32, child: i32) -> State {
    let mut copy = State {
        actions: state.actions,
        ..State::default()
    };
    copy.locals.insert(
        child,
        state.locals.get(&parent).copied().unwrap_or_default(),
    );
    copy.frames = state
        .frames
        .iter()
        .filter(|frame| frame.tid == parent)
        .map(|frame| Frame {
            tid: child,
            ..frame.clone()
        })
        .collect();
    copy
}
pub(super) fn exec(state: &State, parent: i32, process: i32) -> State {
    let mut copy = State::default();
    for (new, old) in copy.actions.iter_mut().zip(&state.actions) {
        if old.handler == 1 {
            *new = *old;
        }
    }
    inherit(&mut copy, process, process);
    copy.locals.get_mut(&process).unwrap().mask =
        state.locals.get(&parent).map_or(0, |local| local.mask);
    copy
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    linux: &mut LinuxState,
    regs: &mut Regs,
    nr: u32,
    a: &Args,
) -> SyscallResult {
    let tid = async_io::current_id(&linux.async_io, kt.tid);
    let state = &mut linux.signals;
    if nr == 15 {
        return match restore(machine, state, tid, regs) {
            Some(value) => SyscallResult::val64(value),
            None => SyscallResult::act(0, thread::KernelAction::Exit(-11)),
        };
    }
    let result = match nr {
        13 => {
            let sig = a.a0 as usize;
            if a.a0 > 64 || sig == 0 || a.a3 != 8 || (a.a1 != 0 && matches!(sig, 9 | 19)) {
                return SyscallResult::val(-22);
            }
            if (a.a1 != 0 && !valid(a.a1, 32)) || (a.a2 != 0 && !valid(a.a2, 32)) {
                return SyscallResult::val(-14);
            }
            let new = (a.a1 != 0).then(|| Action {
                handler: machine.read(a.a1 as usize),
                flags: machine.read(a.a1 as usize + 8),
                restorer: machine.read(a.a1 as usize + 16),
                mask: machine.read(a.a1 as usize + 24),
            });
            let old = state.actions[sig];
            if a.a2 != 0 {
                for (i, value) in [old.handler, old.flags, old.restorer, old.mask]
                    .iter()
                    .enumerate()
                {
                    machine.write(a.a2 as usize + i * 8, *value);
                }
            }
            if let Some(mut action) = new {
                action.mask &= !UNBLOCKABLE;
                state.actions[sig] = action;
            }
            0
        }
        14 => {
            if a.a3 != 8 || (a.a1 != 0 && a.a0 > 2) {
                return SyscallResult::val(-22);
            }
            let new = if a.a1 != 0 {
                let mut bytes = [0; 8];
                if !super::high_memory::copy_from(machine, a.a1, &mut bytes) { return SyscallResult::val(-14); }
                Some(u64::from_le_bytes(bytes))
            } else { None };
            let local = state.locals.entry(tid).or_default();
            if a.a2 != 0 && !super::high_memory::copy_to(machine, a.a2, &local.mask.to_le_bytes()) { return SyscallResult::val(-14); }
            if let Some(mask) = new {
                local.mask = match a.a0 {
                    0 => local.mask | mask,
                    1 => local.mask & !mask,
                    _ => mask,
                } & !UNBLOCKABLE;
            }
            0
        }
        131 => {
            let old = state.locals.get(&tid).copied().unwrap_or_default();
            let active = on_stack(old, regs.frame.rsp);
            let new = if a.a0 != 0 {
                if active {
                    return SyscallResult::val(-1);
                }
                let mut bytes = [0; 24];
                if !super::high_memory::copy_from(machine, a.a0, &mut bytes) { return SyscallResult::val(-14); }
                let flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
                let stack = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                let size = u64::from_le_bytes(bytes[16..].try_into().unwrap());
                if flags != 0 && flags != 2 {
                    return SyscallResult::val(-22);
                }
                if flags == 0 && size < 2048 {
                    return SyscallResult::val(-12);
                }
                if flags == 0 && !super::high_memory::range(stack, size) {
                    return SyscallResult::val(-14);
                }
                Some(if flags == 2 {
                    Local {
                        mask: old.mask,
                        ..Local::default()
                    }
                } else {
                    Local { stack, size, ..old }
                })
            } else {
                None
            };
            if a.a1 != 0 {
                let mut bytes = [0; 24];
                bytes[..8].copy_from_slice(&old.stack.to_le_bytes());
                bytes[8..12].copy_from_slice(&(if old.size == 0 { 2 } else { u32::from(active) }).to_le_bytes());
                bytes[16..].copy_from_slice(&old.size.to_le_bytes());
                if !super::high_memory::copy_to(machine, a.a1, &bytes) { return SyscallResult::val(-14); }
            }
            if let Some(local) = new {
                state.locals.insert(tid, local);
            }
            0
        }
        _ => -38,
    };
    SyscallResult::val(result)
}

pub(super) fn deliver_fault<A: crate::Arch>(
    machine: &mut A,
    linux: &mut LinuxState,
    process: i32,
    regs: &mut Regs,
    addr: u64,
) -> bool {
    deliver(
        machine,
        linux,
        process,
        regs,
        11,
        if regs.err_code & 1 == 0 { 1 } else { 2 },
        addr,
    )
}

pub(super) fn debug_state(linux: &LinuxState, process: i32) {
    let action = linux.signals.actions[17];
    crate::compact_dbg_println!("[LINUX SIGCHLD] pid={} handler={:#x} flags={:#x} frames={}",
        process, action.handler, action.flags, linux.signals.frames.len());
    for (&tid, local) in &linux.signals.locals {
        crate::compact_dbg_println!("[LINUX SIGMASK] pid={} tid={} mask={:#x}", process, tid, local.mask);
    }
}

pub(super) fn handler(linux: &LinuxState, signal: usize) -> u64 { linux.signals.actions[signal].handler }

pub(super) fn disposition(linux: &LinuxState, tid: i32, signal: usize) -> Option<bool> {
    let local = linux.signals.locals.get(&tid).copied().unwrap_or_default();
    if local.mask & (1 << (signal - 1)) != 0 {
        return None;
    }
    Some(linux.signals.actions[signal].handler == 1)
}

pub(super) fn deliver<A: crate::Arch>(
    machine: &mut A,
    linux: &mut LinuxState,
    process: i32,
    regs: &mut Regs,
    signal: usize,
    code: i32,
    addr: u64,
) -> bool {
    if regs.mode() != crate::UserMode::Mode64 {
        return false;
    }
    let fault = signal == 11 && matches!(code, 1 | 2);
    let tid = async_io::current_id(&linux.async_io, process);
    let state = &mut linux.signals;
    let action = state.actions[signal];
    let local = state.locals.get(&tid).copied().unwrap_or_default();
    if action.handler <= 1
        || !valid(action.handler, 1)
        || action.flags & SA_RESTORER == 0
        || !valid(action.restorer, 1)
        || local.mask & (1 << (signal - 1)) != 0
    {
        return false;
    }
    let using_alt =
        action.flags & SA_ONSTACK != 0 && local.size != 0 && !on_stack(local, regs.frame.rsp);
    let top = if using_alt {
        local.stack + local.size
    } else {
        regs.frame.rsp
    };
    let Some(base) = top
        .checked_sub((128 + FRAME_SIZE + 64) as u64)
        .map(|p| (p & !63) + 8)
    else {
        return false;
    };
    if !valid(base, FRAME_SIZE as u64)
        || ((using_alt || on_stack(local, regs.frame.rsp)) && base < local.stack)
    {
        return false;
    }
    let base = base as usize;
    // Snapshot without disturbing the live floating point state.
    let mut fx = machine.clean_fx_template();
    machine.switch_fx(&mut fx);
    let image = A::fx_state_bytes(&fx).copied();
    machine.switch_fx(&mut fx);
    let Some(image) = image else {
        return false;
    };
    machine.zero(base, FRAME_SIZE);
    machine.write(base, action.restorer);
    machine.write(base + UC + 16, local.stack);
    machine.write::<u32>(
        base + UC + 24,
        if local.size == 0 {
            2
        } else {
            u32::from(on_stack(local, regs.frame.rsp))
        },
    );
    machine.write(base + UC + 32, local.size);
    let general = [
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
        regs.r12,
        regs.r13,
        regs.r14,
        regs.r15,
        regs.rdi,
        regs.rsi,
        regs.rbp,
        regs.rbx,
        regs.rdx,
        regs.rax,
        regs.rcx,
        regs.frame.rsp,
        regs.frame.rip,
        regs.frame.rflags,
        regs.frame.cs | (regs.frame.ss << 48),
        if fault { regs.err_code } else { 0 },
        if fault { 14 } else if signal == 4 && code == 2 { 6 } else { 0 },
        local.saved_wait_mask.unwrap_or(local.mask),
        if fault { addr } else { 0 },
    ];
    for (index, value) in general.iter().enumerate() {
        machine.write(base + MC + index * 8, *value);
    }
    machine.write::<u64>(base + MC + 184, (base + FP) as u64);
    machine.write(base + MASK, local.saved_wait_mask.unwrap_or(local.mask));
    machine.write::<i32>(base + INFO, signal as i32);
    machine.write::<i32>(base + INFO + 8, code);
    machine.write::<u64>(base + INFO + 16, addr);
    if matches!(code, 0 | -6) && !fault {
        machine.write::<u32>(base + INFO + 20, super::environment::identity().0);
    }
    machine.copy_to(base + FP, &image);
    state.frames.push(Frame {
        tid,
        base,
        regs: *regs,
    });
    state.locals.entry(tid).or_default().saved_wait_mask = None;
    state.locals.entry(tid).or_default().mask = (local.mask
        | action.mask
        | if action.flags & SA_NODEFER == 0 {
            1 << (signal - 1)
        } else {
            0
        })
        & !UNBLOCKABLE;
    if action.flags & SA_RESETHAND != 0 {
        state.actions[signal] = Action::default();
    }
    regs.frame.rsp = base as u64;
    regs.frame.rip = action.handler;
    regs.frame.rflags &= !(0x100 | 0x400); // clear TF and DF on handler entry
    regs.rdi = signal as u64;
    regs.rsi = (base + INFO) as u64;
    regs.rdx = (base + UC) as u64;
    regs.rax = 0;
    true
}

pub(super) fn deliver_child_exit<A: crate::Arch>(
    machine: &mut A, linux: &mut LinuxState, process: i32, regs: &mut Regs,
    child: i32, exit_code: i32,
) -> bool {
    let signaled = (-64..0).contains(&exit_code);
    if !deliver(machine, linux, process, regs, 17, if signaled { 2 } else { 1 }, child as u64) {
        return false;
    }
    machine.write::<i32>(regs.frame.rsp as usize + INFO + 24,
        if signaled { -exit_code } else { exit_code & 0xff });
    true
}

fn restore<A: crate::Arch>(
    machine: &mut A,
    state: &mut State,
    tid: i32,
    regs: &mut Regs,
) -> Option<i64> {
    let base = regs.frame.rsp.checked_sub(8)? as usize;
    let index = state.frames.iter().rposition(|frame| frame.tid == tid)?;
    if state.frames[index].base != base || !valid(base as u64, FRAME_SIZE as u64) {
        return None;
    }
    let mut general = [0u64; 23];
    for (i, value) in general.iter_mut().enumerate() {
        *value = machine.read(base + MC + i * 8);
    }
    if !valid(general[16], 1) || !valid(general[15], 1) {
        return None;
    }
    let ptr = machine.read::<u64>(base + MC + 184);
    let mut fx = machine.clean_fx_template();
    if ptr != 0 {
        if !valid(ptr, 512) {
            return None;
        }
        let bytes = A::fx_state_bytes_mut(&mut fx)?;
        let allowed = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
        let allowed = if allowed == 0 { 0xffbf } else { allowed };
        machine.copy_from(ptr as usize, bytes);
        let mxcsr = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        // Reserved MXCSR bits cause #GP in FXRSTOR; never pass them to arch.
        if mxcsr & !allowed != 0 {
            return None;
        }
    }
    let original = state.frames.remove(index).regs;
    *regs = original;
    regs.r8 = general[0];
    regs.r9 = general[1];
    regs.r10 = general[2];
    regs.r11 = general[3];
    regs.r12 = general[4];
    regs.r13 = general[5];
    regs.r14 = general[6];
    regs.r15 = general[7];
    regs.rdi = general[8];
    regs.rsi = general[9];
    regs.rbp = general[10];
    regs.rbx = general[11];
    regs.rdx = general[12];
    regs.rax = general[13];
    regs.rcx = general[14];
    regs.frame.rsp = general[15];
    regs.frame.rip = general[16];
    const USER_FLAGS: u64 = 0x254dd5;
    regs.frame.rflags = (original.frame.rflags & !USER_FLAGS) | (general[17] & USER_FLAGS);
    state.locals.entry(tid).or_default().mask = machine.read::<u64>(base + MASK) & !UNBLOCKABLE;
    machine.switch_fx(&mut fx);
    Some(regs.rax as i64)
}
