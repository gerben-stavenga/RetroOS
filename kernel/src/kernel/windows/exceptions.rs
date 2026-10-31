//! Saved CPU state transport. Wine owns SEH traversal and instruction recovery.
use super::*;
use alloc::boxed::Box;
#[derive(Default)]
pub(super) struct State {
    frames: Vec<(u32, Box<dyn core::any::Any>)>,
}
const WORDS: usize = 16;
fn words(r: &Regs) -> [u32; WORDS] {
    [
        r.rdi as u32,
        r.rsi as u32,
        r.rbx as u32,
        r.rdx as u32,
        r.rcx as u32,
        r.rax as u32,
        r.rbp as u32,
        r.ip32(),
        r.sp32(),
        r.frame.rflags as u32,
        r.frame.cs as u32,
        r.frame.ss as u32,
        r.ds as u32,
        r.es as u32,
        r.fs as u32,
        r.gs as u32,
    ]
}
pub(super) fn deliver<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &mut Regs,
    code: u32,
) -> bool {
    let Ok(entry) = export_address(&state.modules, b"RETROOS", b"RetroDispatchFault") else {
        return false;
    };
    let mut flat = Regs::empty();
    flat.init_user_process(0, 0);
    let top = if regs.frame.ss == flat.frame.ss {
        regs.sp32()
    } else {
        machine.read::<u32>((state.teb_base + 0x10c) as usize)
    };
    let Some(sp) = top.checked_sub(128).map(|s| (s & !15) - 4) else {
        return false;
    };
    if sp < state.stack_base.saturating_add(4096) || top > state.stack_base + state.stack_size {
        return false;
    }
    let raw = sp + 16;
    for (i, v) in words(regs).iter().enumerate() {
        machine.write::<u32>(raw as usize + i * 4, *v);
    }
    machine.write::<u32>(sp as usize, 0);
    machine.write::<u32>(sp as usize + 4, raw);
    machine.write::<u32>(sp as usize + 8, code);
    let mut fx = machine.clean_fx_template();
    machine.switch_fx(&mut fx);
    state.exceptions.frames.push((state.teb_base, Box::new(fx)));
    let fs = regs.fs;
    regs.init_user_process(entry, sp);
    regs.fs = fs;
    true
}
fn selector(state: &WindowsState, value: u32, kind: u32) -> bool {
    let mut flat = Regs::empty();
    flat.init_user_process(0, 0);
    if kind == 0 && value == flat.frame.cs as u32 {
        return true;
    }
    if kind != 0 && value == flat.frame.ss as u32 {
        return true;
    }
    if kind == 2 && value == 0 {
        return true;
    }
    if value > 0xffff || value & 7 != 7 {
        return false;
    }
    let Some(&d) = state.ldt.get((value >> 3) as usize) else {
        return false;
    };
    let access = (d >> 40) as u8;
    access & 0xf0 == 0xf0
        && if kind == 0 {
            access & 8 != 0
        } else if kind == 1 {
            access & 0xa == 2
        } else {
            access & 8 == 0 || access & 2 != 0
        }
}
pub(super) fn restore<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &mut Regs,
    address: u32,
) -> u32 {
    let w: [u32; WORDS] = core::array::from_fn(|i| machine.read::<u32>(address as usize + i * 4));
    if !selector(state, w[10], 0)
        || !selector(state, w[11], 1)
        || w[12..].iter().any(|&s| !selector(state, s, 2))
    {
        return 0xc000000d;
    }
    if let Some(i) = state
        .exceptions
        .frames
        .iter()
        .rposition(|f| f.0 == state.teb_base)
    {
        let (_, fx) = state.exceptions.frames.remove(i);
        let mut fx = *fx.downcast::<A::Fx>().unwrap();
        machine.switch_fx(&mut fx);
    }
    regs.rdi = w[0] as u64;
    regs.rsi = w[1] as u64;
    regs.rbx = w[2] as u64;
    regs.rdx = w[3] as u64;
    regs.rcx = w[4] as u64;
    regs.rax = w[5] as u64;
    regs.rbp = w[6] as u64;
    regs.frame.rip = w[7] as u64;
    regs.frame.rsp = w[8] as u64;
    // Only user-controlled flag bits; VIF represents the guest's IF.
    regs.frame.rflags =
        (w[9] as u64 & 0x00250fd5) | 0x202 | if w[9] & 0x200 != 0 { 1 << 19 } else { 0 };
    regs.frame.cs = w[10] as u64;
    regs.frame.ss = w[11] as u64;
    regs.ds = w[12] as u64;
    regs.es = w[13] as u64;
    regs.fs = w[14] as u64;
    regs.gs = w[15] as u64;
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_selectors_stay_in_user_mode() {
        let mut state = WindowsState::new();
        let mut flat = Regs::empty();
        flat.init_user_process(0, 0);
        assert!(selector(&state, flat.frame.cs as u32, 0));
        assert!(selector(&state, flat.frame.ss as u32, 1));
        assert!(!selector(&state, 8, 0));
        assert!(!selector(&state, 0, 1));
        assert!(selector(&state, 0, 2));
        state.ldt.push(descriptor(0x10000, 0xffff));
        assert!(selector(&state, 15, 1));
        assert!(!selector(&state, 15, 0));
        assert!(!selector(&state, 12, 1));
        state.ldt[1] &= !(1 << 47);
        assert!(!selector(&state, 15, 1));
    }
}
