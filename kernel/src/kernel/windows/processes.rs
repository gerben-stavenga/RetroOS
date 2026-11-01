//! Child processes use the common executable launcher and waitable objects.
use super::*;

struct Child {
    pid: u32,
    handles: [u32; 2],
    suspended: bool,
    code: Option<i32>,
}
#[derive(Default)]
pub(super) struct State {
    children: Vec<Child>,
    pending: bool,
    environment: Option<Vec<u8>>,
    completed: Vec<i32>,
}
impl WindowsState {
    pub(crate) fn waits_for_child(&self) -> bool {
        self.processes
            .children
            .iter()
            .any(|c| !c.suspended && c.code.is_none())
    }
    pub(crate) fn child_environment(&mut self) -> Vec<u8> {
        self.processes
            .environment
            .take()
            .unwrap_or_else(|| self.environment.clone())
    }
    pub(crate) fn child_started(&mut self, pid: u32) -> bool {
        if !core::mem::take(&mut self.processes.pending) {
            return false;
        }
        self.processes.children.push(Child {
            pid,
            handles: [0; 2],
            suspended: true,
            code: None,
        });
        true
    }
    pub(crate) fn child_exited(&mut self, pid: u32, code: i32) {
        if let Some(i) = self.processes.children.iter().position(|c| c.pid == pid) {
            let c = &mut self.processes.children[i];
            c.code = Some(code);
            for handle in c.handles {
                threads::signal(&mut self.threads, handle);
            }
            if c.handles == [0, 0] {
                self.processes.completed.push(pid as i32 - 1);
                self.processes.children.remove(i);
            }
        }
    }
    pub(crate) fn take_completed_children(&mut self) -> Vec<i32> {
        core::mem::take(&mut self.processes.completed)
    }
    pub(crate) fn sync_process_cwd<A: crate::Arch>(&self, machine: &mut A) {
        let cwd = process_cwd(self.cwd_str());
        let units = encoding::encode(&cwd, true);
        if units.len() >= 256 {
            return;
        }
        encoding::copy(machine, (PROCESS_DATA + 0x400) as usize, 256, &cwd, true);
        machine.write::<u16>((PROCESS_DATA + 0x24) as usize, (units.len() * 2) as u16);
    }
}
pub(super) fn close(state: &mut WindowsState, handle: u32) {
    for c in &mut state.processes.children {
        for h in &mut c.handles {
            if *h == handle {
                *h = 0;
            }
        }
    }
    for i in (0..state.processes.children.len()).rev() {
        let c = &state.processes.children[i];
        if c.handles == [0, 0] && c.code.is_some() {
            state.processes.completed.push(c.pid as i32 - 1);
            state.processes.children.remove(i);
        }
    }
}
fn wide<A: crate::Arch>(machine: &A, pointer: u32, length: u32) -> Option<Vec<u8>> {
    if length & 1 != 0 || length > 32766 || pointer == 0 && length != 0 {
        return None;
    }
    let units: Vec<u16> = (0..length / 2)
        .map(|i| machine.read::<u16>((pointer + i * 2) as usize))
        .collect();
    alloc::string::String::from_utf16(&units)
        .ok()
        .map(|s| s.into_bytes())
}
pub(super) fn spawn<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &mut Regs,
    gate: Gate,
) -> thread::KernelAction {
    let params = arg(machine, regs, 0) as usize;
    let p: [u32; 8] = core::array::from_fn(|i| machine.read::<u32>(params + i * 4));
    let result = (|| {
        let path = wide(machine, p[0], p[1]).ok_or(-22)?;
        let command = wide(machine, p[2], p[3]).ok_or(-22)?;
        let cwd = wide(machine, p[4], p[5]).ok_or(-22)?;
        let env = wide(machine, p[6], p[7]).ok_or(-22)?;
        let path = windows_path(state, &path, false).map_err(|_| -2)?;
        let cwd = windows_path(state, &cwd, false).map_err(|_| -2)?;
        let mut at = 0;
        if command.first() == Some(&b'"') {
            at = 1;
            while at < command.len() && command[at] != b'"' {
                at += 1;
            }
            if at < command.len() {
                at += 1;
            }
        } else {
            while at < command.len() && !command[at].is_ascii_whitespace() {
                at += 1;
            }
        }
        while at < command.len() && command[at].is_ascii_whitespace() {
            at += 1;
        }
        let tail = &command[at..];
        if path.len() > 164 || cwd.len() > 164 || tail.len() > 127 || env.len() > 4096 {
            return Err(-22);
        }
        let mut image = [0; 164];
        image[..path.len()].copy_from_slice(&path);
        let mut directory = [0; 164];
        directory[..cwd.len()].copy_from_slice(&cwd);
        let mut args = [0; 128];
        args[..tail.len()].copy_from_slice(tail);
        state.processes.pending = true;
        state.processes.environment = Some(env);
        Ok(thread::KernelAction::ForkExec {
            path: image,
            path_len: path.len(),
            cmdtail: args,
            cmdtail_len: tail.len(),
            cwd: directory,
            cwd_len: cwd.len(),
            personality_name: None,
            policy: Default::default(),
            on_error: spawn_error,
            on_success: spawn_success,
        })
    })();
    finish(machine, regs, gate, 0);
    match result {
        Ok(action) => action,
        Err(error) => {
            regs.rax = error as i64 as u64;
            thread::KernelAction::Done
        }
    }
}
fn spawn_error(regs: &mut Regs, error: i32) {
    regs.rax = -(i64::from(error.unsigned_abs())) as u64;
}
fn spawn_success(regs: &mut Regs, tid: i32) {
    regs.rax = (tid + 1) as u64;
}

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &mut Regs,
    gate: Gate,
) -> thread::KernelAction {
    let op = arg(machine, regs, 0);
    let handle = arg(machine, regs, 1);
    let out = arg(machine, regs, 3) as usize;
    if op == 3 {
        state.processes.pending = false;
        state.processes.environment = None;
        finish(machine, regs, gate, 0);
        return thread::KernelAction::Done;
    }
    let index = state.processes.children.iter().position(|c| {
        if op == 0 {
            c.pid == handle
        } else {
            c.handles.contains(&handle) && handle != 0
        }
    });
    let Some(index) = index else {
        finish(machine, regs, gate, 0xc0000008);
        return thread::KernelAction::Done;
    };
    let mut action = thread::KernelAction::Done;
    let status = match op {
        0 => {
            let handles = [
                threads::create_event(state, true, false),
                threads::create_event(state, true, false),
            ];
            state.processes.children[index].handles = handles;
            machine.write::<u32>(out, handles[0]);
            machine.write::<u32>(out + 4, handles[1]);
            0
        }
        1 => {
            let c = &mut state.processes.children[index];
            machine.write::<u32>(out, u32::from(c.suspended));
            if c.suspended {
                c.suspended = false;
                action = thread::KernelAction::WakeChild(c.pid as usize - 1);
            }
            0
        }
        2 => {
            let c = &state.processes.children[index];
            machine.write::<u32>(out, c.code.map_or(0x103, |v| v as u32));
            machine.write::<u32>(out + 4, c.pid);
            0
        }
        _ => 0xc000000d,
    };
    finish(machine, regs, gate, status);
    action
}
