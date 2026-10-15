//! DOS program execution, parent restoration and COM/MZ loaders.

use crate::Regs;
use crate::kernel::thread;
use crate::kernel::dos::{
    ExecParent, dfs, dos_alloc_block, dos_keep_resident_block, dos_set_program_block_owner, machine, mode_transitions,
    seg_offset, snapshot_env,
};
use crate::kernel::dos::machine::{read_u16, vm86_push, vm86_sp, vm86_ss, write_u16};
use super::files::{dfs_open_existing, read_asciiz};
use super::lowmem::{ENV_PARAS, Psp, STUB_SEG, slot_offset};

/// .COM entry IP (relative to its PSP segment). Equivalent to `(psp+0x10):0000`.
const COM_OFFSET: u16 = 0x0100;
/// Initial stack pointer for .COM (top of PSP's 64KB segment)
const COM_SP: u16 = 0xFFFE;
const EXEC_SAVED_IVT_VECTORS: [u8; 11] =
    [0x13, 0x20, 0x21, 0x25, 0x26, 0x28, 0x29, 0x2E, 0x2F, 0x33, 0x67];

// /// DOS INT 21h/4B — Load and Execute Program
// ///
// /// Try to open a program file via VFS. If the name has no extension (no dot),
// /// try appending .COM and .EXE (DOS convention).
// ============================================================================
// INT 2Eh — COMMAND.COM internal execute
// ============================================================================

pub(super) fn int_2eh<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    // DS:SI = pointer to command-line length byte + text (same as PSP:80h format)
    // Treat as COMMAND.COM /C — fork-exec the program in a fresh address space.
    let addr = seg_offset(dos, regs, regs.ds as u16, regs.rsi as u32);
    let len = machine.read::<u8>((addr) as usize) as usize;
    let mut cmd = [0u8; 128];
    let copy = len.min(127);
    machine.copy_from((addr + 1) as usize, &mut cmd[..copy]);
    let mut start = 0;
    while start < copy && cmd[start] == b' ' { start += 1; }
    let mut end = start;
    while end < copy && cmd[end] != b' ' && cmd[end] != b'\r' && cmd[end] != 0 { end += 1; }
    if end <= start { return thread::KernelAction::Done; }

    // Shift the program name to the start of the buffer.
    let plen = end - start;
    cmd.copy_within(start..end, 0);
    fork_exec(dos, &cmd[..plen], b"", Default::default(), regs, kt)
}

/// Open a DOS program file by literal name. No extension probing, no
/// PATH search -- those are shell concerns and live in COMMAND.COM,
/// matching real DOS where INT 21h AH=4B takes a fully-qualified name.
fn dos_open_program<A: crate::Arch>(kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, name: &[u8]) -> i32 {
    match dfs_open_existing(dos, name) {
        Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
        Err(_) => -2,
    }
}

/// Resolve path and return ForkExec action for the event loop to execute.
/// Synth ABI: on success BX=child_tid, CF=0. On error AX=errno, CF=1.
pub(super) fn fork_exec<A: crate::Arch>(dos: &mut thread::DosState<A>, prog_name: &[u8], cmdtail: &[u8], mut policy: crate::kernel::dos::LaunchPolicy, regs: &mut Regs, _kt: &mut thread::KernelThread<A>) -> thread::KernelAction {
    // Verify the file exists (DFS resolve → VFS → would-be open); ENOENT else.
    if dfs_open_existing(dos, prog_name).is_err() {
        regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    // Carry the absolute DOS path (the launcher's namespace), NOT the VFS path.
    // This is the program name a DOS extender reopens its own EXE by, so it must
    // be a real DOS path (the 8.3 names DN/the program used) — `resolve` keeps
    // them verbatim. It's mapped back to VFS only for the read (handle_fork_exec).
    // No VFS form ever reaches the DOS env, and ForkExec stays generic (a
    // personality tag, not a VFS/DOS path field).
    let mut path = [0u8; 164];
    let mut dos_abs = [0u8; dfs::DFS_PATH_MAX];
    let path_len = match dos.dfs.resolve(prog_name, &mut dos_abs) {
        Ok(n) => { path[..n].copy_from_slice(&dos_abs[..n]); n }
        Err(_) => {
            regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }
    };

    fn on_error(regs: &mut Regs, err: i32) {
        regs.rax = (regs.rax & !0xFFFF) | err as u64;
        regs.set_flag32(1);
    }

    fn on_success(regs: &mut Regs, child_tid: i32) {
        regs.rax &= !0xFFFF;                            // AX=0 success
        regs.rbx = (regs.rbx & !0xFFFF) | ((child_tid as u16) as u64);
        regs.clear_flag32(1);
    }

    let mut cmdtail_buf = [0u8; 128];
    let cmdtail_len = cmdtail.len().min(127);
    cmdtail_buf[..cmdtail_len].copy_from_slice(&cmdtail[..cmdtail_len]);
    // This fork establishes a new DOS session. Its later INT 21h EXEC calls
    // (including nested COMMAND.COM /C) must share its resident memory.
    policy.tsr_session = true;

    thread::KernelAction::ForkExec {
        path,
        path_len,
        cmdtail: cmdtail_buf,
        cmdtail_len,
        cwd: [0; 164],
        cwd_len: 0,
        personality_name: Some(thread::PersonalityName::Dos),
        policy,
        on_error,
        on_success,
    }
}

/// Replace a one-shot shell's process, retaining its TID for a Win32
/// CreateProcess caller. DOS INT 21h EXEC is nested and returns to the shell;
/// it cannot provide this process-level replacement.
pub(super) fn exec_replace<A: crate::Arch>(
    machine: &mut A,
    dos: &mut thread::DosState<A>,
    prog_name: &[u8],
    cmdtail: &[u8],
    mut policy: crate::kernel::dos::LaunchPolicy,
    regs: &mut Regs,
) -> thread::KernelAction {
    let fail = |regs: &mut Regs| {
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        thread::KernelAction::Done
    };
    let mut dos_abs = [0u8; dfs::DFS_PATH_MAX];
    let Ok(path_len) = dos.dfs.resolve(prog_name, &mut dos_abs) else {
        return fail(regs);
    };
    let path = dos_abs[..path_len].to_vec();
    let Some(vfs_path) = crate::kernel::dos::dos_abs_to_vfs(&path) else {
        return fail(regs);
    };
    let Ok(buffer) = crate::kernel::exec::load_file_resolved(&vfs_path) else {
        return fail(regs);
    };
    let mut cwd = alloc::vec::Vec::with_capacity(66);
    cwd.push(b'A' + dos.dfs.current_drive_number());
    cwd.push(b':');
    cwd.extend(dos.dfs.get_cwd().iter().map(|&c| if c == b'\\' { b'/' } else { c }));
    let env = crate::kernel::dos::snapshot_parent_env(machine, regs, dos);
    // The replaced shell's process is now the DOS session, just as a child
    // created by fork_exec would be.
    policy.tsr_session = true;
    thread::KernelAction::Exec {
        buffer: buffer.into(),
        path: path.clone(),
        args: alloc::vec![path],
        cmdtail: cmdtail.to_vec(),
        env,
        cwd,
        personality_name: Some(thread::PersonalityName::Dos),
        policy,
    }
}

/// DOS INT 4Bh EXEC — load and execute a DOS program in-process.
/// Loads a .COM or MZ .EXE into a fresh child segment above `heap_seg`,
/// shares the address space with the parent, and transfers control.
/// Parent resumes via exec_return on child INT 20h / 4C00.
/// Non-DOS formats (ELF, BAT) should be routed through COMMAND.COM /C.
/// A batch shell keeps its DOS children in this address space so resident
/// drivers remain visible; standalone commands may fork into new threads.
pub(super) fn exec_program<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let al = regs.rax as u8;
    match al {
        0x00 => {}                                  // load & execute — fall through
        0x03 => return exec_load_overlay(machine, kt, dos, regs),
        // AL=01 (load only) and AL=02 (reserved) not implemented. Borland BC
        // and Watcom tools use 00/03 exclusively; surface others so we notice.
        _ => {
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }
    }

    // Read ASCIIZ filename from DS:DX
    let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let flen = read_asciiz(machine, addr, &mut filename);

    // Read parameter block at ES:BX
    let pb = seg_offset(dos, regs, regs.es as u16, regs.rbx as u32);
    let cmdtail_off = machine.read::<u16>((pb + 2) as usize) as u32;
    let cmdtail_seg = machine.read::<u16>((pb + 4) as usize);
    // The embedded (segment, offset) far pointer is a PM selector:offset
    // when the caller is in PM, an RM paragraph:offset in VM86 — same
    // discriminator seg_offset() uses for buffer addresses elsewhere.
    let cmdtail_addr = seg_offset(dos, regs, cmdtail_seg, cmdtail_off);
    let tail_len = machine.read::<u8>((cmdtail_addr) as usize) as usize;
    let mut tail = [0u8; 128];
    let copy_len = tail_len.min(127);
    machine.copy_from((cmdtail_addr + 1) as usize, &mut tail[..copy_len]);

    let prog_name: &[u8] = &filename[..flen];

    let fd = dos_open_program(kt, dos, prog_name);
    if fd < 0 {
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    let size = crate::kernel::vfs::seek(fd, 0, 2, &kt.fds);
    if size <= 0 {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    crate::kernel::vfs::seek(fd, 0, 0, &kt.fds);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);

    // ELF binaries need a separate address space — route through fork_exec.
    let is_elf = buf.len() >= 4 && buf[0..4] == [0x7F, b'E', b'L', b'F'];
    if is_elf {
        return fork_exec(dos, prog_name, b"", Default::default(), regs, kt);
    }

    let is_exe = is_mz_exe(&buf);
    // Resolve the DOS-form absolute path for the env program-path suffix.
    // Must be drive-qualified uppercase (e.g. "C:\BIN\PROG.EXE") — DOS
    // extenders derive their cwd estimate from this field.
    let mut abs_dos = [0u8; dfs::DFS_PATH_MAX];
    let abs_len = dos.dfs.resolve(prog_name, &mut abs_dos).unwrap_or(0);

    // Parent's PSP segment is now always a real-mode paragraph in
    // `dos.current_psp`. The PSP[0x2C] in memory may have been converted
    // to a selector at `dpmi_enter` — use `saved_rm_env` in that case so
    // the child's parent link / copied env stay in segment form.
    let parent_rm_psp = dos.current_psp;
    let parent_env_seg = match dos.dpmi.as_ref() {
        Some(dpmi) if dpmi.env_ldt_idx != 0 && dpmi.saved_rm_psp == parent_rm_psp => {
            dpmi.saved_rm_env
        }
        _ => Psp::env_seg(machine, parent_rm_psp),
    };
    let parent_env_vec = snapshot_env(machine, parent_env_seg);
    let parent = ParentRef { psp_seg: parent_rm_psp, env: &parent_env_vec };

    // Save parent state before reseating the heap chain for the child.
    // INT frame (IP/CS/FLAGS) is on the VM86 stack at current SS:SP;
    // exec_return restores SS:SP so rm_int31_dispatch pops it and resumes.
    let prev = dos.exec_parent.take();
    let parent_heap = dos.heap_seg;
    let parent_heap_base = dos.heap_base_seg;
    let parent_blocks = dos.dos_blocks.clone();
    let parent_dta = dos.dta;

    // Do NOT reset the MCB chain. Real DOS keeps a single chain across EXEC:
    // the parent's blocks stay allocated while the child runs, and the child's
    // env+program are first-fit `dos_alloc_block`'d into genuinely-free regions
    // (load_exe sizes a max-alloc child from `largest_dos_block`, not
    // 0xA000-heap_base). This is load-bearing: a 16-bit DPMI parent (Borland
    // C) keeps a live PM CS aliased onto a conventional block that can sit
    // ABOVE a free gap (so `heap_seg`'s contiguous-run value is below it).
    // Resetting + flooring the child at `heap_seg` let the child overwrite that
    // block — corrupting BC's code (the 0x20cc #GP cascade after TLINK exits).
    // exec_return restores `parent_blocks`, dropping whatever the child added.

    let loaded = if is_exe {
        match load_exe(machine, regs, dos, &parent, &buf, &abs_dos[..abs_len]) {
            Some(l) => l,
            None => {
                dos.heap_seg = parent_heap;
                dos.heap_base_seg = parent_heap_base;
                dos.current_psp = parent_rm_psp;
                dos.dta = parent_dta;
                dos.dos_blocks = parent_blocks;
                crate::kernel::dos::sync_mcb_chain(machine, dos, regs);
                regs.rax = (regs.rax & !0xFFFF) | 11;
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    } else {
        load_com(machine, regs, dos, &parent, &buf, &abs_dos[..abs_len])
    };
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;
    let psp_seg = loaded.psp_seg;

    Psp::set_cmdline(machine, loaded.psp_seg, &tail[..copy_len]);
    dos.dta = (psp_seg as u32) * 16 + 0x80;
    // DPMI host obligation: parent's PM state must not be observable to the
    // child (no PM handlers fire; child's DPMI entry, if any, allocates a
    // fresh DpmiState). Suspend DPMI state + pm_vectors + LDT, restore in
    // `exec_return`. Swapping the LDT box is cheap (pointer move); the only
    // per-EXEC allocation is the fresh 64KB child LDT.
    let suspended_dpmi = dos.dpmi.take();
    let suspended_pm_vectors = dos.pm_vectors;
    let suspended_pm_dos = core::mem::replace(&mut dos.pm_dos, false);
    let suspended_ldt = core::mem::replace(&mut dos.ldt, crate::kernel::dos::fresh_ldt());
    let suspended_ldt_alloc = core::mem::replace(
        &mut dos.ldt_alloc,
        [0u32; crate::kernel::dos::dpmi::LDT_ENTRIES / 32],
    );
    let suspended_pm_rm_vector_shadow = core::mem::replace(
        &mut dos.pm_rm_vector_shadow,
        [(0, 0, 0); 256],
    );
    let suspended_locked_stack = core::mem::replace(
        &mut dos.pc.locked_stack,
        mode_transitions::LockedStackState::new(),
    );
    dos.tf_sources = 0;
    let parent_pm_mode = regs.mode() != crate::UserMode::VM86;
    let mut parent_ivt = [(0u8, 0u16, 0u16); 12];
    for (slot, &int_num) in parent_ivt.iter_mut().zip(EXEC_SAVED_IVT_VECTORS.iter()) {
        let off = read_u16(machine, 0, (int_num as u32) * 4);
        let seg = read_u16(machine, 0, (int_num as u32) * 4 + 2);
        *slot = (int_num, off, seg);
        if parent_pm_mode {
            write_u16(machine, 0, (int_num as u32) * 4, slot_offset(int_num));
            write_u16(machine, 0, (int_num as u32) * 4 + 2, STUB_SEG);
        }
    }
    crate::kernel::dos::dpmi::install_kernel_ldt_slots(dos);
    crate::kernel::dos::dpmi::reset_pm_vectors(dos);
    // Reload LDTR after swapping in the child LDT.
    dos.on_resume(machine);
    dos.exec_parent = Some(ExecParent {
        child_psp: loaded.psp_seg,
        ss: vm86_ss(regs),
        sp: vm86_sp(regs),
        ds: regs.ds as u16,
        es: regs.es as u16,
        heap_seg: parent_heap,
        heap_base_seg: parent_heap_base,
        psp: parent_rm_psp,
        dta: parent_dta,
        dos_blocks: parent_blocks,
        ivt_vectors: parent_ivt,
        dpmi: suspended_dpmi,
        pm_vectors: suspended_pm_vectors,
        ldt: suspended_ldt,
        ldt_alloc: suspended_ldt_alloc,
        pm_rm_vector_shadow: suspended_pm_rm_vector_shadow,
        pm_dos: suspended_pm_dos,
        locked_stack: suspended_locked_stack,
        pm_mode: parent_pm_mode,
        prev: prev.map(alloc::boxed::Box::new),
    });

    // Set child entry. Push child's CS:IP + FLAGS onto the child's stack
    // so that rm_int31_dispatch's pop restores them correctly. Force IF
    // on in the pushed flags — DOS hands every program "interrupts on";
    // the parent's current EFLAGS (inherited here) has IF cleared because
    // the INT 21h trap gate cleared it on entry, and without this the
    // child boots with IRQ delivery blocked and any wait/scheduling-tick
    // dependency hangs forever (e.g. OMF after re-launch from a launcher).
    regs.set_ss32(ss as u32);
    regs.set_sp32(sp as u32);
    regs.set_user_tf(false);
    regs.project_tf();
    let flags = machine::guest_flags_if_on(regs) as u16;
    vm86_push(machine, regs, flags);
    vm86_push(machine, regs, cs);
    vm86_push(machine, regs, ip);
    regs.ds = psp_seg as u64;
    regs.es = psp_seg as u64;
    regs.clear_flag32(1);
    // Children always start in VM86; PM parents resume through the dispatch tail.
    regs.frame.rflags |= machine::VM_FLAG as u64;
    thread::KernelAction::Done
}

/// DOS INT 21h/4B AL=03 — Load Overlay.
/// Loads a program into caller-chosen memory. No PSP, no control transfer,
/// no address-space changes. Parameter block at ES:BX:
///   WORD 0: load_segment  — where the file image goes
///   WORD 2: reloc_factor  — value added to each relocated word for MZ EXE
/// For .COM / flat binaries the file is copied verbatim at load_seg:0.
/// For MZ .EXE the load module is copied at load_seg:0 and each relocation
/// entry gets `reloc_factor` added (NOT load_seg — the spec leaves it to
/// the caller, e.g. Borland C passes the segment of the overlay frame).
fn exec_load_overlay<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    // ASCIIZ filename at DS:DX
    let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let flen = read_asciiz(machine, addr, &mut filename);
    let prog_name: &[u8] = &filename[..flen];

    // Parameter block at ES:BX — two WORDs.
    let pb = seg_offset(dos, regs, regs.es as u16, regs.rbx as u32);
    let load_seg = machine.read::<u16>((pb) as usize);
    let reloc_factor = machine.read::<u16>((pb + 2) as usize);

    let fd = dos_open_program(kt, dos, prog_name);
    if fd < 0 {
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    let size = crate::kernel::vfs::seek(fd, 0, 2, &kt.fds);
    if size <= 0 {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    crate::kernel::vfs::seek(fd, 0, 0, &kt.fds);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);

    let load_base = (load_seg as u32) << 4;
    if is_mz_exe(&buf) {
        let data = &buf[..];
        let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
        let last_page_bytes = w(0x02) as u32;
        let total_pages = w(0x04) as u32;
        let reloc_count = w(0x06) as usize;
        let header_paragraphs = w(0x08) as u32;
        let reloc_offset = w(0x18) as usize;

        let file_size = if last_page_bytes == 0 {
            total_pages * 512
        } else {
            (total_pages - 1) * 512 + last_page_bytes
        };
        let header_size = header_paragraphs * 16;
        let load_size = file_size.saturating_sub(header_size) as usize;
        let reloc_end = reloc_offset + reloc_count * 4;

        if header_size as usize > data.len()
            || load_size > data.len() - header_size as usize
            || reloc_end > data.len()
        {
            regs.rax = (regs.rax & !0xFFFF) | 11;
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }

        let img = &data[header_size as usize..header_size as usize + load_size];
        machine.copy_to(load_base as usize, img);
        // Apply relocations using caller's reloc_factor (not load_seg).
        for i in 0..reloc_count {
            let entry = reloc_offset + i * 4;
            let off = w(entry) as u32;
            let seg = w(entry + 2) as u32;
            let a = (load_base + (seg << 4) + off) as usize;
            let v: u16 = machine.read(a);
            machine.write::<u16>(a, v.wrapping_add(reloc_factor));
        }
    } else {
        // Raw / .COM: copy file verbatim at load_seg:0.
        machine.copy_to(load_base as usize, &buf);
    }

    regs.clear_flag32(1);
    thread::KernelAction::Done
}

/// Return from an EXEC'd child to the parent.
/// Restores the parent's CS:IP, SS:SP, DS, ES and clears carry (success).
pub(super) fn exec_return<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, parent: ExecParent,
               preserve_pm_env: bool) -> thread::KernelAction {
    let mut parent = parent;
    regs.set_ss32(parent.ss as u32);
    regs.set_sp32(parent.sp as u32);
    // The live frame still belongs to the exiting child until the real-mode
    // dispatch stub consumes the parent's saved IRET frame below SS:SP.  DPMI
    // virtual-IF tracking may have armed TF in that child frame; carrying it
    // across EXEC return single-steps the dispatcher and eventually delivers
    // the child's #DB in the restored parent (Zone 66 exits this way).
    // Clear child CF and TF here.  A parent that was genuinely tracing keeps
    // TF in its saved FLAGS word and the dispatch IRET restores it normally.
    regs.clear_flag32(1);
    regs.set_user_tf(false);
    regs.project_tf();
    regs.ds = parent.ds as u64;
    regs.es = parent.es as u64;
    // Restore parent's mode. The child was always VM86; if the parent
    // was PM, clear VM_FLAG so the dispatch tail runs the PM iret-frame
    // pop on parent's PM stack instead of the VM86 one.
    if parent.pm_mode {
        regs.frame.rflags &= !(machine::VM_FLAG as u64);
    } else {
        regs.frame.rflags |= machine::VM_FLAG as u64;
    }
    dos.heap_seg = parent.heap_seg;
    dos.heap_base_seg = parent.heap_base_seg;
    dos.current_psp = parent.psp;
    dos.dta = parent.dta;
    dos.dos_blocks = parent.dos_blocks;
    crate::kernel::dos::sync_mcb_chain(machine, dos, regs);
    if parent.pm_mode && !preserve_pm_env {
        for &(int_num, off, seg) in parent.ivt_vectors.iter() {
            write_u16(machine, 0, (int_num as u32) * 4, off);
            write_u16(machine, 0, (int_num as u32) * 4 + 2, seg);
        }
    }
    // PM-environment handling on exec_return:
    //   - Normal exit (AH=4Ch): drop child's dpmi/ldt/pm_vectors, restore
    //     parent's. Child's PM state vanishes with the process.
    //   - TSR exit (AH=31h) when child entered DPMI: keep child's dpmi/ldt/
    //     pm_vectors alive — DPMI host installers (Borland's dpmiload,
    //     CWSDPMI when run as a TSR, etc.) install PM services, switch to
    //     RM via 0306, and TSR. The host's LDT entries, INT vectors and
    //     dpmi state must outlive the TSR so subsequent programs can use
    //     the same PM session via the raw-switch trampoline.
    //   - TSR exit when child has no dpmi: nothing to preserve, fall back
    //     to parent's (might itself be Some if parent is the DPMI client).
    if preserve_pm_env && dos.dpmi.is_some() {
        // Drop the parent's saved PM env; release any device mappings it
        // owned before its bookkeeping disappears.
        if let Some(ref mut parent_dpmi) = parent.dpmi {
            parent_dpmi.unmap_all_physical(machine);
            dos.memory.release_owner(machine, parent_dpmi.memory_owner());
        }
    } else {
        // A normal child exit drops its DPMI state. Device mappings are
        // externally owned and therefore require explicit virtual unmapping.
        if let Some(ref mut child_dpmi) = dos.dpmi {
            child_dpmi.unmap_all_physical(machine);
            dos.memory.release_owner(machine, child_dpmi.memory_owner());
        }
        dos.dpmi = parent.dpmi;
        dos.pm_vectors = parent.pm_vectors;
        dos.ldt = parent.ldt;
        dos.ldt_alloc = parent.ldt_alloc;
        dos.pm_rm_vector_shadow = parent.pm_rm_vector_shadow;
        dos.pm_dos = parent.pm_dos;
        dos.pc.locked_stack = parent.locked_stack;
    }
    // LDTR currently points at the child's LDT — reload (same box if we
    // preserved it, parent's box if we restored).
    dos.on_resume(machine);
    dos.exec_parent = parent.prev.map(|b| *b);
    thread::KernelAction::Done
}

/// What a child inherits from its parent: PSP segment (for child's PSP[0x16])
/// and env block (copied into the child's fresh env arena, then the DOS 3+
/// suffix appended). The env borrow can point at a live `Program::env`
/// (same-AS exec) or a kernel-side Vec snapshot (cross-AS exec where the
/// parent's pages are gone).
pub(in crate::kernel::dos) struct ParentRef<'a> {
    pub psp_seg: u16,
    pub env: &'a [u8],
}

/// Output of a successful binary load — segment layout plus initial CPU
/// register values for the VM86 thread.
pub(in crate::kernel::dos) struct Loaded {
    #[allow(dead_code)]
    pub env_seg: u16,
    pub psp_seg: u16,
    pub cs: u16,
    pub ip: u16,
    pub ss: u16,
    pub sp: u16,
    /// First paragraph past the loaded image (= `psp_seg + program_paras`).
    #[allow(dead_code)]
    pub end_seg: u16,
}

// ============================================================================
// DOS program loaders (.COM and MZ .EXE)
// ============================================================================

/// Fill a fresh env arena: copy the parent's variable strings (up to the
/// `00 00` terminator), then append the DOS 3+ suffix `01 00 <prog_name> 00`.
/// Per DOS EXEC (AH=4B), the child always gets a fresh arena — the parent's
/// env is *copied*, never shared.
/// Populate a freshly-allocated env block. Copies parent's variable
/// strings (up to the `00 00` terminator) into `env`, then appends the
/// DOS 3+ suffix `01 00 <prog_name> 00`. Per DOS EXEC (AH=4B), each
/// child gets a fresh arena — the parent's env is *copied*, never shared.
fn fill_env(env: &mut [u8], parent_env: &[u8], prog_name: &[u8]) {
    for b in env.iter_mut() { *b = 0; }
    let suffix_need = 2 + prog_name.len() + 1;
    let vars_cap = env.len().saturating_sub(suffix_need);
    let mut off = 0usize;
    let mut i = 0usize;
    let mut prev_was_nul = false;
    while off < vars_cap && i < parent_env.len() {
        let b = parent_env[i];
        env[off] = b;
        i += 1; off += 1;
        if b == 0 && prev_was_nul { break; }
        prev_was_nul = b == 0;
    }
    // DOS 3+ suffix: word 01 00, then child's own program pathname (drive-
    // qualified uppercase DOS form, e.g. "C:\BIN\PROG.EXE"), then NUL. DOS
    // extenders (BC, dos4gw, dos16m) parse this field back.
    env[off] = 0x01; env[off + 1] = 0x00;
    off += 2;
    for &b in prog_name {
        if off + 1 >= env.len() { break; }
        env[off] = b;
        off += 1;
    }
    env[off] = 0;
}

/// Initialize a freshly-allocated PSP at `psp_seg` to point at its env
/// block at `env_seg`, with parent_psp / JFT / cmdline default fields set.
fn init_psp<A: crate::Arch>(machine: &mut A, _regs: &mut Regs, psp_seg: u16, env_seg: u16, parent_psp: u16) {
    let mut jft = [0xFFu8; 20];
    jft[0] = 0; jft[1] = 1; jft[2] = 2;   // stdin/stdout/stderr → SFT 0/1/2
    let mut cmdline = [0u8; 127];
    cmdline[0] = 0x0D;                      // empty tail terminated by CR

    Psp::store(machine, psp_seg, Psp {
        int_20: [0xCD, 0x20],
        top_of_mem: 0xA000,
        parent_psp,
        env_seg,
        jft,
        max_files: 20,
        jft_far_off: 0x0018,
        jft_far_seg: psp_seg,
        cmdline_len: 0,
        cmdline,
        ..Default::default()
    });

}

/// Check if data starts with the MZ signature.
pub(in crate::kernel::dos) fn is_mz_exe(data: &[u8]) -> bool {
    data.len() >= 28 && data[0] == b'M' && data[1] == b'Z'
}

/// Allocate the env block (`ENV_PARAS` paragraphs) and program block as
/// separate AH=48-style allocations on `dos`'s MCB chain, exactly like
/// real DOS does on `INT 21h AH=4B EXEC`. Returns `(env_seg, psp_seg,
/// end_seg)`.
fn alloc_program_blocks<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, prog_paras: u16)
    -> Result<(u16, u16, u16), ()>
{
    let env_seg = dos_alloc_block(machine, dos, regs, ENV_PARAS).map_err(|_| ())?;
    let psp_seg = dos_alloc_block(machine, dos, regs, prog_paras).map_err(|_| ())?;
    let end_seg = psp_seg.wrapping_add(prog_paras);
    Ok((env_seg, psp_seg, end_seg))
}

/// Populate the env block + PSP + load module for a freshly-allocated
/// program. Common to `load_exe` and `load_com`. Sets `dos.current_psp`
/// and re-syncs the MCB chain so block ownership reflects the new PSP.
fn populate_program<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: &mut thread::DosState<A>, env_seg: u16, psp_seg: u16,
                    parent: &ParentRef, prog_name: &[u8]) {
    // Build the env arena in a local buffer, write it to guest memory, and
    // read the BLASTER config from the same buffer (no second guest read).
    let mut env = alloc::vec![0u8; (ENV_PARAS as usize) * 16];
    fill_env(&mut env, parent.env, prog_name);
    machine.copy_to(((env_seg as u32) << 4) as usize, &env);
    // Latch this program's BLASTER A/I/D/H into the SB-DMA layer so the
    // virtual 8237 traps the right channel and the IRQ relay uses the
    // right vector. Missing BLASTER leaves the SB16 defaults.
    dos.pc.sb.configure_from_env(&env);
    // ULTRASND makes the (emulated) GUS exist for this program and sets its
    // base/DMA/IRQ wiring; without it the card stays absent.
    dos.pc.gus.configure_from_env(&env);
    // BLASTER's P<port> makes the MPU-401 / General MIDI device exist. Its
    // GM bank is a boot asset (the same .PAT set the GUS plays), so it is
    // handed in here rather than fetched by the device.
    dos.pc.mpu.configure_from_env(&env, crate::kernel::midi_bank::get());
    init_psp(machine, regs, psp_seg, env_seg, parent.psp_seg);
    dos.current_psp = psp_seg;
    dos_set_program_block_owner(machine, dos, regs, env_seg, psp_seg, psp_seg);
}

/// Load a .COM binary. Allocates env + program block (1000h paragraphs =
/// 64 KB, the standard .COM arena), populates env/PSP/code. Stack at
/// PSP:COM_SP (top of 64 KB segment), code at (psp+0x10):0000.
pub(in crate::kernel::dos) fn load_com<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: &mut thread::DosState<A>, parent: &ParentRef,
                       data: &[u8], prog_name: &[u8]) -> Loaded {
    let (env_seg, psp_seg, end_seg) = alloc_program_blocks(machine, dos, regs, 0x1000)
        .expect("load_com: allocation failed");
    populate_program(machine, regs, dos, env_seg, psp_seg, parent, prog_name);

    // Load .COM code at psp_seg:0x100 (= (psp_seg+0x10):0).
    let load_addr = ((psp_seg as u32) << 4) + COM_OFFSET as u32;
    machine.copy_to(load_addr as usize, data);

    Loaded {
        env_seg, psp_seg,
        cs: psp_seg, ip: COM_OFFSET, ss: psp_seg, sp: COM_SP,
        end_seg,
    }
}

/// Load an MZ .EXE binary at `heap_end` (env_seg).
///
/// MZ header layout (first 28 bytes):
///   0x00: 'MZ' signature
///   0x02: bytes on last page (0 = full 512-byte page)
///   0x04: total pages (512 bytes each, includes header)
///   0x06: relocation count
///   0x08: header size in paragraphs (16 bytes each)
///   0x0E: initial SS (relative to load segment)
///   0x10: initial SP
///   0x14: initial IP
///   0x16: initial CS (relative to load segment)
///   0x18: relocation table offset
pub(in crate::kernel::dos) fn load_exe<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: &mut thread::DosState<A>, parent: &ParentRef,
                       data: &[u8], prog_name: &[u8]) -> Option<Loaded> {
    if data.len() < 28 { return None; }

    let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);

    let last_page_bytes = w(0x02) as u32;
    let total_pages = w(0x04) as u32;
    let reloc_count = w(0x06) as usize;
    let header_paragraphs = w(0x08) as u32;
    let min_extra = w(0x0A) as u32;
    let max_extra = w(0x0C) as u32;
    let init_ss = w(0x0E);
    let init_sp = w(0x10);
    let init_ip = w(0x14);
    let init_cs = w(0x16);
    let reloc_offset = w(0x18) as usize;

    let file_size = if last_page_bytes == 0 {
        total_pages * 512
    } else {
        (total_pages - 1) * 512 + last_page_bytes
    };
    let header_size = header_paragraphs * 16;
    let load_size = file_size.saturating_sub(header_size) as usize;

    if header_size as usize > data.len() || load_size > data.len() - header_size as usize {
        return None;
    }

    let load_paras = (load_size as u32).div_ceil(16) as u16;
    // Real DOS gives the program min(e_maxalloc, available) extra paragraphs
    // above the load module. Programs with e_maxalloc=0xFFFF (Watcom, BC, most
    // Turbo) expect ALL available conventional memory and then `AH=4A` it back
    // down. "Available" is the largest FREE region in the live MCB chain — NOT
    // 0xA000-heap_base — because EXEC no longer resets the chain, so the parent
    // (and prior siblings) keep their blocks. Allocate the env block first,
    // then size the program to the largest remaining free region so it lands
    // in one contiguous block that never overlaps a still-live parent (e.g.
    // BC's PM CS alias). exec_return drops these blocks when the child exits.
    let env_seg = dos_alloc_block(machine, dos, regs, ENV_PARAS).ok()?;
    let avail = crate::kernel::dos::largest_dos_block(dos);
    let base_paras = 0x10u16.saturating_add(load_paras);
    let floor = base_paras.saturating_add(min_extra as u16);
    if avail < floor { return None; }
    let prog_paras = base_paras.saturating_add(max_extra as u16).min(avail).max(floor);
    let psp_seg = dos_alloc_block(machine, dos, regs, prog_paras).ok()?;
    let end_seg = psp_seg.wrapping_add(prog_paras);
    populate_program(machine, regs, dos, env_seg, psp_seg, parent, prog_name);

    // Load module starts 0x10 paragraphs after the PSP.
    let load_segment = psp_seg + 0x10;

    let load_base = (load_segment as u32) << 4;
    let load_data = &data[header_size as usize..header_size as usize + load_size];
    machine.copy_to(load_base as usize, load_data);

    // Zero the allocation tail so re-exec cannot expose stale data past the image.
    let bss_start = load_base + load_size as u32;
    let bss_end = (end_seg as u32) << 4;
    if bss_end > bss_start {
        machine.zero(bss_start as usize, (bss_end - bss_start) as usize);
    }

    // Apply relocations: each entry is (offset, segment) within the load
    // module. Add load_segment to the 16-bit word at that address.
    let reloc_end = reloc_offset + reloc_count * 4;
    if reloc_end > data.len() { return None; }
    for i in 0..reloc_count {
        let entry = reloc_offset + i * 4;
        let off = w(entry) as u32;
        let seg = w(entry + 2) as u32;
        let addr = (load_base + (seg << 4) + off) as usize;
        let val: u16 = machine.read(addr);
        machine.write::<u16>(addr, val.wrapping_add(load_segment));
    }

    Some(Loaded {
        env_seg, psp_seg,
        cs: init_cs.wrapping_add(load_segment),
        ip: init_ip,
        ss: init_ss.wrapping_add(load_segment),
        sp: init_sp,
        end_seg,
    })
}

/// Return from a PSP created by the guest with AH=55h. DOS uses the parent
/// PSP's saved INT 21h frame as its return context, replacing that frame's
/// destination with the child's INT 22h address. Keeping the return in the
/// ordinary IRET path also restores the parent's stack and flags together.
pub(super) fn return_to_psp_parent<A: crate::Arch>(
    machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, status: u16,
    resident_paras: Option<u16>,
) -> bool {
    if regs.mode() != crate::UserMode::VM86 { return false; }
    let child_seg = dos.current_psp;
    let child = machine.read::<Psp>(Psp::base(child_seg));
    if child.int_20 != [0xCD, 0x20] || child.parent_psp == child_seg
        || child._terminate_addr == 0
    {
        return false;
    }
    let parent = machine.read::<Psp>(Psp::base(child.parent_psp));
    let saved = parent._ss_sp;
    if parent.int_20 != [0xCD, 0x20] || saved == 0 { return false; }

    // The three DOS process vectors belong to the exiting PSP. A loader may
    // have supplied its own INT 22h continuation after AH=55h.
    for (vector, target) in [(0x22usize, child._terminate_addr),
                             (0x23, child._ctrl_break_addr),
                             (0x24, child._critical_err)] {
        machine.write::<u32>(vector * 4, target);
    }
    let ss = (saved >> 16) as u16;
    let sp = saved as u16;
    write_u16(machine, u32::from(ss), u32::from(sp), child._terminate_addr as u16);
    write_u16(machine, u32::from(ss), u32::from(sp).wrapping_add(2),
        (child._terminate_addr >> 16) as u16);
    write_u16(machine, u32::from(ss), u32::from(sp).wrapping_add(4), 0x0200);
    regs.set_ss32(u32::from(ss));
    regs.set_sp32(u32::from(sp));
    machine::set_vm86_flags(regs, 0x0200);
    dos.current_psp = child.parent_psp;
    dos.last_child_exit_status = status;

    // AH=55h does not transfer ownership of its caller-allocated PSP block.
    // Only blocks the child subsequently allocated belong to the child.
    if let Some(keep) = resident_paras {
        if dos.dos_blocks.iter().any(|block| block.seg == child_seg) {
            let _ = crate::kernel::dos::dos_resize_block(machine, dos, regs, child_seg, keep.max(6));
        }
    } else {
        dos.dos_blocks.retain(|block| block.owner != child_seg);
        crate::kernel::dos::sync_heap_seg(dos);
        crate::kernel::dos::sync_mcb_chain(machine, dos, regs);
    }
    true
}

/// Terminate a DOS program while retaining `keep` paragraphs from its PSP.
/// INT 27h and INT 21h/AH=31h differ only in how that count is supplied.
pub(super) fn terminate_resident<A: crate::Arch>(
    machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, keep: u16,
) -> thread::KernelAction {
    if dos.exec_parent.as_ref().is_some_and(|parent| parent.child_psp == dos.current_psp)
        && let Some(parent) = dos.exec_parent.take()
    {
        // Keep is measured from the *child's* PSP, not from the parent's
        // heap seg. They differ by the env block + MCB overhead
        // (ENV_PARAS + 2). Using parent.heap_seg here under-counts
        // and leaves the gap between (parent.heap_seg + keep) and
        // the actual resident-block end available for subsequent
        // allocs — overlapping the still-live TSR's image+stack.
        let child_psp_seg = dos.current_psp;
        // Termination type 03h (TSR) | return code in AL.
        dos.last_child_exit_status = 0x0300 | (regs.rax as u8) as u16;
        // TSR: preserve child's PM env (LDT/dpmi/pm_vectors) so a
        // DPMI host installer like Borland's dpmiload — which
        // calls dpmi_enter, sets up host services, switches back
        // to RM via 0306, then TSRs — leaves the PM session usable
        // by subsequent programs that enter via the raw-switch
        // trampoline.
        let action = exec_return(machine, dos, regs, parent, /*preserve_pm_env=*/true);
        dos_keep_resident_block(machine, dos, regs, child_psp_seg, keep, child_psp_seg);
        return action;
    }
    let status = 0x0300 | u16::from(regs.rax as u8);
    if return_to_psp_parent(machine, dos, regs, status, Some(keep)) {
        return thread::KernelAction::Done;
    }
    // Cross-thread TSR. Encode termination type 03h
    // | AL into exit_code so the parent's last_child_exit_status
    // (set by exit_thread) carries the TSR marker per AH=4Dh spec.
    let code = regs.rax as u8;
    thread::KernelAction::Exit(0x0300 | (code as i32))
}
