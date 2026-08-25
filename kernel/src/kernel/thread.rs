//! Thread and process management
//!
//! Thread states: Unused, Running, Ready, Blocked, Zombie
//! TID 0 is the idle/init thread (never scheduled away from if no other threads)

use crate::kernel::stacktrace::SymbolData;
use crate::println;
use crate::Regs;

// Re-export personality state types so `thread::DosState` / `thread::LinuxState` still works
pub use crate::kernel::dos::DosState;
pub use crate::kernel::linux::LinuxState;
pub use crate::kernel::os2::Os2State;
pub use crate::kernel::windows::WindowsState;

/// Maximum number of threads
pub const MAX_THREADS: usize = 1024;

/// Maximum file descriptors per thread
// 64: BC's project linker holds every .OBJ of the project open at once
// (wolfsrc = 31 objs + libs + exe + map on top of the std handles); real DOS
// lets a program raise its JFT to 255 via AH=67h. Keep below the DOS device
// sentinels at 98/99 (EMS_DEVICE_HANDLE / NULL_FILE_HANDLE).
pub const MAX_FDS: usize = 64;

/// What a file descriptor refers to
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    /// Slot is free
    None,
    /// VFS file (index into global FILE_TABLE)
    Vfs(i32),
    /// Read end of a kernel pipe
    PipeRead(u8),
    /// Write end of a kernel pipe
    PipeWrite(u8),
    /// Console stdout/stderr (VGA putchar)
    ConsoleOut,
    /// Open directory (for opendir/getdents). `handle` names the directory in
    /// the VFS dir-handle table (-1 = unknown → getdents falls back to cwd);
    /// `next` is the next entry index to return — getdents64 advances it so a
    /// sequential reader sees each entry exactly once and EOF after the last.
    Dir { handle: i32, next: u32 },
    /// Network socket — the i32 is the backend socket handle (injected socket
    /// layer; hosted std::net punch-through).
    Socket(i32),
}

impl FdKind {
    pub fn is_none(&self) -> bool { matches!(self, FdKind::None) }
}

/// A pending blocked read — generalized from stdin-only to any fd
pub struct PendingRead {
    pub fd_kind: FdKind,   // what we're reading from (PipeRead or ConsoleOut won't happen)
    pub buf_ptr: usize,
    pub buf_len: usize,
}

/// A pending blocked poll — re-evaluated on each event-loop tick until any
/// monitored fd becomes ready or the timeout expires.
pub struct PendingPoll {
    pub fds_ptr: usize,    // user-space pointer to pollfd[]
    pub nfds: usize,
    pub timeout_ms: i32,   // -1 = infinite
}

/// Thread state
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThreadState {
    Unused = 0,
    Running,
    Ready,
    Blocked,
    Zombie,
}

/// What the OS personality wants the kernel to do.
/// Returned by the KernelEvent dispatch in `startup::event_loop`, by syscall
/// dispatch, and by DPMI INT/exception paths. The event loop acts on it —
/// personality code never touches scheduling.
// ForkExec carries the exec payload inline; it is constructed and consumed in
// the same event-loop turn (never stored), so the size gap to the unit variants
// doesn't cost per-thread memory — boxing it would only add an alloc on the hot
// fork/exec path.
#[allow(clippy::large_enum_variant)]
pub enum KernelAction {
    /// Nothing to do, continue current thread.
    Done,
    /// Yield current thread to scheduler.
    Yield,
    /// Exit current thread with given code.
    Exit(i32),
    /// Fork/clone: COW-clone the current process in the executor (after the kt
    /// borrow releases). `child_stack` overrides the child's SP when nonzero
    /// (clone); 0 = plain fork. `on_done` writes the parent's return value
    /// (child tid, or -errno).
    Fork { on_done: fn(&mut crate::Regs, i32), child_stack: usize },
    /// Switch to a specific thread (already resolved by caller).
    Switch(usize),
    /// ForkExec: fork a child, exec the given path.
    /// `cmdtail` is the raw DOS-style argument string (everything after the
    /// program name in the parent's PSP cmdline) — written verbatim to the
    /// child's PSP[0x80] so DOS programs see their args. Empty for callers
    /// that don't pass args.
    ForkExec {
        path: [u8; 164],
        path_len: usize,
        cmdtail: [u8; 128],
        cmdtail_len: usize,
        /// Which personality's namespace `path` is in (the launcher's). `Some(Dos)`
        /// ⇒ `path` is a DOS path (resolved to VFS only for the read; used verbatim
        /// as the program name a DOS extender reopens). `None` ⇒ `path` is VFS-form
        /// (the generic default). Keeps this generic action free of DOS specifics —
        /// it's a tag, not a DOS path field.
        personality_name: Option<PersonalityName>,
        /// Virtual IOPL the child execs at: 1 = spec-conforming (default),
        /// 3 = non-conforming (COMMAND.COM passed `iopl3` from LOADFIX.CFG).
        viopl: u8,
        on_error: fn(&mut crate::Regs, i32),
        on_success: fn(&mut crate::Regs, child_tid: i32),
    },
    /// Exec: replace the current process in place with a loaded binary. The
    /// handler reads path/argv from the (still-live) old address space and loads
    /// the file; the executor tears down + rebuilds, off the handler's borrow.
    Exec {
        buffer: alloc::vec::Vec<u8>,
        path: alloc::vec::Vec<u8>,
        args: alloc::vec::Vec<alloc::vec::Vec<u8>>,
        cwd: alloc::vec::Vec<u8>,
    },
    /// wait4: reap a zombie child (or block until one exists). Run in the
    /// executor so the child-table scan/reap happens off the parent's borrow.
    Wait { pid: i32, status_ptr: usize },
    /// DOS INT-31 synth op on a *child* thread (reap / waitpid probe). Run in
    /// the executor so the cross-thread table
    /// access happens off the caller's `dos`/`kt` borrow. The executor writes
    /// the AX/BX/CF result into the live frame.
    DosSynthChild { pid: i32, op: DosChildOp },
}

/// Which child-thread operation a `KernelAction::DosSynthChild` performs.
#[derive(Clone, Copy)]
pub enum DosChildOp {
    /// AH=05 SYNTH_REAP: recycle the zombie slot.
    Reap,
    /// AH=04 SYNTH_WAITPID: non-blocking exit probe.
    Waitpid,
}

/// OS personality — determines event loop dispatch and carries OS-specific state
/// The personality identity without its state — a lightweight tag for code that
/// needs to name "DOS" or "Linux" generically (e.g. which namespace a path is
/// in) without carrying a whole `DosState`/`LinuxState`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PersonalityName {
    Dos,
    Linux,
    Os2,
    Windows,
}

#[allow(clippy::large_enum_variant)] // see the note on Linux below
pub enum Personality<A: crate::Arch> {
    /// DOS mode: VM86 (real mode) or DPMI (32-bit protected mode)
    Dos(alloc::boxed::Box<DosState<A>>),
    /// Linux userspace (32 or 64-bit, distinguished by CS descriptor).
    ///
    /// Inline rather than boxed, unlike `Dos`: at ~272 bytes it sets the
    /// enum's size, but a `Thread` holds exactly one `Personality` and threads
    /// are already heap-allocated, so boxing would buy an indirection on every
    /// syscall to save a few hundred bytes once per thread.
    Linux(LinuxState),
    /// Native 32-bit OS/2 LX userspace.
    Os2(Os2State),
    /// Native 32-bit Windows PE userspace.
    Windows(WindowsState),
}

impl<A: crate::Arch> Personality<A> {
    pub fn surface_buffer<'a>(
        &'a self,
        key: crate::kernel::gui::SurfaceKey,
        format: vga::PixelFormat,
    ) -> Option<crate::kernel::gui::PixelBuffer<'a>> {
        match self {
            Self::Os2(state) if key == crate::kernel::gui::SurfaceKey(1) => {
                crate::kernel::os2::surface_buffer(state)
            }
            Self::Windows(state) if key == crate::kernel::gui::SurfaceKey(1) => {
                crate::kernel::windows::surface_buffer(state)
            }
            Self::Dos(state) if key == crate::kernel::gui::SurfaceKey(2) => {
                crate::kernel::dos::surface_buffer(state, format)
            }
            Self::Linux(_) if key == crate::kernel::gui::SurfaceKey(1) => {
                crate::kernel::term::surface_buffer()
            }
            _ => None,
        }
    }

    /// Give the first running personality the boot display. Unlike a later
    /// materialization, Linux adopts the existing contents instead of
    /// repainting its shared console snapshot.
    pub fn adopt_display(
        &mut self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        display: crate::kernel::display::Display,
    ) -> Option<crate::kernel::display::Display> {
        match self {
            Self::Dos(d) => {
                d.acquire_display_restore(
                    machine, bios_workspace,
                    crate::kernel::display::DisplayHandoff::Surface(display));
                None
            }
            Self::Linux(_) | Self::Os2(_) | Self::Windows(_) => {
                crate::kernel::linux::repaint_console();
                Some(display)
            }
        }
    }

    pub fn uses_compositor(&self) -> bool {
        matches!(self, Self::Linux(_) | Self::Os2(_) | Self::Windows(_))
            || matches!(self, Self::Dos(d) if !d.pc.vga.is_fullscreen())
    }

    /// Hand this thread the machine's Sound Blaster, returning whatever it
    /// did not take. Moves with the console, and for the same reason: it is
    /// one piece of machine hardware and the owner is whoever the machine is
    /// currently showing. A Linux thread has no use for it and hands it
    /// straight back; so does a DOS thread on a machine running the card as
    /// the kernel mixer's sink, because there the sink never let it go and
    /// this is `None`.
    pub fn adopt_sb<A2>(
        &mut self,
        machine: &mut A2,
        card: Option<crate::kernel::drivers::sb16::SbCard>,
    ) -> Option<crate::kernel::drivers::sb16::SbCard>
    where
        A2: crate::Arch,
    {
        match (self, card) {
            (Self::Dos(d), Some(card)) => {
                d.pc.sb.adopt_card(machine, card);
                None
            }
            (_, card) => card,
        }
    }

    /// Take the card back off this thread, if it has it.
    pub fn release_sb<A2: crate::Arch>(
        &mut self,
        machine: &mut A2,
    ) -> Option<crate::kernel::drivers::sb16::SbCard> {
        match self {
            Self::Dos(d) => d.pc.sb.release_card(machine),
            Self::Linux(_) | Self::Os2(_) | Self::Windows(_) => None,
        }
    }

    /// Out-focus hook: snapshot whatever state lives only in hardware (VGA
    /// framebuffer + register set, shared TTY console buffer).
    pub fn release_display(
        &mut self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> crate::kernel::display::DisplayHandoff {
        match self {
            Self::Dos(d) => d.release_display(machine, bios_workspace),
            Self::Linux(_) | Self::Os2(_) | Self::Windows(_) => panic!("composited display is owned by the event loop"),
        }
    }

    pub fn repaint_osd(&mut self) {
        match self {
            Self::Linux(_) => crate::kernel::linux::repaint_console(),
            Self::Os2(os2) => os2.repaint_osd(),
            Self::Windows(windows) => windows.repaint_osd(),
            Self::Dos(_) => {}
        }
    }

    /// In-focus hook: repaint the suspended screen state to hardware.
    /// Visual rematerialization only — CPU-binding side effects (LDT, TLS,
    /// deferred wait_status writeout) live in `on_resume` and run
    /// independently of focus changes.
    pub fn acquire_display_restore(
        &mut self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        display: crate::kernel::display::DisplayHandoff,
    ) {
        match self {
            Self::Dos(d) => d.acquire_display_restore(machine, bios_workspace, display),
            Self::Linux(_) | Self::Os2(_) | Self::Windows(_) => panic!("composited personality cannot acquire a fullscreen display"),
        }
    }

    /// Attach a handoff whose current contents are authoritative. DOS binds
    /// the live adapter without replaying its recovery snapshot; a surface
    /// display is already value state, so Linux's ordinary attach is replace.
    pub fn acquire_display_replace(
        &mut self,
        machine: &mut A,
        _bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        display: crate::kernel::display::DisplayHandoff,
    ) {
        match self {
            Self::Dos(d) => d.acquire_display_replace(machine, display),
            Self::Linux(_) | Self::Os2(_) | Self::Windows(_) => panic!("composited personality cannot acquire a fullscreen display"),
        }
    }

    /// Swap-in hook: rebind per-thread CPU state. Called every time a thread
    /// becomes the running thread, regardless of whether it's also taking
    /// focus visually.
    pub fn on_resume(&mut self, machine: &mut A) {
        match self {
            Self::Dos(d) => d.on_resume(machine),
            Self::Linux(l) => l.on_resume(machine),
            Self::Os2(o) => o.on_resume(machine),
            Self::Windows(w) => w.on_resume(machine),
        }
    }

    /// Advance this thread's emulated devices to the current virtual time,
    /// before audio, display, input routing, and guest resume. DOS steps its
    /// PIT and services sound-device events; Linux currently has no virtual
    /// devices to advance. Runs once per event-loop iteration.
    pub fn advance_world(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        regs: &Regs,
        now_ns: u64,
        dt_ns: u64,
        audio_pushed: u64,
    ) {
        let prof = crate::kernel::startup::profile_enabled();
        let t0 = if prof { machine.rdtsc() } else { 0 };
        match self {
            Self::Dos(dos) => {
                // Port-polling games can exit to the kernel hundreds of
                // thousands of times between adjacent millisecond ticks.
                // Display and output pumping are driven by clock wakeups, so
                // revisiting the timed devices when time did not advance
                // is pure per-exit overhead. Device service is not:
                // its latency contract is the slice (MI2 arms a one-byte DMA
                // probe and expects the completion back-to-back; a 1 ms
                // floor loses it — 35e3b27, regressed once by a full
                // early-out here).
                if dt_ns != 0 {
                    crate::kernel::dos::advance_timers(dos, now_ns);
                }
                crate::kernel::dos::audio_service(
                    machine, dos, now_ns, dt_ns, audio_pushed);
                if dt_ns != 0 && dos.pc.vga.is_fullscreen() {
                    crate::kernel::dos::pump_fullscreen(machine, bios, dos, regs, now_ns);
                }
            }
            Self::Linux(_) | Self::Os2(_) | Self::Windows(_) => {}
        }
        if prof {
            crate::kernel::startup::bill_slice2(
                0, machine.rdtsc().wrapping_sub(t0), 0, 0, u64::from(dt_ns != 0));
        }
    }

    /// Advance one emulated-audio span; its samples may be output or discarded.
    pub fn audio_tick(
        &mut self,
        machine: &mut A,
        now_ns: u64,
        span: crate::kernel::sound::AudioSpan<'_>,
    ) {
        match self {
            Self::Dos(dos) => crate::kernel::dos::audio_tick(machine, dos, now_ns, span),
            Self::Linux(_) | Self::Os2(_) | Self::Windows(_) => {}
        }
    }

    /// Render compositor-owned personality state into the event loop's output.
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        regs: &Regs,
        now_ns: u64,
        display: &mut crate::kernel::display::Display,
        desktop: &mut crate::kernel::gui::Desktop,
        endpoint: crate::kernel::gui::EndpointId,
    ) {
        let prof = crate::kernel::startup::profile_enabled();
        let t0 = if prof { machine.rdtsc() } else { 0 };
        match self {
            Self::Dos(dos) => {
                crate::kernel::dos::render(
                    machine, bios, dos, regs, now_ns, display, desktop, endpoint,
                );
            }
            Self::Linux(_) => {
                crate::kernel::linux::render(machine, bios, display, desktop, endpoint)
            }
            Self::Os2(os2) => {
                crate::kernel::os2::render(machine, bios, os2, display, desktop, endpoint)
            }
            Self::Windows(windows) => {
                crate::kernel::windows::render(machine, bios, windows, display, desktop, endpoint)
            }
        }
        if prof {
            crate::kernel::startup::bill_slice2(
                0, 0, machine.rdtsc().wrapping_sub(t0), 0, 0);
        }
    }

    /// Dispatch a kernel event produced by this thread's user code.
    pub fn handle_event(
        &mut self,
        machine: &mut A,
        bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        kt: &mut KernelThread<A>,
        regs: &mut Regs,
        kevent: crate::KernelEvent,
    ) -> KernelAction {
        match self {
            Self::Dos(dos) => crate::kernel::dos::handle_event(machine, bios_display, kt, dos, regs, kevent),
            Self::Linux(linux) => crate::kernel::linux::handle_event(machine, kt, linux, regs, kevent),
            Self::Os2(os2) => crate::kernel::os2::handle_event(machine, kt, os2, regs, kevent),
            Self::Windows(windows) => crate::kernel::windows::handle_event(machine, kt, windows, regs, kevent),
        }
    }

    /// A page fault at `addr` may be a VGA planar-trap access (A0000 is left
    /// unmapped while unchained graphics needs the planar write/read logic).
    /// Returns true if it was handled (resume the thread), false → real SEGV.
    /// Unified across backends: both deliver the PageFault, the kernel decodes.
    pub fn try_vga_fault(
        &mut self,
        machine: &mut A,
        regs: &mut Regs,
        addr: u32,
    ) -> bool {
        match self {
            Self::Dos(dos) => crate::kernel::dos::try_vga_fault(machine, dos, regs, addr),
            _ => false,
        }
    }

    /// Per-iteration slice work AFTER input routing: deliver queued IRQs to
    /// a runnable DOS guest; complete a blocked Linux thread's pending pipe
    /// read / poll (which may make it Ready again).
    pub fn after_input(
        &mut self,
        machine: &mut A,
        kt: &mut KernelThread<A>,
        regs: &mut Regs,
    ) {
        let blocked = kt.state == ThreadState::Blocked;
        match self {
            Self::Dos(dos) => {
                if !blocked {
                    crate::kernel::dos::raise_pending(machine, dos, regs);
                }
            }
            Self::Linux(linux) => {
                if blocked {
                    crate::kernel::linux::complete_pending_io(machine, kt, linux, regs);
                }
            }
            Self::Os2(_) | Self::Windows(_) => {}
        }
    }
}

/// Backward compat alias
pub type ThreadMode<A> = Personality<A>;

// `Regs::init_user_process[_64]` (canonical user-entry register state) moved
// into the shared `arch-abi` crate alongside `Regs` — the kernel can no longer
// add inherent impls to `Regs` (orphan rule), and that state is part of the
// backend-agnostic contract anyway.

/// Kernel-side thread state shared across all personalities.
/// Personality code receives `&mut KernelThread<A>` alongside its own `&mut DosState<A>`
/// or `&mut LinuxState`, giving clean split borrows with no wrapper hacks.
pub struct KernelThread<A: crate::Arch> {
    pub tid: i32,
    pub pid: i32,
    pub priority: i32,
    pub parent_tid: i32,
    pub state: ThreadState,
    pub time: u32,
    /// Register state + address-space handle for this thread's execution
    /// context. `vcpu.regs` is the saved CPU state, `vcpu.space` the page-table
    /// root. Bundled so the kernel manipulates one "thing to run" rather than
    /// two loosely-coupled fields (see arch::Vcpu).
    pub vcpu: crate::Vcpu<A>,
    pub fx_state: A::Fx,
    pub exit_code: i32,
    pub addr_hash: u64,
    pub cpu_hash: u64,
    pub symbols: Option<SymbolData>,
    pub fds: [FdKind; MAX_FDS],
    // u64: one bit per fd slot, so it must cover MAX_FDS (was u16 — fds >= 16
    // silently wrapped the shift in release builds).
    pub cloexec: u64,
    /// Short program name for the F12 switch picker (DOS has no stored image
    /// path the way Linux's `exec_path` does). Set from the launch path's
    /// basename at fork-exec; empty until then. NUL-padded.
    pub comm: [u8; 16],
}

/// Thread control block = kernel state + OS personality
pub struct Thread<A: crate::Arch> {
    pub kernel: KernelThread<A>,
    pub personality: Personality<A>,
}

/// FNV-1a hash of a Regs struct (raw byte view).
/// Used to detect whether a saved thread's CPU state is modified while
/// the thread is not running.
pub fn hash_regs(r: &Regs) -> u64 {
    let bytes = unsafe {
        core::slice::from_raw_parts(r as *const _ as *const u8, core::mem::size_of::<Regs>())
    };
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Recompute a thread's cpu_hash after an out-of-band modification to cpu_state.
pub fn refresh_cpu_hash<A: crate::Arch>(t: &mut Thread<A>) {
    t.kernel.cpu_hash = hash_regs(&t.kernel.vcpu.regs);
}

impl<A: crate::Arch> KernelThread<A> {
    pub fn empty() -> Self {
        KernelThread {
            tid: 0,
            pid: 0,
            priority: 0,
            parent_tid: -1,
            state: ThreadState::Unused,
            time: 0,
            vcpu: crate::Vcpu::empty(),
            fx_state: Default::default(),
            exit_code: 0,
            addr_hash: 0,
            cpu_hash: 0,
            symbols: None,
            fds: [FdKind::None; MAX_FDS],
            cloexec: 0,
            comm: [0; 16],
        }
    }

    /// Record the program's display name from a launch path (basename, NUL-padded).
    pub fn set_comm(&mut self, path: &[u8]) {
        self.comm = [0; 16];
        let base = basename(path);
        let n = base.len().min(self.comm.len());
        self.comm[..n].copy_from_slice(&base[..n]);
    }

    /// The recorded program name, empty if never set.
    pub fn comm_str(&self) -> &[u8] {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(self.comm.len());
        &self.comm[..end]
    }

    /// Find a free fd slot (starting from `from`). Returns fd number or None.
    pub fn alloc_fd(&self, from: usize) -> Option<usize> {
        (from..MAX_FDS).find(|&i| self.fds[i].is_none())
    }

    /// Close a single fd, decrementing pipe/VFS refcounts as needed.
    pub fn close_fd(&mut self, fd: usize) {
        if fd >= MAX_FDS { return; }
        match self.fds[fd] {
            FdKind::Vfs(idx) => {
                crate::kernel::vfs::close_vfs_handle(idx);
            }
            FdKind::PipeRead(idx) => {
                crate::kernel::kpipe::close_reader(idx);
            }
            FdKind::PipeWrite(idx) => {
                crate::kernel::kpipe::close_writer(idx);
            }
            FdKind::Socket(h) => {
                crate::kernel::net::close(h);
            }
            FdKind::Dir { handle, .. } => {
                crate::kernel::vfs::close_dir_handle(handle);
            }
            FdKind::ConsoleOut | FdKind::None => {}
        }
        self.fds[fd] = FdKind::None;
        self.cloexec &= !(1 << fd);
    }

    /// Close all fds.
    pub fn close_all_fds(&mut self) {
        for i in 0..MAX_FDS {
            self.close_fd(i);
        }
    }

    /// Close only CLOEXEC fds (for execve).
    pub fn close_cloexec(&mut self) {
        let mask = self.cloexec;
        for i in 0..MAX_FDS {
            if mask & (1 << i) != 0 {
                self.close_fd(i);
            }
        }
    }

    /// Duplicate fd table for fork. Increments refcounts on pipes and VFS handles.
    pub fn dup_all_fds(&self, dst: &mut Self) {
        dst.fds = self.fds;
        dst.cloexec = self.cloexec;
        for i in 0..MAX_FDS {
            match dst.fds[i] {
                FdKind::Vfs(idx) => {
                    crate::kernel::vfs::add_vfs_ref(idx);
                }
                FdKind::PipeRead(idx) => {
                    crate::kernel::kpipe::add_reader(idx);
                }
                FdKind::PipeWrite(idx) => {
                    crate::kernel::kpipe::add_writer(idx);
                }
                // TODO: refcount for fork/dup socket sharing — for now the child
                // inherits the same backend handle; the first close frees it.
                FdKind::Socket(_) => {}
                FdKind::Dir { handle, .. } => {
                    crate::kernel::vfs::add_dir_ref(handle);
                }
                FdKind::ConsoleOut | FdKind::None => {}
            }
        }
    }
}

impl<A: crate::Arch> Thread<A> {
    pub fn empty() -> Self {
        Thread {
            kernel: KernelThread::empty(),
            personality: Personality::Linux(LinuxState::new()),
        }
    }

    /// Check if this thread is a DOS thread (VM86 or DPMI)
    pub fn is_dos(&self) -> bool {
        matches!(self.personality, Personality::Dos(_))
    }

    /// Check if this DOS thread has DPMI state active
    pub fn has_dpmi(&self) -> bool {
        matches!(&self.personality, Personality::Dos(dos) if dos.dpmi.is_some())
    }

    /// Get mutable reference to DosState (panics if not a DOS thread)
    pub fn dos_mut(&mut self) -> &mut DosState<A> {
        match &mut self.personality {
            Personality::Dos(dos) => dos,
            _ => panic!("dos_mut on non-DOS thread"),
        }
    }
}

// The thread table is no longer a global: `startup()` owns a `Vec<Thread>`
// (built by `init_threading`) and threads `&mut [Thread<A>]` through the event
// loop and the executors. The table API below takes that slice; the live
// register frame lives in `ExecutionContext`, never here.

/// Console stdin kpipe index (shared by all Linux processes)
static mut CONSOLE_PIPE: u8 = 0;

pub fn set_console_pipe(idx: u8) { unsafe { CONSOLE_PIPE = idx; } }
pub fn console_pipe() -> u8 { unsafe { CONSOLE_PIPE } }

/// Check if threading system is initialized
pub fn is_initialized<A: crate::Arch>(threads: &[Thread<A>]) -> bool {
    !threads.is_empty()
}

pub fn prng() -> u64 {
    /// PRNG state for random scheduling
    static mut SEED: u64 = 0xcafe_babe_dead_beef;

    unsafe {
        const A: u64 = 0xdead_beed;
        const C: u64 = 0x1234_5679;
        SEED = A.wrapping_mul(SEED).wrapping_add(C);
        SEED
    }
}


/// Get thread by TID. Borrow is tied to the passed slice.
pub fn get_thread<A: crate::Arch>(threads: &mut [Thread<A>], tid: usize) -> Option<&mut Thread<A>> {
    if tid >= MAX_THREADS {
        return None;
    }
    let thread = &mut threads[tid];
    if thread.kernel.state != ThreadState::Unused {
        Some(thread)
    } else {
        None
    }
}

/// Get mutable references to two different threads (for switch_to). Safe
/// `split_at_mut` — no aliasing, no `unsafe`.
pub fn get_two_threads<A: crate::Arch>(threads: &mut [Thread<A>], a: usize, b: usize) -> (&mut Thread<A>, &mut Thread<A>) {
    assert!(a != b && a < MAX_THREADS && b < MAX_THREADS);
    if a < b {
        let (lo, hi) = threads.split_at_mut(b);
        (&mut lo[a], &mut hi[0])
    } else {
        let (lo, hi) = threads.split_at_mut(a);
        (&mut hi[0], &mut lo[b])
    }
}

/// Create a new thread with the given root page table.
pub fn create_thread<'a, A: crate::Arch>(threads: &'a mut [Thread<A>], machine: &mut A, parent_tid: Option<usize>, root: A::PageTable, is_process: bool) -> Option<&'a mut Thread<A>> {
    let (parent_pid, parent_prio, parent_tidv) = match parent_tid {
        Some(tid) => {
            let p = &threads[tid].kernel;
            (p.pid, p.priority, p.tid)
        }
        None => (0, 0, -1),
    };
    for (i, t) in threads.iter_mut().enumerate().take(MAX_THREADS) {
        if t.kernel.state == ThreadState::Unused {
            let k = &mut t.kernel;
            k.tid = i as i32;
            k.pid = if is_process { i as i32 } else { parent_pid };
            k.priority = parent_prio;
            k.parent_tid = parent_tidv;
            k.state = ThreadState::Ready;
            k.time = machine.get_ticks() as u32;
            k.vcpu = crate::Vcpu::new(Regs::empty(), root);
            k.fx_state = machine.clean_fx_template();
            k.exit_code = 0;
            k.addr_hash = 0;
            k.cpu_hash = 0;
            t.personality = Personality::Linux(LinuxState::new());
            return Some(t);
        }
    }
    None
}

/// Reserve the child record while leaving the current address space live.
/// The caller COW-forks that live space into the parent's now-parked slot;
/// this fresh child's empty slot then denotes the still-live address space.
pub fn reserve_live_child<'a, A: crate::Arch>(
    threads: &'a mut [Thread<A>],
    machine: &mut A,
    parent_tid: usize,
) -> Option<&'a mut Thread<A>> {
    let (parent_prio, parent_tidv) = {
        let p = &threads[parent_tid].kernel;
        (p.priority, p.tid)
    };
    for (i, t) in threads.iter_mut().enumerate().take(MAX_THREADS) {
        if t.kernel.state == ThreadState::Unused {
            let k = &mut t.kernel;
            k.tid = i as i32;
            k.pid = i as i32;
            k.priority = parent_prio;
            k.parent_tid = parent_tidv;
            k.state = ThreadState::Ready;
            k.time = machine.get_ticks() as u32;
            k.vcpu.regs = Regs::empty();
            k.fx_state = machine.clean_fx_template();
            k.exit_code = 0;
            k.addr_hash = 0;
            k.cpu_hash = 0;
            t.personality = Personality::Linux(LinuxState::new());
            return Some(t);
        }
    }
    None
}

/// Initialize a thread as a 32-bit user process
pub fn init_process_thread<A: crate::Arch>(thread: &mut Thread<A>, entry: u32, stack: u32) {
    thread.kernel.vcpu.regs.init_user_process(entry, stack);
}

/// Initialize a thread as a 64-bit user process
pub fn init_process_thread_64<A: crate::Arch>(thread: &mut Thread<A>, entry: u64, stack: u64) {
    thread.kernel.vcpu.regs.init_user_process_64(entry, stack);
}

/// Save CPU state to thread.
pub fn save_state<A: crate::Arch>(thread: &mut Thread<A>, regs: &Regs) {
    thread.kernel.vcpu.regs = *regs;
}

/// Block a thread (waiting for child exit).
pub fn block_thread<A: crate::Arch>(threads: &mut [Thread<A>], tid: usize) {
    threads[tid].kernel.state = ThreadState::Blocked;
}

pub fn unblock_thread<A: crate::Arch>(threads: &mut [Thread<A>], tid: usize) {
    if tid < MAX_THREADS && threads[tid].kernel.state == ThreadState::Blocked {
        threads[tid].kernel.state = ThreadState::Ready;
    }
}

/// Yield a thread: save regs, mark Ready, schedule next.
pub fn yield_thread<A: crate::Arch>(threads: &mut [Thread<A>], tid: usize, regs: &crate::Regs) -> Option<usize> {
    {
        let k = &mut threads[tid].kernel;
        k.vcpu.regs = *regs;
        k.state = ThreadState::Ready;
    }
    schedule(threads, tid)
}

/// Set return value in thread's saved state
pub fn set_return<A: crate::Arch>(thread: &mut Thread<A>, ret: i32) {
    thread.kernel.vcpu.regs.rax = ret as i64 as u64;
}

/// Schedule next thread (randomly selected from ready threads).
/// Returns Some(idx) if a switch is needed, None to stay with current.
pub fn schedule<A: crate::Arch>(threads: &[Thread<A>], current_tid: usize) -> Option<usize> {
    let mut next_idx: usize = usize::MAX;
    let mut count = 0u64;

    for (i, t) in threads.iter().enumerate().take(MAX_THREADS).skip(1) {
        if i == current_tid {
            continue;
        }
        if t.kernel.state == ThreadState::Ready {
            count += 1;
            if prng().is_multiple_of(count) {
                next_idx = i;
            }
        }
    }

    if next_idx == usize::MAX {
        None
    } else {
        Some(next_idx)
    }
}

/// Borrow another thread's `DosState` for a swap-style operation.
/// Returns the target's DosState if the target is a DOS thread, else an errno.
pub fn with_target_dos<F: FnOnce(&mut DosState<A>) -> i32, A: crate::Arch>(threads: &mut [Thread<A>], target_tid: i32, f: F) -> i32 {
    if target_tid < 0 || (target_tid as usize) >= MAX_THREADS { return -22; } // EINVAL
    let target = &mut threads[target_tid as usize];
    if target.kernel.state == ThreadState::Unused { return -3; } // ESRCH
    match &mut target.personality {
        Personality::Dos(d) => f(d),
        _ => -22, // target not DOS
    }
}

/// Last path component (after the final `/` or `\`). The name a picker shows.
pub fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/' || b == b'\\') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Endpoint selected by the F12 window picker (a tid, or -1 when idle).
static SWITCH_TO: core::sync::atomic::AtomicIsize = core::sync::atomic::AtomicIsize::new(-1);

/// Ask to focus a specific thread (the F12 picker's selection).
pub fn request_switch_to(tid: usize) {
    SWITCH_TO.store(tid as isize, core::sync::atomic::Ordering::Relaxed);
}

/// Consume a pending targeted switch, if any.
pub fn take_switch_target() -> Option<usize> {
    let v = SWITCH_TO.swap(-1, core::sync::atomic::Ordering::Relaxed);
    if v >= 0 { Some(v as usize) } else { None }
}

/// Exit thread and schedule next.
/// Returns the TID of the next thread to run (falls back to thread 0/idle).
#[allow(clippy::too_many_arguments)]
pub fn exit_thread<A: crate::Arch>(
    threads: &mut [Thread<A>],
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    tid: usize,
    exit_code: i32,
    exiting_display: &mut Option<crate::kernel::display::ExitDisplay>,
    sb_handoff: &mut Option<crate::kernel::drivers::sb16::SbCard>,
    event_display: &mut Option<crate::kernel::display::Display>,
) -> usize {
    let parent_tid = threads[tid].kernel.parent_tid;
    let term_type = ((exit_code >> 8) & 0xFF) as u8;
    // A successful DOS child returns the live adapter to its DOS parent. The
    // parent's detached VGA is an error/background-switch recovery image, not
    // something to replay on the normal DOS EXEC return path. Ctrl-Break and
    // fault termination restore it; normal exit and TSR retain live VGA state.
    let return_dos_vga = matches!(term_type, 0x00 | 0x03)
        && matches!(threads[tid].personality, Personality::Dos(_))
        && parent_tid >= 0
        && (parent_tid as usize) < MAX_THREADS
        && matches!(threads[parent_tid as usize].personality, Personality::Dos(_));

    // DOS EXEC return transfers the complete child VGA through the event loop;
    // the parked parent's recovery image remains in its own record until the
    // parent address space is active and can consume the replacement.
    if return_dos_vga {
        let child_was_focused = tid == crate::kernel::focus::focused();
        let child = &mut threads[tid];
        let Personality::Dos(child_dos) = &mut child.personality else { unreachable!() };
        let returned = child_dos.pc.vga.release_for_parent_replace(machine);
        assert!(exiting_display.is_none(), "unconsumed exiting display");
        *exiting_display = Some(crate::kernel::display::ExitDisplay::DosReplace(returned));
        if child_was_focused {
            crate::kernel::focus::adopt(parent_tid as usize);
        }
    }

    // Tear down the dying thread (only touches threads[tid]).
    {
        let thread = &mut threads[tid];
        // Release the dying thread's display NOW — `arch_user_clean` below
        // unmaps 0xA0000, after which native VGA capture would fault. A normal
        // DOS parent adopts the unchanged live token; other successors restore
        // their own detached model.
        if tid == crate::kernel::focus::focused() && event_display.is_none() {
            let display = thread.personality.release_display(machine, bios_workspace);
            assert!(exiting_display.is_none(), "unconsumed exiting display");
            *exiting_display = Some(crate::kernel::display::ExitDisplay::Restore(display));
        }
        // The card outlives its holder: whatever the dying thread had goes
        // back into the handoff for the next owner, exactly as the display
        // token does. A thread that never had it yields `None`.
        if let Some(card) = thread.personality.release_sb(machine) {
            assert!(sb_handoff.is_none(), "unconsumed SB handoff");
            *sb_handoff = Some(card);
        }
        match &mut thread.personality {
            Personality::Dos(dos) => dos.on_exit(
                machine, &mut thread.kernel.vcpu, !return_dos_vga),
            Personality::Linux(_) | Personality::Os2(_) | Personality::Windows(_) => {}
        }
        thread.kernel.close_all_fds();
        thread.kernel.symbols = None;
        thread.kernel.exit_code = exit_code;
    }

    // Wake blocked parent and write status BEFORE arch_user_clean — the
    // parent's stack is still accessible through COW-shared pages. Needs the
    // dying thread and the parent borrowed at once (disjoint via split).
    let mut woke_parent = false;
    if parent_tid >= 0 && (parent_tid as usize) < MAX_THREADS && parent_tid as usize != tid {
        let (thread, parent) = get_two_threads(threads, tid, parent_tid as usize);
        let was_waiting = parent.kernel.state == ThreadState::Blocked;
        if was_waiting {
            parent.kernel.state = ThreadState::Ready;
            match &mut parent.personality {
                Personality::Dos(_) => {
                    parent.kernel.vcpu.regs.rax &= !0xFFFF;
                }
                Personality::Linux(linux) => {
                    parent.kernel.vcpu.regs.rax = thread.kernel.tid as u64;
                    // status_ptr was saved in sys_wait4 when parent blocked.
                    // Just set the exit code; the deferred write happens
                    // during thread switch when parent's address space is loaded.
                    linux.wait_exit_code = exit_code;
                }
                Personality::Os2(_) => {
                    parent.kernel.vcpu.regs.rax = thread.kernel.tid as u64;
                }
                Personality::Windows(_) => {
                    parent.kernel.vcpu.regs.rax = thread.kernel.tid as u64;
                }
            }
            refresh_cpu_hash(parent);
            woke_parent = true;
        }
        if let Personality::Dos(dos) = &mut parent.personality {
            // exit_code from the DOS personality already encodes termination
            // type in bits 8..15 and AL/vector in bits 0..7 — copy verbatim.
            dos.last_child_exit_status = exit_code as u16;
        }
    }

    machine.free_user_pages();
    threads[tid].kernel.state = ThreadState::Zombie;
    crate::dbg_println!("[mem] exit tid={} code={} free_pages={}",
        tid, exit_code, machine.free_page_count());

    // Hand focus back to the parent that spawned us — it's the natural caller
    // of wait4. Covers "parent was Blocked on wait4 and we just woke it" and
    // "parent is Ready but hasn't reached wait4 yet" (Rust Command::status:
    // fork stays on child, parent only reaches wait4 after we exit). If the
    // parent is gone/stuck, fall through to the regular scheduler.
    if parent_tid >= 0 && (parent_tid as usize) < MAX_THREADS {
        let parent_state = threads[parent_tid as usize].kernel.state;
        if woke_parent
            || matches!(parent_state, ThreadState::Ready | ThreadState::Running)
        {
            return parent_tid as usize;
        }
    }
    schedule(threads, tid).unwrap_or(0)
}

/// Look for an exited child without reaping it. Returns (child_tid, exit_code)
/// if a matching zombie exists, -EAGAIN if children are alive but none exited,
/// -ECHILD if no children at all. The slot stays in `Zombie` state so the
/// caller can still inspect the child's per-personality state (e.g. DOS pulls
/// the final VGA snapshot via `with_target_dos`) before calling `reap`.
pub fn peek_zombie_child<A: crate::Arch>(threads: &[Thread<A>], current_tid: usize, pid: i32) -> (i32, i32) {
    let current_tid = threads[current_tid].kernel.tid;
    let mut has_children = false;

    for t in threads.iter().take(MAX_THREADS).skip(1) {
        let k = &t.kernel;
        if k.parent_tid == current_tid && k.state != ThreadState::Unused {
            has_children = true;
            if k.state == ThreadState::Zombie && (pid == -1 || k.tid == pid) {
                return (k.tid, k.exit_code);
            }
        }
    }

    if has_children { (-11, 0) } else { (-10, 0) }
}

/// Recycle a Zombie thread slot. No-op if the tid isn't a zombie.
pub fn reap<A: crate::Arch>(threads: &mut [Thread<A>], machine: &mut A, tid: i32) {
    if tid < 0 || (tid as usize) >= MAX_THREADS { return; }
    {
        let t = &mut threads[tid as usize];
        if t.kernel.state == ThreadState::Zombie {
            // Release everything the zombie still holds — the address-space
            // object (interp: host VA reservation + page bookkeeping; metal:
            // no-op, frames went back at exit) and the personality state
            // (VGA planes + suspend snapshot, LDT, DOS bookkeeping). A slot
            // must hold no resources once Unused: anyone learning the tid is
            // free has, by contract, nothing left to collect from it.
            machine.destroy_space(&mut t.kernel.vcpu.space);
            t.personality = Personality::Linux(LinuxState::new());
            t.kernel.state = ThreadState::Unused;
        }
    }
}

/// Reap every zombie. The event loop calls this before returning: its
/// contract is "no thread resources survive the loop" — callers (the DN
/// restart loop, the cmdline sequence) never inherit zombies to clean up.
pub fn reap_all_zombies<A: crate::Arch>(threads: &mut [Thread<A>], machine: &mut A) {
    for i in 1..MAX_THREADS {
        if threads[i].kernel.state == ThreadState::Zombie {
            reap(threads, machine, i as i32);
        }
    }
}

/// Atomic peek + reap. Returns (child_tid, exit_code) or the peek error code.
/// Use when there's no per-personality state to grab from the zombie (the
/// only current caller is Linux sys_wait4, which has nothing to retrieve
/// once the parent has the exit code).
pub fn waitpid<A: crate::Arch>(threads: &mut [Thread<A>], machine: &mut A, current_tid: usize, pid: i32) -> (i32, i32) {
    let r = peek_zombie_child(threads, current_tid, pid);
    if r.0 >= 0 { reap(threads, machine, r.0); }
    r
}

/// Print a SEGV diagnostic for a thread. Halts forever if the faulting
/// thread is init (pid 0) — no parent to escalate to. The caller is
/// expected to dispatch `KernelAction::Exit(-11)` against the faulting
/// `tid` so `exit_thread` does the regular cleanup (parent wake,
/// `last_child_exit_status`, `arch_user_clean`, personality `on_exit`).
pub fn signal_thread<A: crate::Arch>(thread: &Thread<A>, fault_address: usize) {
    if thread.kernel.pid == 0 {
        println!("\x1b[91mSEGV in init at {:#x}\x1b[0m", fault_address);
        loop { core::hint::spin_loop(); }
    }
    println!("SEGV in thread {} at {:#x} rip={:#x} cs={:#x} rsp={:#x} ss={:#x} fl={:#x} rax={:#x} rbx={:#x} rcx={:#x}",
        thread.kernel.tid, fault_address,
        thread.kernel.vcpu.regs.frame.rip, thread.kernel.vcpu.regs.frame.cs,
        thread.kernel.vcpu.regs.frame.rsp, thread.kernel.vcpu.regs.frame.ss,
        thread.kernel.vcpu.regs.frame.rflags,
        thread.kernel.vcpu.regs.rax, thread.kernel.vcpu.regs.rbx, thread.kernel.vcpu.regs.rcx);
}

/// Build the thread table (heap-allocated `Vec<Thread>`, MAX_THREADS slots).
/// `startup()` owns the returned table and threads `&mut [Thread<A>]` through the
/// event loop and executors — it is no longer a global.
pub fn init_threading<A: crate::Arch>() -> alloc::vec::Vec<Thread<A>> {
    let mut threads = alloc::vec::Vec::with_capacity(MAX_THREADS);
    for _ in 0..MAX_THREADS {
        threads.push(Thread::empty());
    }
    // Thread 0 is the init/idle thread (uses boot page directory).
    threads[0].kernel.tid = 0;
    threads[0].kernel.pid = 0;
    threads[0].kernel.priority = 0;
    threads[0].kernel.parent_tid = -1;
    threads[0].kernel.state = ThreadState::Running;
    // root stays empty — idle thread doesn't use user pages
    threads
}
