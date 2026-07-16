//! Virtual interrupt-flag (IF) virtualization for protected-mode DPMI clients —
//! the single path, owned by the address space.
//!
//! The hole this closes (see `dpmi-iopl3-single-step-cost`): at CPL>IOPL,
//! `CLI`/`STI` `#GP` (pinned real IOPL=1) so we see virtual IF go 1→0, but
//! `POPF`/`IRET` silently drop IF with no fault, so we never see 0→1.
//!
//! The Windows-95 technique (see Raymond Chen, "Getting MS-DOS games to run on
//! Windows 95: the interrupt flag"): don't chase the exit's *address*, tag the
//! saved-flags *data* with TF. The reload drops IF but loads TF (not
//! IOPL-gated), so a `#DB` fires one instruction later and we restore VIF there.
//! `STI` exits `#GP` on their own and need no tag.
//!
//! Each CLI site is learned once (by single-stepping the window) into one of
//! three exit shapes, then runs free forever after:
//!   * `Sti`      — the exit `#GP`s on its own.
//!   * `Flags(d)` with `d >= 0` — the saved-flags word was pushed BEFORE the
//!     CLI (at `cli_sp + d`), so it exists and is stable: tag it in memory.
//!   * `Reg(r)`   — the flags round-trip through registers (Watcom's
//!     `pushf; pop r1; cli; …; push r2; popf`; the body may move the image
//!     r1 → … → r2 through registers or memory). The exit word is built AFTER
//!     the CLI by the exit's own `push`, so a memory tag there gets
//!     overwritten; instead tag the *source register* `r1` — the guest's own
//!     copies + push then carry TF onto the stack. The push that would clobber
//!     a memory tag now creates it. Promoted only from a `RegProbe` pass that
//!     OBSERVED the tag propagate, never from byte/value pattern alone.
//!   * `Flags(d)` with `d < 0` and no register idiom — single-step every time.
//!
//! Everything here is POLICY and belongs to the DOS/DPMI personality, NOT arch:
//! the map is per-CLI-site and thus **per address space** (a bare virtual
//! address is meaningless across spaces), lives and dies with the client, and
//! is invalidated per page when code is written. arch's only job is to reflect
//! the `#GP`/`#DB` and let us drive `regs` + guest memory.

use arch_abi::{Arch, Regs};

// EFLAGS bits.
const IF_FLAG: u32 = 1 << 9;
const TF_FLAG: u32 = 1 << 8;
const VIF_FLAG: u32 = 1 << 19; // our virtual IF (host-only bit)

/// How a window exits, learned per CLI site.
#[derive(Clone, Copy)]
enum Class {
    /// Exit is an `STI` — it `#GP`s on its own, nothing to tag.
    Sti,
    /// Exit is a `POPF`/`IRET`; its flags word sits at `cli_sp + delta`.
    Flags(i32),
    /// Candidate register tag: `pushf; pop r1` precedes the CLI, the exit is
    /// `push r2; popf`, and r1's CLI-time value equals the word popped. Value
    /// equality alone can't prove the popped image *derives from* r1 (flags
    /// images are near-constant, so a stale copy elsewhere can coincide), so
    /// the next window runs a PROBE: tag r1, step anyway, and promote to
    /// [`Class::Reg`] only if the popped word arrives carrying the tag.
    RegProbe(u8),
    /// Confirmed register tag: a probe observed the TF tag travel
    /// CLI-register → … → push → popf. Tag `r` at the CLI and run free
    /// (x86 index 0..7, never esp).
    Reg(u8),
}

/// The window currently open (transient — swapped in/out WITH the address space,
/// so it is per-thread automatically). Was the global `WIN`/`CUR_SITE`/`CUR_SP`.
#[derive(Clone, Copy)]
struct Active {
    cli_ip: u32,
    cli_sp: u32,
    learning: bool,
    /// `Some(r)` while this learning window is a PROBE: we set TF in `r` at the
    /// CLI and are stepping to observe whether the exit's popped word carries
    /// it (see [`Class::RegProbe`]).
    probe: Option<u8>,
    /// GPRs (eax..edi) at the CLI, captured when learning — lets the exit
    /// classifier compare a register's CLI-time value against the word the
    /// exit actually popped before nominating a register tag.
    snap: [u32; 8],
}

/// Per-address-space virtual-IF state. A field on the DPMI client; dropped with
/// the address space, so nothing leaks across clients or reboots.
#[derive(Default)]
pub struct VifMap {
    /// `cli_ip → Class`, learned once per site. Small open-addressed table keyed
    /// by the CLI address *within this space*.
    sites: SiteTable,
    active: Option<Active>,
    /// Per-client parity counters (windows, tag-closes, post-tag #DBs, steps).
    pub stats: [u32; 4],
}

impl VifMap {
    pub const fn new() -> Self {
        VifMap { sites: SiteTable::new(), active: None, stats: [0; 4] }
    }

    /// A `CLI` `#GP`'d: virtual IF just went 1→0, a window opens at `cli_ip`.
    /// `arch` gives guest memory + segment bases; `regs` is the fault frame.
    pub fn on_cli<A: Arch>(&mut self, arch: &mut A, regs: &mut Regs, cli_ip: u32) {
        let cli_sp = regs.sp32();
        self.active = Some(Active { cli_ip, cli_sp, learning: false, probe: None, snap: [0; 8] });
        self.stats[0] = self.stats[0].wrapping_add(1);
        match self.sites.get(cli_ip) {
            Some(Class::Sti) => {
                // Run free — the STI will #GP and close it.
                self.stats[1] = self.stats[1].wrapping_add(1);
                regs.clear_flag32(TF_FLAG);
            }
            // Flags saved on the stack BEFORE the CLI (d >= 0): the word exists
            // now and nothing rewrites it before the exit reads it — tag it.
            Some(Class::Flags(d)) if d >= 0 => {
                let addr = stack_base::<A>(regs).wrapping_add(cli_sp.wrapping_add(d as u32));
                let w: u32 = arch.read(addr as usize);
                if looks_like_flags(w) {
                    arch.write(addr as usize, w | TF_FLAG); // tag: TF rides the flags
                    self.stats[1] = self.stats[1].wrapping_add(1);
                    regs.clear_flag32(TF_FLAG);
                } else {
                    self.begin_learn(regs, None); // stale delta (wrong page / SMC) → relearn
                }
            }
            // Flags ride in a register: tag the SOURCE. The guest's own `push`
            // writes the tagged image to the stack and the `popf` loads TF → #DB.
            // The looks_like_flags guard means we only ever set bit 8 in a value
            // that is already a flags image, never in a live pointer.
            Some(Class::Reg(r)) => {
                let v = reg32(regs, r);
                if looks_like_flags(v) {
                    set_reg32(regs, r, v | TF_FLAG);
                    self.stats[1] = self.stats[1].wrapping_add(1);
                    regs.clear_flag32(TF_FLAG);
                } else {
                    self.begin_learn(regs, None); // register isn't flags right now → relearn
                }
            }
            // Probe pass: tag the candidate register AND step. classify_exit
            // promotes to Reg only if the popped word carries the tag — the one
            // observation that proves the image flows from this register.
            Some(Class::RegProbe(r)) => {
                let v = reg32(regs, r);
                if looks_like_flags(v) {
                    set_reg32(regs, r, v | TF_FLAG);
                    self.begin_learn(regs, Some(r));
                } else {
                    self.begin_learn(regs, None);
                }
            }
            // A word BELOW cli_sp with no register idiom: the exit builds its own
            // flags image after the CLI and we can't predict it — step every time.
            Some(Class::Flags(_)) => self.begin_learn(regs, None),
            None => self.begin_learn(regs, None),
        }
    }

    /// An `STI` `#GP`'d: it re-enabled IF on its own. If we were learning, this
    /// site's exit is an STI. (arch has already reflected the fault; we set VIF.)
    pub fn on_sti(&mut self, regs: &mut Regs) {
        regs.set_flags32(regs.flags32() | VIF_FLAG);
        if let Some(a) = self.active.take()
            && a.learning
        {
            self.sites.insert(a.cli_ip, Class::Sti);
        }
        regs.clear_flag32(TF_FLAG);
    }

    /// A `#DB`: either the post-tag trap (a tagged `POPF`/`IRET` just ran) or a
    /// learning single-step. Returns whether the client should resume.
    pub fn on_db<A: Arch>(&mut self, arch: &mut A, regs: &mut Regs) -> DbResult {
        match self.active {
            Some(a) if a.learning => self.step_learn(arch, regs),
            _ => {
                // Post-tag (or self-heal of a leaked tag): restore VIF, one
                // instruction late; clear TF.
                regs.set_flags32(regs.flags32() | VIF_FLAG);
                regs.clear_flag32(TF_FLAG);
                self.active = None;
                self.stats[2] = self.stats[2].wrapping_add(1);
                DbResult::Resume
            }
        }
    }

    fn begin_learn(&mut self, regs: &mut Regs, probe: Option<u8>) {
        if let Some(a) = &mut self.active {
            a.learning = true;
            a.probe = probe;
            for (i, s) in a.snap.iter_mut().enumerate() {
                *s = reg32(regs, i as u8);
            }
        }
        regs.set_flag32(TF_FLAG);
    }

    /// Single-step the window, emulating each sensitive op; when one re-enables
    /// VIF it is the exit — record its class and stop stepping.
    fn step_learn<A: Arch>(&mut self, arch: &mut A, regs: &mut Regs) -> DbResult {
        const BUDGET: usize = 64;
        for _ in 0..BUDGET {
            if regs.flags32() & VIF_FLAG != 0 {
                regs.clear_flag32(TF_FLAG);
                self.active = None;
                return DbResult::Resume;
            }
            let (cs_base, cs_32) = code_view::<A>(regs);
            let mut p = regs.ip32();
            let mut has66 = false;
            loop {
                let b = arch.read::<u8>(cs_base.wrapping_add(p) as usize);
                if b == 0x66 {
                    has66 = true;
                    p = p.wrapping_add(1);
                } else if matches!(b, 0x67 | 0xF0 | 0xF2 | 0xF3) {
                    p = p.wrapping_add(1);
                } else {
                    break;
                }
            }
            let op = arch.read::<u8>(cs_base.wrapping_add(p) as usize);
            if !matches!(op, 0x9C | 0x9D | 0xCF | 0xFA | 0xFB) {
                self.stats[3] = self.stats[3].wrapping_add(1);
                regs.set_flag32(TF_FLAG);
                return DbResult::Resume;
            }
            let op32 = cs_32 ^ has66; // operand width of this instruction
            let sp_before = regs.sp32();
            let ip_before = regs.ip32(); // this instruction's start (the exit's IP)
            match arch_abi::monitor::monitor(arch, regs) {
                arch_abi::monitor::MonitorResult::Resume => {
                    if regs.flags32() & VIF_FLAG != 0 {
                        if let Some(a) = self.active {
                            let class = classify_exit(arch, regs, &a, op, op32, sp_before, ip_before);
                            self.sites.insert(a.cli_ip, class);
                        }
                        regs.clear_flag32(TF_FLAG);
                        self.active = None;
                        return DbResult::Resume;
                    }
                }
                arch_abi::monitor::MonitorResult::Event(ev) => return DbResult::Event(ev),
            }
        }
        self.stats[3] = self.stats[3].wrapping_add(1);
        regs.set_flag32(TF_FLAG);
        DbResult::Resume
    }

    /// Drop learned entries on a written code page (self-modifying code, overlay
    /// reload). Called from the per-space code-write / SMC path.
    pub fn invalidate_page(&mut self, page: u32) {
        self.sites.retain_out_of_page(page);
    }
}

/// Decide what kind of exit just re-enabled VIF. `op` is the exit opcode, already
/// emulated (so `regs` is post-exit); `ip_before`/`sp_before` are its pre-emulation
/// IP/SP. Only the ops that set VIF reach here: STI (0xFB), POPF (0x9D), IRET
/// (0xCF) — STI is emulated inline during learning, so it lands here too.
fn classify_exit<A: Arch>(
    arch: &mut A,
    regs: &Regs,
    a: &Active,
    op: u8,
    op32: bool,
    sp_before: u32,
    ip_before: u32,
) -> Class {
    // STI re-enables on its own and #GPs at IOPL=1 — no tag needed, runs free.
    if op == 0xFB {
        return Class::Sti;
    }
    // POPF fed from a pushed register: the flags image was captured into `r1`
    // (`pushf; pop r1` before the CLI) and popped from `r2` (`push r2; popf` at
    // the exit) — the body may move it r1 → … → r2 through registers or memory.
    // The byte pattern is a backward read, not an instruction-boundary proof,
    // and value equality can't distinguish dataflow from coincidence (flags
    // images are near-constant), so classification is two-phase:
    //  * learn pass: bytes nominate (r1, r2) and the values line up (r1's CLI
    //    image == r2 at exit == the word popped) → `RegProbe(r1)`;
    //  * probe pass: r1 was tagged at this window's CLI and we stepped anyway —
    //    the tag arriving in the popped word proves the flow end-to-end →
    //    `Reg(r1)` runs free; its absence proves coincidence → fall through to
    //    the memory delta (d < 0 keeps stepping).
    if op == 0x9D {
        // POPF never changes CS, so the code base is still the faulting CS's —
        // resolve it here instead of threading it through the call.
        let cs_base = code_view::<A>(regs).0;
        let popped: u32 = arch.read(stack_base::<A>(regs).wrapping_add(sp_before) as usize);
        let m = if op32 { u32::MAX } else { 0xFFFF };
        if let Some(r) = a.probe {
            if popped & TF_FLAG != 0 && (popped ^ a.snap[r as usize]) & m & !TF_FLAG == 0 {
                return Class::Reg(r);
            }
        } else if let Some((r1, r2)) = reg_idiom(arch, cs_base, a.cli_ip, ip_before)
            && looks_like_flags(a.snap[r1 as usize])
            && (a.snap[r1 as usize] ^ reg32(regs, r2)) & m & !TF_FLAG == 0
            && (popped ^ reg32(regs, r2)) & m == 0
        {
            return Class::RegProbe(r1);
        }
    }
    // Otherwise a memory delta. POPF: flags at [sp]. IRET: after EIP+CS,
    // [sp+8] (32-bit) or [sp+4] (16-bit). d >= 0 tags; d < 0 steps.
    let off: u32 = match (op, op32) {
        (0xCF, true) => 8,
        (0xCF, false) => 4,
        _ => 0,
    };
    Class::Flags(sp_before.wrapping_add(off).wrapping_sub(a.cli_sp) as i32)
}

/// Match the Watcom register round-trip idiom: `pushf; pop r1` immediately
/// before the CLI, and `push r2; popf` at the exit. `r1` need not equal `r2` —
/// the body may move the image between registers or through memory; the caller
/// checks the values line up and a probe pass proves the dataflow before the
/// site runs free. Returns `(r1, r2)` (never esp).
fn reg_idiom<A: Arch>(arch: &mut A, cs_base: u32, cli_ip: u32, popf_ip: u32) -> Option<(u8, u8)> {
    let at = |ip: u32| -> u8 { arch.read::<u8>(cs_base.wrapping_add(ip) as usize) };
    let pushf = at(cli_ip.wrapping_sub(2)); // 9C
    let pop = at(cli_ip.wrapping_sub(1)); //  58..5F  pop r1
    let push = at(popf_ip.wrapping_sub(1)); // 50..57  push r2
    if pushf == 0x9C && (0x58..=0x5F).contains(&pop) && (0x50..=0x57).contains(&push) {
        let (r1, r2) = (pop - 0x58, push - 0x50);
        if r1 != 4 && r2 != 4 {
            return Some((r1, r2));
        }
    }
    None
}

/// Result of `on_db` — resume the client, or bubble a decoded event (a POPF that
/// turned out to be an INT-reflect, a fault, …) up to the personality.
pub enum DbResult {
    Resume,
    Event(arch_abi::KernelEvent),
}

/// Saved flags we intend to re-enable IF from: IF set, reserved bit 1 set, TF
/// clear. Checks only the low 16 bits, valid for a 16- or 32-bit pushed image.
fn looks_like_flags(w: u32) -> bool {
    w & IF_FLAG != 0 && w & 2 != 0 && w & TF_FLAG == 0
}

fn stack_base<A: Arch>(regs: &Regs) -> u32 {
    A::seg_base(regs.stack_seg())
}
fn code_view<A: Arch>(regs: &Regs) -> (u32, bool) {
    let cs = regs.code_seg();
    (A::seg_base(cs), A::seg_is_32(cs))
}

/// The low 32 bits of a GPR by x86 register index (0=eax..7=edi).
fn reg32(regs: &Regs, idx: u8) -> u32 {
    (match idx {
        0 => regs.rax,
        1 => regs.rcx,
        2 => regs.rdx,
        3 => regs.rbx,
        4 => regs.frame.rsp,
        5 => regs.rbp,
        6 => regs.rsi,
        _ => regs.rdi,
    }) as u32
}
/// Write the low 32 bits of a GPR (esp/idx 4 never reached — filtered at learn).
fn set_reg32(regs: &mut Regs, idx: u8, v: u32) {
    let slot: &mut u64 = match idx {
        0 => &mut regs.rax,
        1 => &mut regs.rcx,
        2 => &mut regs.rdx,
        3 => &mut regs.rbx,
        4 => &mut regs.frame.rsp,
        5 => &mut regs.rbp,
        6 => &mut regs.rsi,
        _ => &mut regs.rdi,
    };
    *slot = (*slot & !0xFFFF_FFFF) | v as u64;
}

// ── Small per-space CLI-site table ───────────────────────────────────────────
// Open-addressed, fixed capacity — a client has a handful of critical sections.
// Stores the `Class` enum directly; `None` = empty slot.

const N: usize = 64;

struct SiteTable {
    slots: [Option<(u32, Class)>; N], // (cli_ip, class)
}

impl SiteTable {
    const fn new() -> Self {
        SiteTable { slots: [None; N] }
    }
    fn slot(ip: u32) -> usize {
        (ip.wrapping_mul(0x9E37_79B1) >> 26) as usize & (N - 1)
    }
    fn get(&self, ip: u32) -> Option<Class> {
        match self.slots[Self::slot(ip)] {
            Some((a, c)) if a == ip => Some(c),
            _ => None,
        }
    }
    fn insert(&mut self, ip: u32, c: Class) {
        self.slots[Self::slot(ip)] = Some((ip, c));
    }
    fn retain_out_of_page(&mut self, page: u32) {
        for s in &mut self.slots {
            if let Some((a, _)) = *s
                && a >> 12 == page
            {
                *s = None;
            }
        }
    }
}

impl Default for SiteTable {
    fn default() -> Self {
        Self::new()
    }
}
