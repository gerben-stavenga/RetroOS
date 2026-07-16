//! Virtual interrupt-flag (IF) virtualization for protected-mode DPMI clients —
//! the single path, owned by the address space.
//!
//! The hole this closes (see `dpmi-iopl3-single-step-cost`): at CPL>IOPL,
//! `CLI`/`STI` `#GP` (pinned real IOPL=1) so we see virtual IF go 1→0, but
//! `POPF`/`IRET` silently drop IF with no fault, so we never see 0→1.
//!
//! The Windows-95 technique (see Raymond Chen, "Getting MS-DOS games to run on
//! Windows 95: the interrupt flag"): don't chase the exit's *address*, tag the
//! saved-flags *data*. At the `CLI` set TF in the flags word the matching
//! `POPF`/`IRET` will reload (at `cli_sp + delta`, a per-site offset learned
//! once by single-stepping). The reload drops IF but loads TF (not IOPL-gated),
//! so a `#DB` fires one instruction later and we restore VIF there. `STI` exits
//! `#GP` on their own and need no tag.
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
}

/// The window currently open (transient — swapped in/out WITH the address space,
/// so it is per-thread automatically). Was the global `WIN`/`CUR_SITE`/`CUR_SP`.
#[derive(Clone, Copy)]
struct Active {
    cli_ip: u32,
    cli_sp: u32,
    learning: bool,
}

/// Per-address-space virtual-IF state. A field on the DPMI client; dropped with
/// the address space, so nothing leaks across clients or reboots.
#[derive(Default)]
pub struct VifMap {
    /// `cli_ip → Class`, learned once per site. Small open-addressed table keyed
    /// by the CLI address *within this space*.
    sites: SiteTable,
    active: Option<Active>,
    /// Per-client parity counters (windows, predicted-free, tag-closes, steps).
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
        self.active = Some(Active { cli_ip, cli_sp, learning: false });
        self.stats[0] = self.stats[0].wrapping_add(1);
        match self.sites.get(cli_ip) {
            Some(Class::Sti) => {
                // Run free — the STI will #GP and close it.
                self.stats[1] = self.stats[1].wrapping_add(1);
                regs.clear_flag32(TF_FLAG);
            }
            // A flags word at or ABOVE the CLI's SP (d >= 0) was pushed BEFORE the
            // CLI, so it exists now and nothing rewrites it before the exit reads
            // it — tag it in place and run free.
            Some(Class::Flags(d)) if d >= 0 => {
                let addr = stack_base(arch, regs).wrapping_add(cli_sp.wrapping_add(d as u32));
                let w: u32 = arch.read(addr as usize);
                if looks_like_flags(w) {
                    arch.write(addr as usize, w | TF_FLAG); // tag: TF rides the flags
                    self.stats[1] = self.stats[1].wrapping_add(1);
                    regs.clear_flag32(TF_FLAG);
                } else {
                    self.begin_learn(regs); // stale delta (wrong page / SMC) → relearn
                }
            }
            // A word BELOW cli_sp (d < 0) is pushed AFTER the CLI (the exit builds
            // its own flags image), so a CLI-time tag would be overwritten before
            // the POPF/IRET reads it — step to catch the real exit every time.
            Some(Class::Flags(_)) => self.begin_learn(regs),
            None => self.begin_learn(regs),
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

    fn begin_learn(&mut self, regs: &mut Regs) {
        if let Some(a) = &mut self.active {
            a.learning = true;
        }
        regs.set_flag32(TF_FLAG);
    }

    /// Single-step the window, emulating each sensitive op; when one re-enables
    /// VIF it is the exit — record its class + `delta` and stop stepping.
    fn step_learn<A: Arch>(&mut self, arch: &mut A, regs: &mut Regs) -> DbResult {
        const BUDGET: usize = 64;
        for _ in 0..BUDGET {
            if regs.flags32() & VIF_FLAG != 0 {
                regs.clear_flag32(TF_FLAG);
                self.active = None;
                return DbResult::Resume;
            }
            let (cs_base, cs_32) = code_view(arch, regs);
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
            match arch_abi::monitor::monitor(arch, regs) {
                arch_abi::monitor::MonitorResult::Resume => {
                    if regs.flags32() & VIF_FLAG != 0 {
                        let a = self.active;
                        if let Some(a) = a {
                            match op {
                                0xFB => self.sites.insert(a.cli_ip, Class::Sti),
                                0x9D | 0xCF => {
                                    // POPF: flags at [sp]. IRET: after EIP+CS,
                                    // [sp+8] (32-bit) or [sp+4] (16-bit).
                                    let off: u32 = match (op, op32) {
                                        (0xCF, true) => 8,
                                        (0xCF, false) => 4,
                                        _ => 0,
                                    };
                                    let d = sp_before.wrapping_add(off).wrapping_sub(a.cli_sp)
                                        as i32;
                                    self.sites.insert(a.cli_ip, Class::Flags(d));
                                }
                                _ => {}
                            }
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

fn stack_base<A: Arch>(_arch: &A, regs: &Regs) -> u32 {
    A::seg_base(regs.stack_seg())
}
fn code_view<A: Arch>(_arch: &A, regs: &Regs) -> (u32, bool) {
    let cs = regs.code_seg();
    (A::seg_base(cs), A::seg_is_32(cs))
}

// ── Small per-space CLI-site table ───────────────────────────────────────────
// Open-addressed, fixed capacity — a client has a handful of critical sections.

const N: usize = 64;

struct SiteTable {
    ip: [u32; N],   // 0 = empty
    class: [u8; N], // 0 empty · 1 Sti · 2 Flags
    delta: [i32; N],
}

impl SiteTable {
    const fn new() -> Self {
        SiteTable { ip: [0; N], class: [0; N], delta: [0; N] }
    }
    fn slot(ip: u32) -> usize {
        (ip.wrapping_mul(0x9E37_79B1) >> 26) as usize & (N - 1)
    }
    fn find(&self, ip: u32) -> Option<usize> {
        let i = Self::slot(ip);
        (self.ip[i] == ip && self.class[i] != 0).then_some(i)
    }
    fn get(&self, ip: u32) -> Option<Class> {
        self.find(ip).map(|i| match self.class[i] {
            1 => Class::Sti,
            _ => Class::Flags(self.delta[i]),
        })
    }
    fn insert(&mut self, ip: u32, c: Class) {
        let i = Self::slot(ip);
        self.ip[i] = ip;
        match c {
            Class::Sti => {
                self.class[i] = 1;
            }
            Class::Flags(d) => {
                self.class[i] = 2;
                self.delta[i] = d;
            }
        }
    }
    fn retain_out_of_page(&mut self, page: u32) {
        for i in 0..N {
            if self.ip[i] >> 12 == page {
                self.class[i] = 0;
                self.ip[i] = 0;
            }
        }
    }
}

impl Default for SiteTable {
    fn default() -> Self {
        Self::new()
    }
}
