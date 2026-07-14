//! arch-abi — the backend-agnostic contract shared by the kernel and every
//! `arch` backend (bare-metal x86 in `kernel/src/arch/`, and the software
//! interpreter in `arch-interp/`).
//!
//! This crate holds only the *pure-data* types that cross the arch↔kernel
//! boundary: the register/frame layout, the execution mode, the canonical
//! `KernelEvent` a run produces, port-I/O sizes, the IRQ event, the raw page
//! blob, and the guest-visible selector/size constants. It is `no_std`, has
//! zero dependencies, and builds identically under both the Bazel freestanding
//! toolchain (metal) and the host build (interp).
//!
//! Backend-internal types (`RootPageTable`, `KernelPages`, `FxState`, `Vcpu`,
//! `GuestMem`) deliberately do NOT live here — each backend defines its own,
//! because their representation (real page tables / FXSAVE vs a software
//! address space) genuinely differs. Both backends are x86, so they share this
//! one register ABI rather than inventing two.

#![no_std]

mod arch;
pub use arch::{Arch, GuestBytes, Vcpu};

pub mod monitor;

/// Hardware execute breakpoints available for the virtual-IF exit set (DR0-DR3).
pub const MAX_EXEC_BP: usize = 4;

/// Single-step trace budget — a cross-boundary diagnostic, not an arch operation.
/// Armed by the DOS/DPMI layer (kernel) to watch a client's code path after a
/// suspicious return; consumed by the backend's single-step `#DB` handler, which
/// decrements it and logs each step until it reaches zero. It lives here because
/// it is the one piece of state the *arming* side (kernel) and the *consuming*
/// side (backend) both touch, and both depend on this crate. Backends without a
/// single-step trap (the interpreter) simply never read it.
pub static PM_STEP_BUDGET: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Boot-time platform configuration, read once by the platform entry point and
/// handed to `startup` — instead of the kernel poking firmware ports itself.
///
/// It carries the host-selected headless command line, working directory,
/// debug-watch addresses, and the is-QEMU flag. On metal, the backend's entry
/// reads these from QEMU's fw_cfg interface; the hosted `main` fills them
/// straight from its CLI args. It lives here — the boot boundary contract — so
/// the entry (which constructs it) and the kernel (which consumes it) share one
/// type across the crate split.
pub struct BootConfig {
    cmdline: [u8; 4096],
    cmdline_len: Option<usize>, // None = no headless cmdline (interactive DN loop)
    cwd: [u8; 256],
    cwd_len: Option<usize>,
    /// VFS subtree that DOS drive `C:` maps to (normalized: no leading `/`, one
    /// trailing `/`; empty = root). Default `home/retroos/` so DOS gets a tidy
    /// C: while Linux keeps the real `/`. The in-OS build toolchain sets it to
    /// `""` (root) so TC's hardcoded `C:\TC` paths still resolve.
    c_root: [u8; 128],
    c_root_len: usize,
    /// Debug write-watch addresses (metal QEMU `opt/debug-watch`), if any.
    pub debug_watch: Option<(u32, u32)>,
    /// Host is QEMU-like: fabricate the synthetic 0x3DA vtrace etc. (vs Bochs /
    /// real hardware, whose 0x3DA is passed through).
    pub is_qemu: bool,
}

impl BootConfig {
    pub const fn empty() -> Self {
        let mut cfg = BootConfig {
            cmdline: [0; 4096], cmdline_len: None,
            cwd: [0; 256], cwd_len: None,
            c_root: [0; 128], c_root_len: 0,
            debug_watch: None, is_qemu: false,
        };
        // Default C: root = "home/retroos/".
        let d = *b"home/retroos/";
        let mut i = 0;
        while i < d.len() { cfg.c_root[i] = d[i]; i += 1; }
        cfg.c_root_len = d.len();
        cfg
    }
    /// Record the headless command line (semicolon-separated program list).
    pub fn set_cmdline(&mut self, s: &[u8]) {
        let n = s.len().min(self.cmdline.len());
        self.cmdline[..n].copy_from_slice(&s[..n]);
        self.cmdline_len = Some(n);
    }
    /// Record the explicit working directory for the headless launch.
    pub fn set_cwd(&mut self, s: &[u8]) {
        let n = s.len().min(self.cwd.len());
        self.cwd[..n].copy_from_slice(&s[..n]);
        self.cwd_len = Some(n);
    }
    pub fn cmdline(&self) -> Option<&[u8]> { self.cmdline_len.map(|n| &self.cmdline[..n]) }
    pub fn cwd(&self) -> Option<&[u8]> { self.cwd_len.map(|n| &self.cwd[..n]) }
    /// Set the DOS C: root (VFS prefix). Normalized: leading `/` stripped, one
    /// trailing `/` added when non-empty; `"/"` or `""` → root.
    pub fn set_c_root(&mut self, s: &[u8]) {
        let mut t = s;
        while t.first() == Some(&b'/') { t = &t[1..]; }
        while t.last() == Some(&b'/') { t = &t[..t.len() - 1]; }
        let mut n = 0;
        for &b in t {
            if n < self.c_root.len() - 1 { self.c_root[n] = b; n += 1; }
        }
        if n > 0 { self.c_root[n] = b'/'; n += 1; }
        self.c_root_len = n;
    }
    /// The DOS C: root as a VFS prefix (e.g. `home/retroos/`, or `` for root).
    pub fn c_root(&self) -> &[u8] { &self.c_root[..self.c_root_len] }
}

/// Parse an `opt/debug-watch` value (`"addr0[,addr1]"`, hex with optional `0x`)
/// into write-watch addresses, for the metal entry to fill
/// `BootConfig::debug_watch`. Returns `None` if empty/unparseable.
pub fn parse_debug_watch(raw: &[u8]) -> Option<(u32, u32)> {
    fn trim(s: &[u8]) -> &[u8] {
        let start = s.iter().position(|&c| c > b' ').unwrap_or(s.len());
        let end = s.iter().rposition(|&c| c > b' ').map_or(start, |i| i + 1);
        &s[start..end]
    }
    fn parse_u32(mut s: &[u8]) -> Option<u32> {
        s = trim(s);
        if s.starts_with(b"0x") || s.starts_with(b"0X") { s = &s[2..]; }
        if s.is_empty() { return None; }
        let mut value = 0u32;
        for &b in s {
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                b'_' => continue,
                _ => return None,
            };
            value = value.checked_mul(16)?.checked_add(digit)?;
        }
        Some(value)
    }
    let raw = trim(raw);
    if raw.is_empty() { return None; }
    let split = raw.iter().position(|&b| b == b',' || b == b' ' || b == b';');
    let addr0 = parse_u32(raw.get(..split.unwrap_or(raw.len()))?)?;
    let addr1 = match split {
        Some(idx) => parse_u32(trim(&raw[idx + 1..])).unwrap_or(0),
        None => 0,
    };
    Some((addr0, addr1))
}

// =============================================================================
// Guest-visible selector values (ABI-fixed across backends)
// =============================================================================
//
// These are the ring-3 GDT selector values the guest runs under. The metal
// backend installs a GDT with exactly these selectors; the interpreter presents
// the same values so `Regs::mode()` decodes identically on both. They live here
// (rather than in a backend) because they are part of the guest-visible ABI.

pub const USER_CS: u16 = 0x20 | 3; // Ring 3
pub const USER_DS: u16 = 0x28 | 3; // Ring 3
pub const USER_CS64: u16 = 0x30 | 3; // Ring 3

/// `Arch::map_phys_range` flag: map the range as an **emulated MMIO aperture** —
/// present=0 with the regular Cache-Disable (PCD) attribute the kernel already
/// uses for device memory (NVMe BARs, AC'97/SB DMA map present+PCD). The
/// present=0 + PCD pair is the *trapped* twin: a guest access faults to the
/// kernel (the planar VGA window, future emulated BARs) instead of
/// demand-committing RAM — present distinguishes passthrough device memory
/// from an emulated one. No invented software bit. The interp must NOT ignore
/// map flags — that silently diverges from metal the moment a flag carries
/// meaning.
pub const MAP_MMIO: u64 = 1 << 10;

// =============================================================================
// Page geometry
// =============================================================================

/// Page size in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Low memory (first 1MB) is mapped here for VGA/BIOS/VM86 on the metal
/// backend; the interpreter reuses the same constant value.
pub const LOW_MEM_BASE: usize = 0xC0A0_0000;

/// A raw 4 KiB, page-aligned blob. Pure data shared by both backends (page
/// tables on metal, scratch frames, etc.). The inner array is public so each
/// backend can build page-table storage out of it.
#[derive(Clone)]
#[repr(C, align(4096))]
pub struct RawPage(pub [u8; PAGE_SIZE]);

// =============================================================================
// Register / interrupt-frame layout
// =============================================================================

/// CPU-pushed interrupt frame for 64-bit mode.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frame64 {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl core::fmt::Debug for Frame64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame64")
            .field("rip", &format_args!("{:#018x}", self.rip))
            .field("cs", &format_args!("{:#06x}", self.cs))
            .field("rflags", &format_args!("{:#018x}", self.rflags))
            .field("rsp", &format_args!("{:#018x}", self.rsp))
            .field("ss", &format_args!("{:#06x}", self.ss))
            .finish()
    }
}

/// User execution mode, derived from register state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserMode { VM86, Mode32, Mode64 }

/// CPU register state saved by the interrupt handler.
/// Also used as the saved CPU state in Thread (identical layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Regs {
    // Segment registers (zero-extended)
    pub gs: u64,
    pub fs: u64,
    pub es: u64,
    pub ds: u64,
    // x86-64 extended registers (zero in 32-bit mode)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    // General purpose registers
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp_dummy: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // Interrupt info (software-pushed, zero-extended to 64-bit)
    pub int_num: u64,
    pub err_code: u64,
    // CPU-pushed interrupt frame normalized to Frame64 before the kernel sees it.
    pub frame: Frame64,
}

impl Regs {
    pub const fn empty() -> Self {
        Regs {
            gs: 0, fs: 0, es: 0, ds: 0,
            r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
            rdi: 0, rsi: 0, rbp: 0, rsp_dummy: 0, rbx: 0, rdx: 0, rcx: 0, rax: 0,
            int_num: 0, err_code: 0,
            frame: Frame64 { rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0 },
        }
    }

    pub fn ip32(&self) -> u32 {
        self.frame.rip as u32
    }

    pub fn set_ip32(&mut self, ip: u32) {
        self.frame.rip = ip as u64;
    }

    pub fn cs32(&self) -> u32 {
        self.frame.cs as u32
    }

    pub fn set_cs32(&mut self, cs: u32) {
        self.frame.cs = cs as u64;
    }

    pub fn flags32(&self) -> u32 {
        self.frame.rflags as u32
    }

    pub fn set_flags32(&mut self, flags: u32) {
        self.frame.rflags = flags as u64;
    }

    pub fn set_flag32(&mut self, mask: u32) {
        self.set_flags32(self.flags32() | mask);
    }

    pub fn clear_flag32(&mut self, mask: u32) {
        self.set_flags32(self.flags32() & !mask);
    }

    pub fn sp32(&self) -> u32 {
        self.frame.rsp as u32
    }

    pub fn set_sp32(&mut self, sp: u32) {
        self.frame.rsp = sp as u64;
    }

    pub fn ss32(&self) -> u32 {
        self.frame.ss as u32
    }

    pub fn set_ss32(&mut self, ss: u32) {
        self.frame.ss = ss as u64;
    }

    /// Get instruction pointer.
    pub fn ip(&self) -> u64 {
        self.frame.rip
    }

    /// Get code segment
    pub fn code_seg(&self) -> u16 {
        self.frame.cs as u16
    }

    /// Get flags
    pub fn flags(&self) -> u64 {
        self.frame.rflags
    }

    /// Derive execution mode from canonical register state.
    /// Checks CS first (64-bit wins over stale VM flag), then EFLAGS.VM.
    /// Returns Mode32 for kernel regs (ring 1 CS) too.
    pub fn mode(&self) -> UserMode {
        if self.frame.cs == USER_CS64 as u64 {
            UserMode::Mode64
        } else if self.frame.rflags & (1 << 17) != 0 {
            UserMode::VM86
        } else {
            UserMode::Mode32
        }
    }

    /// Get stack pointer
    pub fn sp(&self) -> u64 {
        self.frame.rsp
    }

    /// Get stack segment
    pub fn stack_seg(&self) -> u16 {
        self.frame.ss as u16
    }

    /// Initialize for a 32-bit user process (stored as Frame64; arch converts
    /// on exit if needed). Canonical entry state, so it lives with the contract.
    pub fn init_user_process(&mut self, entry: u32, stack: u32) {
        let ds = USER_DS as u64;
        const IF_FLAG: u64 = 1 << 9;
        // VIF (bit 19) is the canonical guest interrupt-enable; a fresh Linux
        // process runs with interrupts on. Metal forces real IF=1 regardless,
        // but the interp projects VIF->IF, so without this it would run IF=0.
        const VIF_FLAG: u64 = 1 << 19;

        *self = Self::empty();
        self.gs = ds;
        self.fs = ds;
        self.es = ds;
        self.ds = ds;
        self.frame = Frame64 {
            rip: entry as u64,
            cs: USER_CS as u64,
            rflags: IF_FLAG | VIF_FLAG,
            rsp: stack as u64,
            ss: USER_DS as u64,
        };
    }

    /// Initialize for a 64-bit user process.
    pub fn init_user_process_64(&mut self, entry: u64, stack: u64) {
        let ds = USER_DS as u64;
        const IF_FLAG: u64 = 1 << 9;
        // VIF (bit 19) is the canonical guest interrupt-enable; a fresh Linux
        // process runs with interrupts on. Metal forces real IF=1 regardless,
        // but the interp projects VIF->IF, so without this it would run IF=0.
        const VIF_FLAG: u64 = 1 << 19;

        *self = Self::empty();
        self.gs = 0;   // FS/GS are MSR bases in 64-bit mode, 0 = no TLS yet
        self.fs = 0;
        self.es = ds;
        self.ds = ds;
        self.frame = Frame64 {
            rip: entry,
            cs: USER_CS64 as u64,
            rflags: IF_FLAG | VIF_FLAG,
            rsp: stack,
            ss: USER_DS as u64,
        };
    }
}

impl core::fmt::Debug for Regs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "INT: {:#04x}  ERR: {:#010x}", self.int_num, self.err_code)?;
        writeln!(f, "IP:  {:#010x}  CS: {:#06x}  FL: {:#010x}", self.ip(), self.code_seg(), self.flags())?;
        writeln!(f, "SP:  {:#010x}  SS: {:#06x}", self.sp(), self.stack_seg())?;
        writeln!(f, "RAX: {:#018x}  RBX: {:#018x}", self.rax, self.rbx)?;
        writeln!(f, "RCX: {:#018x}  RDX: {:#018x}", self.rcx, self.rdx)?;
        writeln!(f, "RSI: {:#018x}  RDI: {:#018x}", self.rsi, self.rdi)?;
        writeln!(f, "RBP: {:#018x}  R8:  {:#018x}", self.rbp, self.r8)?;
        writeln!(f, "R9:  {:#018x}  R10: {:#018x}", self.r9, self.r10)?;
        writeln!(f, "R11: {:#018x}  R12: {:#018x}", self.r11, self.r12)?;
        writeln!(f, "R13: {:#018x}  R14: {:#018x}", self.r13, self.r14)?;
        writeln!(f, "R15: {:#018x}", self.r15)?;
        write!(f, "DS: {:#06x}  ES: {:#06x}  FS: {:#06x}  GS: {:#06x}",
               self.ds as u16, self.es as u16, self.fs as u16, self.gs as u16)
    }
}

// =============================================================================
// Port-I/O operand width
// =============================================================================

/// Operand width for port I/O events.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoSize {
    Byte  = 0,
    Word  = 1,
    Dword = 2,
}

impl IoSize {
    pub const fn bytes(self) -> u32 {
        match self { IoSize::Byte => 1, IoSize::Word => 2, IoSize::Dword => 4 }
    }
    pub const fn from_u32(v: u32) -> Self {
        match v & 3 { 0 => IoSize::Byte, 1 => IoSize::Word, _ => IoSize::Dword }
    }
}

// =============================================================================
// Canonical kernel-visible event
// =============================================================================

/// Canonical kernel-visible event. `do_arch_execute` returns one of these
/// for every ring-3 trap — the event loop matches on shape, not raw numbers.
///
/// Variants split by origin:
/// - **Monitor-produced** (`SoftInt`, `Hlt`, `In`/`Out`/`Ins`/`Outs`, `Fault`)
///   come from decoding a sensitive-instruction #GP. These are the only
///   variants that flow through `encode`.
/// - **Direct-IDT** (`Irq`, `PageFault`, `Exception`) come from raw `int_num`
///   / `err_code` / CR2 and are written into the arch boundary without
///   going through `encode`.
///
/// `decode` is the single inverse and handles both origins. The interpreter
/// backend produces these variants directly (no #GP encode round-trip), but
/// shares the exact same enum so the kernel event loop is backend-blind.
#[derive(Copy, Clone, Debug)]
pub enum KernelEvent {
    /// Hardware IRQ was ACK'd + queued inline by arch; the event loop just
    /// needs to know a scheduling point happened.
    Irq,
    /// Page fault at `addr` (CR2).
    PageFault { addr: u32 },
    /// CPU-raised fault from ring 3 — e.g. #DE (0), #UD (6), #NP (11), #SS (12),
    /// #AC (17). Never includes #BP/#OF (vectors 3/4) since those are only
    /// raised by the user `INT3`/`INTO` instructions, nor #PF (handled above).
    Exception(u8),
    /// User-executed `INT n` — either monitor-decoded from a #GP'd `INT n` or
    /// delivered directly through a DPL=3 IDT gate (vectors 3, 4, 0x30..=0xFF,
    /// plus VM86 `INT3`/`0xCC` which bypasses VME). Note that `INT 0x80` lands
    /// here too — it's not the same thing as the `SYSCALL` instruction, which
    /// has its own `Syscall` event.
    SoftInt(u8),
    /// User executed the `SYSCALL` instruction (64-bit only). Distinct from
    /// `SoftInt(0x80)`: the IDT gate path and the SYSCALL fast-path land at
    /// different arch entries (`int_vector` vs `syscall_entry_64`); arch tags
    /// the SYSCALL one with int_num=256 so this stays unambiguous.
    Syscall,
    /// HLT from user code — scheduler yields.
    Hlt,
    /// Port `IN` (AL/AX/EAX ← port). Kernel emulates, writes back into rax.
    In { port: u16, size: IoSize },
    /// Port `OUT` (port ← AL/AX/EAX).
    Out { port: u16, size: IoSize },
    /// String `INS` (ES:DI ← port, advance DI by size). One element per event;
    /// on `rep` the monitor re-faults per iteration (see `monitor`), so the
    /// kernel does a single element and decrements the count. `addr32` selects
    /// (E)CX / (E)DI width for the count and index register.
    Ins { size: IoSize, rep: bool, addr32: bool },
    /// String `OUTS` (port ← DS:SI, advance SI by size). One element per event;
    /// same `rep`/`addr32` semantics as `Ins`.
    Outs { size: IoSize, rep: bool, addr32: bool },
    /// Non-sensitive #GP or unknown opcode — reflect as fault.
    Fault,
}

impl KernelEvent {
    // Private wire format for `encode`/`decode`. Tags are an arbitrary
    // internal numbering — they have no relationship to any CPU vector,
    // IRQ number, or opcode. The arch boundary sees them only as opaque
    // `(event, extra)` u32 pairs.
    const IRQ:        u32 = 1;
    const PAGE_FAULT: u32 = 2;
    const EXCEPTION:  u32 = 3;
    const SOFT_INT:   u32 = 4;
    const HLT:        u32 = 5;
    const IN:         u32 = 6;
    const OUT:        u32 = 7;
    const INS:        u32 = 8;
    const OUTS:       u32 = 9;
    const FAULT:      u32 = 10;
    const SYSCALL:    u32 = 11;

    /// Encode into the `(event, extra)` u32 pair that flows across the
    /// arch→kernel boundary as `(eax, edx)`. Total over all variants.
    /// Exact inverse of `decode`.
    #[inline]
    pub fn encode(self) -> (u32, u32) {
        match self {
            KernelEvent::Irq                  => (Self::IRQ, 0),
            KernelEvent::PageFault { addr }   => (Self::PAGE_FAULT, addr),
            KernelEvent::Exception(n)         => (Self::EXCEPTION, n as u32),
            KernelEvent::SoftInt(n)           => (Self::SOFT_INT, n as u32),
            KernelEvent::Syscall              => (Self::SYSCALL, 0),
            KernelEvent::Hlt                  => (Self::HLT, 0),
            KernelEvent::In  { port, size }   => (Self::IN,  (port as u32) | ((size as u32) << 16)),
            KernelEvent::Out { port, size }   => (Self::OUT, (port as u32) | ((size as u32) << 16)),
            KernelEvent::Ins  { size, rep, addr32 } => (Self::INS,  (size as u32) | ((rep as u32) << 8) | ((addr32 as u32) << 9)),
            KernelEvent::Outs { size, rep, addr32 } => (Self::OUTS, (size as u32) | ((rep as u32) << 8) | ((addr32 as u32) << 9)),
            KernelEvent::Fault                => (Self::FAULT, 0),
        }
    }

    /// Decode the `(event, extra)` pair produced by `encode`.
    pub fn decode(event: u32, extra: u32) -> Self {
        match event {
            Self::IRQ        => KernelEvent::Irq,
            Self::PAGE_FAULT => KernelEvent::PageFault { addr: extra },
            Self::EXCEPTION  => KernelEvent::Exception(extra as u8),
            Self::SOFT_INT   => KernelEvent::SoftInt(extra as u8),
            Self::SYSCALL    => KernelEvent::Syscall,
            Self::HLT        => KernelEvent::Hlt,
            Self::IN         => KernelEvent::In  { port: extra as u16, size: IoSize::from_u32(extra >> 16) },
            Self::OUT        => KernelEvent::Out { port: extra as u16, size: IoSize::from_u32(extra >> 16) },
            Self::INS        => KernelEvent::Ins  { size: IoSize::from_u32(extra), rep: extra & (1 << 8) != 0, addr32: extra & (1 << 9) != 0 },
            Self::OUTS       => KernelEvent::Outs { size: IoSize::from_u32(extra), rep: extra & (1 << 8) != 0, addr32: extra & (1 << 9) != 0 },
            Self::FAULT      => KernelEvent::Fault,
            _ => panic!("KernelEvent::decode: unknown tag {:#x}", event),
        }
    }
}

// =============================================================================
// IRQ event
// =============================================================================

/// Typed IRQ event. Each hardware IRQ captures its data and pushes one of these.
#[derive(Clone, Copy)]
pub enum Irq {
    Tick,
    Key(u8), // raw PS/2 scancode (press and release)
    /// One PS/2 mouse motion/button packet decoded into deltas + button mask.
    /// `dx` / `dy` are signed motion since the previous packet (PS/2 reports
    /// +Y as up; we flip so `+dy` means screen-down). `buttons`: bit 0 left,
    /// bit 1 right, bit 2 middle. Consumer is responsible for accumulating
    /// position and clamping to a screen range.
    Mouse { dx: i16, dy: i16, buttons: u8 },
    /// Any other unmasked hardware IRQ line, forwarded raw. Arch stays
    /// policy-free — the kernel decides if it's a device it owns and when
    /// the line can be rearmed after the guest-visible device ack.
    Hw(u8),
}
