//! `trait Arch` — the backend-agnostic *behavioural* contract.
//!
//! `lib.rs` holds the pure-data types that cross the boundary (`Regs`,
//! `KernelEvent`, `Irq`, page constants). This module holds the **operations**:
//! the trait every backend implements (`kernel/src/arch/` for bare metal,
//! `arch-interp/` for the software CPU) and the kernel programs against.
//!
//! The design intent (why a trait, and why `&mut self`):
//!
//! * The kernel depends *solely* on this crate. It is generic over `A: Arch`
//!   and receives its backend by dependency injection — `startup(arch: &mut A)`
//!   — called either by the metal boot crate or by the hosted `main`. There is
//!   no `cfg`-selected `extern crate … as arch` and no compile-time backend
//!   baked into the kernel.
//!
//! * Every operation takes `&self`/`&mut self`. The backend's mutable state
//!   (guest RAM, the live register file, the virtual PIC/PIT, page tables) is
//!   *owned* by the `Arch` value and reached only through a borrow. Threading a
//!   single `&mut A` through the kernel is what lets the borrow checker enforce
//!   that the kernel never aliases that state — it replaces the global `static
//!   mut`s (and their `unsafe`) the free-function backends rely on today. When
//!   the kernel goes multi-core, each core drives a distinct `&mut Arch`, and
//!   Rust keeps the cores honest for free.
//!
//! Representation that genuinely differs between backends stays backend-owned
//! via associated types: `PageTable` (a real page-table root vs a software
//! address space) and `Fx` (an FXSAVE area vs a host FPU snapshot). The
//! register/space bundle the kernel stores per thread is `Vcpu<Self::PageTable>`
//! — generic over the page-table type but otherwise shared, since both backends
//! are x86 and share the `Regs` ABI.

use crate::{Irq, KernelEvent, Regs};

// =============================================================================
// GuestBytes — access to guest memory
// =============================================================================

/// Access to guest memory, implemented for two receivers:
///
/// * the backend's page-table handle (`A::PageTable`) — the primitive; the
///   backend supplies the one real impl (host-pointer deref on metal, guest-RAM
///   index on the interp), confining the `unsafe` there;
/// * the running [`Vcpu`] — the kernel already holds `&mut Vcpu` in the DOS /
///   Linux paths and reaches its address space through it (`regs.read(addr)`);
///   the blanket impl below forwards to `self.space`.
///
/// **No method returns a reference into guest memory.** Guest RAM is external,
/// volatile memory: a DOS guest places live structures at address 0 (the IVT)
/// and at arbitrary, unaligned paragraph addresses, and the guest/BIOS/devices
/// may mutate them under us. A Rust `&T`/`&[u8]` would assert non-null,
/// alignment, and "no mutation for the borrow's lifetime" against memory that
/// promises none of those — instant UB the moment the reference is *formed*,
/// before any read. So every accessor copies bytes between guest memory and a
/// caller-owned buffer; the only references that ever exist point at locals.
///
/// All accesses are **volatile** (never elided, reordered, or coalesced — the
/// guest/devices can observe and change the bytes) and **unaligned-safe** (done
/// byte-at-a-time, so any `addr`/alignment is fine).
///
/// `addr` is a guest-linear address as `usize` (the 32-bit kernel addresses all
/// guest memory within 4 GiB).
///
/// Soundness note: `read::<T>` reconstructs a `T` from copied bytes, so `T` must
/// be valid for *all* bit patterns (an integer or a `#[repr(C, packed)]` POD
/// struct of integers). Reading a `bool`/`char`/fieldless-enum out of guest
/// memory would be UB; the kernel never does.
pub trait GuestBytes {
    /// Read a `T` at `addr` (volatile, unaligned, bytewise into a local).
    fn read<T: Copy>(&self, addr: usize) -> T;
    /// Write a `T` at `addr` (volatile, unaligned, bytewise from a local).
    fn write<T: Copy>(&mut self, addr: usize, val: T);
    /// Copy `dst.len()` bytes from guest memory at `addr` into `dst`.
    fn copy_from(&self, addr: usize, dst: &mut [u8]);
    /// Copy `src` into guest memory at `addr`.
    fn copy_to(&mut self, addr: usize, src: &[u8]);
    /// Copy bytes from guest memory at `addr` into `dst`, stopping before the
    /// first NUL or at `dst.len()`. Returns the number of bytes copied (the
    /// C-string length, capped at `dst.len()`); the NUL is not copied.
    fn copy_cstr(&self, addr: usize, dst: &mut [u8]) -> usize;
    /// Zero `len` bytes at `addr`.
    fn zero(&mut self, addr: usize, len: usize);
    /// Copy `len` bytes within guest memory (`src` → `dst`), overlap-safe.
    fn copy_within(&mut self, src: usize, dst: usize, len: usize);
}

// =============================================================================
// Vcpu — one execution context (registers + the address space they run in)
// =============================================================================

/// Register state plus the address-space handle those registers execute in.
///
/// This is the unit the kernel stores per thread and hands back to `Arch` to
/// resume. `space` is the backend's page-table root type (`A::PageTable`):
/// a real per-thread root on metal, a software address space on the interp.
///
/// Derefs to `Regs` so `vcpu.rax` / `vcpu.mode()` keep working and a
/// `&mut Vcpu<P>` coerces where a `&mut Regs` is expected. Guest-memory access
/// is provided by the backend's [`GuestBytes`] impl for `Vcpu<P>` (the
/// forwarders that used to be inherent methods).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vcpu<P> {
    /// Architectural register state, including the program counter
    /// (`regs.frame.rip`) and the mode (32/64/VM86, derived from CS/EFLAGS).
    pub regs: Regs,
    /// Handle to the address space these registers run in. The arch context
    /// switch swaps it into the live root on entry.
    pub space: P,
}

impl<P> core::ops::Deref for Vcpu<P> {
    type Target = Regs;
    fn deref(&self) -> &Regs { &self.regs }
}
impl<P> core::ops::DerefMut for Vcpu<P> {
    fn deref_mut(&mut self) -> &mut Regs { &mut self.regs }
}

impl<P> Vcpu<P> {
    /// Bundle existing registers with an address-space handle.
    pub const fn new(regs: Regs, space: P) -> Self {
        Vcpu { regs, space }
    }
}

impl<P: Default> Vcpu<P> {
    /// A cleared context with a default (empty) address space.
    pub fn empty() -> Self {
        Vcpu { regs: Regs::empty(), space: P::default() }
    }
}

/// A `Vcpu` reaches guest memory through the address space it names — forward
/// every memory op to `self.space` (the backend supplies the real impl on its
/// page-table type). The `Vcpu` is *the* guest-memory handle: registers + the
/// address space they run against, in one object, which the kernel already holds
/// as `regs`/`vcpu` in every handler. So `regs.read(addr)` is the single way the
/// kernel touches guest memory — there is no separate machine-side accessor.
impl<P: GuestBytes> GuestBytes for Vcpu<P> {
    fn read<T: Copy>(&self, addr: usize) -> T { self.space.read(addr) }
    fn write<T: Copy>(&mut self, addr: usize, val: T) { self.space.write(addr, val) }
    fn copy_from(&self, addr: usize, dst: &mut [u8]) { self.space.copy_from(addr, dst) }
    fn copy_to(&mut self, addr: usize, src: &[u8]) { self.space.copy_to(addr, src) }
    fn copy_cstr(&self, addr: usize, dst: &mut [u8]) -> usize { self.space.copy_cstr(addr, dst) }
    fn zero(&mut self, addr: usize, len: usize) { self.space.zero(addr, len) }
    fn copy_within(&mut self, src: usize, dst: usize, len: usize) { self.space.copy_within(src, dst, len) }
}

// =============================================================================
// The backend contract
// =============================================================================

/// The full kernel→arch boundary. One value implements this per CPU; the kernel
/// threads `&mut impl Arch` through `startup` and the event loop.
///
/// `Arch` is deliberately **not** a memory accessor. Guest memory belongs to the
/// address space, which the running thread's `Vcpu` carries (`Vcpu::space`); the
/// kernel reads/writes it through the `Vcpu` it already holds (`regs.read(addr)`).
/// So there is exactly one guest-memory path — the vcpu — and `Arch` is just the
/// rest of the machine: CPU exec, ports, timer, IRQ lines, the page-table/fork/
/// LDT/DMA "arch calls", FPU state, and a few x86 segment helpers.
pub trait Arch {
    /// Backend page-table root type stored in `Vcpu::space`. It is the guest-
    /// memory primitive — `GuestBytes` routes through it, which is what makes
    /// `vcpu.read(addr)` work.
    type PageTable: GuestBytes + Copy + Default;
    /// Backend FPU/SSE save area (FXSAVE blob on metal; host snapshot on interp).
    type Fx: Copy;

    // ── Port I/O ───────────────────────────────────────────────────────────

    fn inb(&mut self, port: u16) -> u8;
    fn inw(&mut self, port: u16) -> u16;
    fn inl(&mut self, port: u16) -> u32;
    fn outb(&mut self, port: u16, val: u8);
    fn outw(&mut self, port: u16, val: u16);
    fn outl(&mut self, port: u16, val: u32);

    /// Let the guest access ports `[port, port+count)` directly — clear them in
    /// the I/O-permission bitmap so they no longer trap to the kernel. The DOS
    /// layer uses this to drop the per-write trap on the OPL ports once it finds
    /// a real card (passthrough). No-op on backends that interpret all I/O.
    fn allow_io_ports(&mut self, port: u16, count: usize);

    /// Reset the I/O-permission bitmap to deny-all. The kernel's io_policy
    /// rebuilds a thread's allowed set (reset + allow_io_ports ranges) on
    /// every swap-in; which ports a personality may touch is kernel policy,
    /// this is only the mechanism. No-op on backends that interpret all I/O.
    fn reset_io_bitmap(&mut self);

    // ── Execution & scheduling ─────────────────────────────────────────────
    //
    // The event loop *owns* the live `Vcpu` (there is no `REGS` global). It hands
    // a `&mut Vcpu` to `execute`, which resumes it and writes the post-run state
    // back into the same `Vcpu` before returning the event. Because the loop owns
    // the vcpu and `arch` is a separate borrow, handlers receive disjoint
    // `(&mut arch, &mut vcpu)`, and a thread's memory rides on the vcpu itself
    // (`Vcpu: GuestBytes`) — so the borrow checker, not a global, keeps them sound.

    /// Resume `vcpu` and return the next kernel-visible event, leaving `vcpu`
    /// holding the post-run register state.
    fn execute(&mut self, vcpu: &mut Vcpu<Self::PageTable>) -> KernelEvent;

    /// Context-switch: swap the live state (`live`) with the saved buffer
    /// (`swap`) and make the now-incoming address space active. On entry `swap`
    /// holds the incoming thread's state and `live` the outgoing thread's; on
    /// return `live` holds the incoming state and `swap` the outgoing (which the
    /// scheduler stores back into the parked thread). `hash_ptr` null ⇒ no
    /// hashing; `fx_ptr` null ⇒ skip FPU swap.
    fn switch_to(
        &mut self,
        live: &mut Vcpu<Self::PageTable>,
        swap: &mut Vcpu<Self::PageTable>,
        hash_ptr: *mut u64,
        fx_ptr: *mut Self::Fx,
    );

    // ── Timer ──────────────────────────────────────────────────────────────

    /// Monotonic tick count (PIT/virtual time).
    fn get_ticks(&self) -> u64;
    /// Consume and return ticks accumulated since the last call.
    fn take_pending_ticks(&mut self) -> u32;
    /// Drain queued hardware-IRQ events, calling `f` for each.
    fn drain(&mut self, f: &mut dyn FnMut(Irq));
    /// Read the CPU timestamp counter.
    fn rdtsc(&self) -> u64;

    // ── IRQ lines ──────────────────────────────────────────────────────────

    /// Assert/deassert the CPU INTR line from the virtual PIC. No-op on metal
    /// (real 8259 drives INTR); the interp re-checks for a pending IRQ at a
    /// basic-block boundary.
    fn set_irq_line(&mut self, asserted: bool);
    /// Re-arm (re-unmask) an IRQ line that `handle_irq` left masked pending a
    /// deferred guest-visible device ack.
    fn rearm_irq(&mut self, line: u8);

    /// Arm hardware write-watchpoints at up to two guest-linear addresses
    /// (`None`/missing entry disables): a `#DB` fires when the guest writes one,
    /// for catching memory corruption. Real on metal (programs the debug
    /// registers); a no-op on backends with no debug-register feature.
    fn set_debug_watch(&mut self, addrs: Option<(u32, u32)>);

    // ── Arch calls: paging / fork / LDT / DMA ──────────────────────────────

    /// COW-fork the current address space into `child` (fills the child root).
    fn user_fork(&mut self, child: &mut Self::PageTable);

    /// Tear down a dead thread's address space entirely. `free_user_pages`
    /// (called at exit, while the space is still active) returns its page
    /// FRAMES; this releases the space OBJECT itself — on the interpreter
    /// the host VA reservation + per-page bookkeeping, on metal a no-op
    /// (the saved-entries buffer lives in the Thread and drops with it).
    /// Called at reap, after execution has switched away.
    fn destroy_space(&mut self, root: &mut Self::PageTable);
    /// Free user pages in the current address space (the CLEAN call).
    fn free_user_pages(&mut self);
    /// Set page permissions for a range (`writable`, `executable`).
    fn set_page_flags(&mut self, start_vpage: usize, count: usize, writable: bool, executable: bool);
    /// Map the first 1 MB user-accessible for VM86.
    fn map_low_mem(&mut self);
    /// Copy `count` page-table entries `src → dst`.
    fn copy_page_entries(&mut self, src_vpage: usize, dst_vpage: usize, count: usize);
    /// Swap `count` page-table entries between two ranges.
    fn swap_page_entries(&mut self, a_vpage: usize, b_vpage: usize, count: usize);
    /// Clear page entries to absent (re-enables demand paging on next access).
    fn unmap_range(&mut self, base_page: usize, count: usize);
    /// Free physical pages and restore identity-mapped read-only entries.
    fn free_range(&mut self, base_page: usize, count: usize);
    /// Replace `count` user pages at `vpage` with fresh anonymous RW frames.
    fn map_fresh_range(&mut self, vpage: usize, count: usize);
    /// Load the LDT (write base+limit into the GDT slot and `LLDT`).
    fn load_ldt(&mut self, ldt: &[u64]);
    /// Map a range of physical pages into user virtual space.
    fn map_phys_range(&mut self, vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64);
    /// Allocate `num_pages` physically contiguous, ISA-DMA-safe pages
    /// (< 16 MB, not crossing a `1 << boundary_log2` boundary). Returns the
    /// starting physical page number, or 0 on failure.
    fn alloc_phys_contig(&mut self, num_pages: usize, boundary_log2: u32) -> u64;
    /// Free a run previously returned by `alloc_phys_contig`.
    fn free_phys_contig(&mut self, start_page: u64, num_pages: usize);
    /// Physical page of DMA channel `ch`'s permanent ISA-DMA buffer (0 = none).
    fn dma_channel_buf(&self, ch: usize) -> u64;
    /// Set a per-thread TLS GDT entry. Returns the GDT index or -1 on error.
    fn set_tls_entry(&mut self, index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32;

    // ── FPU/SSE state ──────────────────────────────────────────────────────

    /// A clean FPU/SSE save area for a fresh thread.
    fn clean_fx_template(&self) -> Self::Fx;

    // ── Diagnostics & power ────────────────────────────────────────────────

    /// Physical free-page count (diagnostic logging).
    fn free_page_count(&self) -> usize;
    /// Power off / leave the host.
    fn shutdown(&mut self) -> !;
    /// Disable interrupts and halt forever (panic / shutdown failure).
    fn halt_forever(&mut self) -> !;

    // ── x86 segment helpers (DOS personality) ──────────────────────────────

    /// Linear base of selector `sel` from the live descriptor tables.
    fn seg_base(&self, sel: u16) -> u32;
    /// Whether selector `sel` is a 32-bit (D=1) segment.
    fn seg_is_32(&self, sel: u16) -> bool;
    /// Software-reflect a VM86 `INT n` into the guest's IVT handler (used when
    /// VME is unavailable, e.g. on the interp). Operates on the register frame;
    /// a `&mut Vcpu` coerces here via `DerefMut`.
    fn sw_reflect_vm86_int(&mut self, regs: &mut Regs, vector: u8);
}
