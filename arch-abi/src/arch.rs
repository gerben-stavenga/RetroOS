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

/// Read/write access to guest memory, implemented for three receivers:
///
/// * the backend's page-table handle (`A::PageTable`) — the primitive; the
///   backend supplies the one real impl (host-pointer deref on metal, guest-RAM
///   index on the interp), confining the `unsafe` there;
/// * the running [`Vcpu`] — the kernel already holds `&mut Vcpu` in the DOS /
///   Linux paths and reaches its address space through it (`regs.read(addr)`);
///   the blanket impl below forwards to `self.space`;
/// * the [`Arch`] backend itself — the active address space, for code that
///   touches guest memory without a `Vcpu` in hand (`arch.read(addr)`).
///
/// Slice-returning methods borrow `self`, so a view can't outlive a mutation of
/// the space — the lifetime the old `&'static` handle could not express.
///
/// `addr` is a guest-linear address as `usize` (the 32-bit kernel addresses all
/// guest memory within 4 GiB).
pub trait GuestBytes {
    /// Read a `T` at `addr` (unaligned-safe).
    fn read<T: Copy>(&self, addr: usize) -> T;
    /// Write a `T` at `addr` (unaligned-safe).
    fn write<T: Copy>(&mut self, addr: usize, val: T);
    /// Borrow `len` bytes at `addr`.
    fn slice(&self, addr: usize, len: usize) -> &[u8];
    /// Mutably borrow `len` bytes at `addr`.
    fn slice_mut(&mut self, addr: usize, len: usize) -> &mut [u8];
    /// Borrow a NUL-terminated C string (excluding the NUL), scanning ≤ `max`.
    fn c_str(&self, addr: usize, max: usize) -> &[u8];
    /// Zero `len` bytes at `addr`.
    fn zero(&mut self, addr: usize, len: usize);
    /// Copy `src` into guest memory at `addr`.
    fn write_bytes(&mut self, addr: usize, src: &[u8]);
}

/// In-place borrow of a `T` living in guest memory, for the DOS struct overlays
/// (PSP, low-memory BIOS area) that mutate fields directly. Separate from
/// [`GuestBytes`] because it is generic over the placed type rather than `Self`,
/// and only the active-space (`Arch`) receiver needs it.
pub trait GuestOverlay {
    /// Borrow the `T` at `addr` in guest memory in place.
    fn at<T>(&mut self, addr: usize) -> &mut T;
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
/// every `GuestBytes` op to `self.space` (the backend supplies the real impl on
/// its page-table type). This is what keeps `regs.read(addr)` working across the
/// DOS/Linux personalities without the kernel knowing the backend.
impl<P: GuestBytes> GuestBytes for Vcpu<P> {
    fn read<T: Copy>(&self, addr: usize) -> T { self.space.read(addr) }
    fn write<T: Copy>(&mut self, addr: usize, val: T) { self.space.write(addr, val) }
    fn slice(&self, addr: usize, len: usize) -> &[u8] { self.space.slice(addr, len) }
    fn slice_mut(&mut self, addr: usize, len: usize) -> &mut [u8] { self.space.slice_mut(addr, len) }
    fn c_str(&self, addr: usize, max: usize) -> &[u8] { self.space.c_str(addr, max) }
    fn zero(&mut self, addr: usize, len: usize) { self.space.zero(addr, len) }
    fn write_bytes(&mut self, addr: usize, src: &[u8]) { self.space.write_bytes(addr, src) }
}

// =============================================================================
// The backend contract
// =============================================================================

/// The full kernel→arch boundary. One value implements this per CPU; the kernel
/// threads `&mut impl Arch` through `startup` and the event loop.
///
/// `Arch: GuestBytes + GuestOverlay` so `arch.read(addr)` reaches the active
/// address space. Because `PageTable: GuestBytes`, a thread's `Vcpu` is
/// `GuestBytes` too (via the blanket impl), so the kernel can reach a thread's
/// memory through the `Vcpu` it already holds.
///
/// Method grouping mirrors the old free-function surface (`kernel/src/arch/`):
/// port I/O, execution/scheduling, the timer, IRQ lines, the page-table/fork/
/// LDT/DMA "arch calls", FPU state, and a few x86 segment helpers the DOS
/// personality needs.
pub trait Arch: GuestBytes + GuestOverlay {
    /// Backend page-table root type stored in `Vcpu::space`. It is the canonical
    /// `GuestBytes` implementor — the active address space's memory primitive.
    type PageTable: GuestBytes + Copy + Default;
    /// Backend FPU/SSE save area (FXSAVE blob on metal; host snapshot on interp).
    type Fx: Copy;

    // ── Port I/O ───────────────────────────────────────────────────────────

    fn inb(&mut self, port: u16) -> u8;
    fn inw(&mut self, port: u16) -> u16;
    fn outb(&mut self, port: u16, val: u8);
    fn outw(&mut self, port: u16, val: u16);

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
