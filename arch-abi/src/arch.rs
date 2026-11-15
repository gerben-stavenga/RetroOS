//! The combined architecture interface and saved CPU context.
//!
//! Arch owns execution and lifecycle. X86, Memory and Diagnostics
//! group its supporting capabilities.

use crate::{Regs, KernelEvent, ExecutionProfile, ExecutionProfileStage, FramebufferMapPolicy};
use crate::page_entry::PageEntry;
use crate::mapping::{MappingError, MappingFailure, UserPage, validate_batch};

/// Execution and lifecycle of one backend/core, with supporting capabilities
/// grouped into independently usable traits.
pub trait Arch: Sized + X86 + Memory + Diagnostics + 'static {
    /// Run the active space with `regs` until an interruption (IRQ, syscall,
    /// exception, or monitored instruction), and return that event with the
    /// post-run registers. The time limit bounds this call only; zero returns
    /// `Irq` without executing instructions. IRQ data belongs to device drivers.
    fn execute(&mut self, regs: &mut Regs, io: &crate::IoPolicy, max_time: core::time::Duration) -> KernelEvent;

    /// Halt this core until an interruption or max_time elapses. Zero returns
    /// immediately. Device data remains with its owner; this returns `Irq`.
    fn idle(&mut self, max_time: core::time::Duration) -> KernelEvent;

    /// Interrupt one processor to end its current CPU loan.
    fn interrupt_processor(&mut self, _processor: u32) {}

    /// Monotonic time in nanoseconds.
    fn now(&self) -> u64;

    /// Power off / leave the host.
    fn shutdown(&mut self) -> !;

    /// Disable interrupts and halt forever (panic / shutdown failure).
    fn halt_forever(&mut self) -> !;
}

/// x86 registers, port I/O, descriptor tables and ISA interrupt control.
pub trait X86 {
    // Port I/O

    fn inb(&mut self, port: u16) -> u8;

    fn inw(&mut self, port: u16) -> u16;

    fn inl(&mut self, port: u16) -> u32;

    fn outb(&mut self, port: u16, val: u8);

    fn outw(&mut self, port: u16, val: u16);

    fn outl(&mut self, port: u16, val: u32);

    // Native interrupt-controller operations

    /// Unmask a physical ISA IRQ line left masked after interrupt delivery.
    /// Physical EOI has already been sent; this does not send another EOI.
    fn isa_unmask_irq(&mut self, line: u8);

    /// Configure and enable an ISA IRQ line (edge-triggered, active-high).
    fn isa_enable_irq(&mut self, line: u8) {
        let _ = line;
    }

    // Segments and descriptor tables

    /// Load the LDT (write base+limit into the GDT slot and `LLDT`).
    fn load_ldt(&mut self, ldt: &[u64]);

    /// Notify the backend that the active thread's LDT descriptors changed
    /// (a DPMI descriptor edit). Metal reads the live hardware LDT, so the
    /// default is a no-op; the interpreter uses it to re-materialize its
    /// software copy of the descriptor tables before the next guest entry.
    fn on_ldt_changed(&mut self) {}

    /// Set a per-thread TLS GDT entry. Returns the GDT index or -1 on error.
    fn set_tls_entry(&mut self, index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32;

    /// Linear base of selector `sel` from the current descriptor tables.
    fn seg_base(sel: u16) -> u32;

    /// Whether selector `sel` is a 32-bit (D=1) segment.
    fn seg_is_32(sel: u16) -> bool;

    /// Does the VM86 redirection bitmap trap this vector (true), or should the
    /// monitor reflect it through the real-mode IVT itself (false)?
    fn int_intercepted(vector: u8) -> bool;

    // FPU/SSE state

    /// Backend FPU/SSE save area (FXSAVE blob on metal; host snapshot on interp).
    type Fx: Copy + Default + 'static;

    /// Swap the live FPU/SSE image with `fx`, independently of the address space.
    fn switch_fx(&mut self, fx: &mut Self::Fx);

    /// Standard x86 FXSAVE image for a Linux signal frame, when supported.
    fn fx_state_bytes(_fx: &Self::Fx) -> Option<&[u8; 512]> { None }

    fn fx_state_bytes_mut(_fx: &mut Self::Fx) -> Option<&mut [u8; 512]> { None }

    /// A clean FPU/SSE save area for a fresh thread.
    fn clean_fx_template(&self) -> Self::Fx;

    /// The guest's current x87 top-of-stack register, ST(0), as the raw 80-bit
    /// extended value.
    ///
    /// The MMIO instruction decoder needs it: an x87 store (`fstp [mmio]`) to a
    /// trapped aperture faults like any other write, and the value being stored
    /// lives nowhere in the general registers. Reading it must not disturb the
    /// stack — `fpu_pop` is the separate half, for the popping forms.
    fn fpu_st0(&self) -> [u8; 10];

    /// Pop the guest's x87 stack, discarding ST(0).
    fn fpu_pop(&mut self);

    // CPU capabilities and native registers

    /// Whether this CPU/backend supports executing 64-bit user code.
    fn user_64_supported(&self) -> bool;

    /// Arm hardware write-watchpoints at up to two guest-linear addresses
    /// (`None`/missing entry disables): a `#DB` fires when the guest writes one,
    /// for catching memory corruption. Real on metal (programs the debug
    /// registers); a no-op on backends with no debug-register feature.
    fn set_debug_watch(&mut self, addrs: Option<(u32, u32)>);

    /// Replace both native IDT entries, returning the previous handler pair.
    /// Backends without a native IDT leave this operation unused.
    ///
    /// # Safety
    /// Each entry must obey its mode's interrupt-frame and return conventions.
    /// Restore both entries before their code or associated state expires.
    unsafe fn replace_interrupt_handlers(&mut self, _vector: u8, handlers: crate::InterruptHandlers) -> crate::InterruptHandlers { handlers }
}

/// Active address spaces, mappings and physical memory.
pub trait Memory {
    /// Backend page-table root type stored in `Vcpu::space` — an OWNED address
    /// space, so it is **not** `Copy`: a parked `Vcpu` moves rather than
    /// duplicating the space. It is an OPAQUE owned handle — **not** a memory
    /// accessor. Guest memory is reached only through the *active* space, so
    /// `GuestBytes` is a supertrait of `Arch` (the active-space accessor), never
    /// implemented on `PageTable` or a parked `Vcpu`. `Default` supplies the
    /// empty placeholder a switch leaves behind in a now-running thread's slot.
    type PageTable: Default;

    /// Hardware leaf format, including whether execute-disable is available.
    fn page_format(&self) -> crate::page_entry::X86PteFormat;

    /// Read does not allocate data frames. The result is a snapshot, not an
    /// owning reference; its backing must stay valid until replacement finishes.
    fn read_mapping(&mut self, page: UserPage) -> Result<PageEntry, MappingError>;

    /// Return a uniform run starting at `page`, bounded by `maximum` pages.
    /// This exposes sparse mapping state without expanding its page tables.
    fn read_mapping_run(&mut self, page: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
        if maximum == 0 { return Err(MappingError::InvalidAddress); }
        page.offset(maximum - 1)?;
        Ok((self.read_mapping(page)?, 1))
    }

    /// Repeat an entry across a range. Each Owned occurrence retains a reference.
    /// # Safety
    /// Same backing lifetime requirements as replace_mapping.
    unsafe fn fill_mappings(&mut self, start: UserPage, count: usize, entry: PageEntry) -> Result<(), MappingFailure> {
        validate_batch(start, count)?;
        for completed in 0..count {
            unsafe { self.replace_mapping(start.offset(completed).unwrap(), entry) }
                .map_err(|error| MappingFailure { completed, error })?;
        }
        Ok(())
    }

    /// Retain Owned backing before releasing the displaced mapping's reference.
    /// Borrowed mappings never retain or release backing.
    ///
    /// # Safety
    /// Supplied frames must be valid; Borrowed backing must outlive every alias.
    /// Writable aliases must obey the caller's synchronization/ownership rules.
    /// Serialize mapping changes with other CPUs using the same address space.
    unsafe fn replace_mapping(&mut self, page: UserPage, entry: PageEntry) -> Result<(), MappingError>;

    fn read_mappings(&mut self, start: UserPage, entries: &mut [PageEntry]) -> Result<(), MappingFailure> {
        validate_batch(start, entries.len())?;
        for (completed, entry) in entries.iter_mut().enumerate() {
            *entry = self.read_mapping(start.offset(completed).unwrap())
                .map_err(|error| MappingFailure { completed, error })?;
        }
        Ok(())
    }

    /// # Safety
    /// Same requirements as replace_mapping, for every supplied entry.
    unsafe fn replace_mappings(&mut self, start: UserPage, entries: &[PageEntry]) -> Result<(), MappingFailure> {
        validate_batch(start, entries.len())?;
        for (completed, &entry) in entries.iter().enumerate() {
            unsafe { self.replace_mapping(start.offset(completed).unwrap(), entry) }
                .map_err(|error| MappingFailure { completed, error })?;
        }
        Ok(())
    }

    /// Copy a high user buffer through a backend-owned window. False means EFAULT.
    fn high_copy(&mut self, _address: u64, _buffer: &mut [u8], _to_user: bool) -> bool { false }

    /// Install `incoming` as the active address space and return the displaced
    /// one. Registers and FPU state are unchanged.
    fn activate(&mut self, incoming: Self::PageTable) -> Self::PageTable;

    /// COW-fork the current address space into `child` (fills the child root).
    fn user_fork(&mut self, child: &mut Self::PageTable);

    /// Detach shared page-table metadata before concurrent process execution.
    /// Consumes explicit backing inputs; -11 requests another input batch.
    fn private_page_tables(&mut self) -> i32 { 0 }

    fn refresh_kernel_mappings(&mut self) {}

    /// Tear down a dead thread's address space entirely. `free_user_pages`
    /// (called at exit, while the space is still active) returns its page
    /// FRAMES; this releases the space OBJECT itself — on the interpreter
    /// the host VA reservation + per-page bookkeeping, on metal a no-op
    /// (the saved-entries buffer lives in the Thread and drops with it).
    /// Called at reap, after execution has switched away.
    fn destroy_space(&mut self, root: &mut Self::PageTable);

    /// Free user pages in the current address space (the CLEAN call).
    fn free_user_pages(&mut self);

    fn physical_frame_io(&self) -> Option<crate::PhysicalFrameIo> { None }

    fn page_supply(&self) -> Option<*mut crate::page_supply::PageSupply> { None }

    fn set_page_input(&mut self, _input: *mut crate::page_supply::PageInput) -> *mut crate::page_supply::PageInput { core::ptr::null_mut() }

    /// Translate a page-aligned kernel address to its backing physical frame.
    /// # Safety
    /// The address must refer to live mapped RAM.
    unsafe fn physical_frame(&mut self, base: core::ptr::NonNull<u8>) -> crate::page_entry::PhysicalFrame;

    /// Install a privileged driver window; user mappings use replace_mapping.
    fn map_kernel_physical(&mut self, vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64);

    /// Cache/copy policy for a physical linear framebuffer owned by a display
    /// controller. The conservative default is strong-UC.
    fn framebuffer_map_policy(&self) -> FramebufferMapPolicy {
        FramebufferMapPolicy {
            flags: crate::MAP_PHYS_CACHE_DISABLE | crate::MAP_PHYS_FOREIGN,
            slow: true,
            wide: false,
        }
    }


}

/// Optional execution profiling and address-space diagnostics.
pub trait Diagnostics {
    /// Diagnostic snapshot of the active page tables. A nonzero expected hash
    /// requests a comparison and mismatch report. Returns zero if unsupported.
    fn check_address_space(&mut self, _expected: u64) -> u64 { 0 }

    /// Deterministic profiling for the kernel/arch/guest execution boundary.
    fn execution_profile_set(&mut self, _enabled: bool) {}

    /// Clear execution counters without changing whether recording is enabled.
    fn execution_profile_reset(&mut self) {}

    fn execution_profile_begin(&mut self) {}

    fn execution_profile_time(&mut self, _stage: ExecutionProfileStage) {}

    fn execution_profile(&self) -> ExecutionProfile { ExecutionProfile::default() }
}

// =============================================================================
// GuestBytes — access to guest memory
// =============================================================================

/// Byte access to the active address space, implemented by the backend.
/// Parked page-table handles and Vcpu values do not expose memory access.
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
/// low guest memory within 4 GiB). High long-mode mappings use
/// `Memory::read_mapping` and `Memory::high_copy` without narrowing their addresses.
///
/// Soundness note: `read::<T>` reconstructs a `T` from copied bytes, so `T` must
/// be valid for *all* bit patterns (an integer or a `#[repr(C, packed)]` POD
/// struct of integers). Reading a `bool`/`char`/fieldless-enum out of guest
/// memory would be UB; the kernel never does.
///
/// These are raw transfers over the active space. The caller must supply
/// sufficient fault backing for all pages touched. Kernel bulk transfers split
/// at page boundaries and replenish their PageSupply between calls.
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
// Vcpu — a thread's PARKED context (registers + its owned, inactive space)
// =============================================================================

/// A thread's saved execution context: its registers plus the OWNED address
/// space they run in. This is the *parked* form — what a non-running thread
/// stores. It is deliberately NOT the live/active context: the running thread's
/// registers live in the event loop (a plain `&mut Regs`) and its address space
/// is moved *into* the backend as the single active space ([`crate::Memory::activate`]).
///
/// `space` is `A::PageTable` — an OWNED, move-only address-space handle. It is
/// **not** the guest-memory accessor: guest memory is reached only through the
/// *active* space, which the backend owns, so [`GuestBytes`] is implemented on
/// `Arch` (the active-space accessor), never on a parked `Vcpu`. That is the
/// principle — you can only touch memory that is active, which on metal is a
/// hardware fact (a `deref` needs the live page tables), so the type system
/// must not offer a way to read an inactive space.
pub struct Vcpu<A: Arch> {
    /// Architectural register state (program counter, mode, GPRs).
    pub regs: Regs,
    /// The thread's OWNED address space, dormant while parked. Activated by
    /// moving it into the backend ([`crate::Memory::activate`]); the displaced space
    /// comes back and is re-parked here.
    pub space: A::PageTable,
}

// `Vcpu` is NOT `Copy`/`Clone`: `space` is an owned, move-only resource, so a
// `Vcpu` names exactly one address space and aliasing is a type error. `Regs`
// is plain data and is snapshotted on its own; the space moves.

impl<A: Arch> core::ops::Deref for Vcpu<A> {
    type Target = Regs;
    fn deref(&self) -> &Regs { &self.regs }
}
impl<A: Arch> core::ops::DerefMut for Vcpu<A> {
    fn deref_mut(&mut self) -> &mut Regs { &mut self.regs }
}

impl<A: Arch> Vcpu<A> {
    /// Bundle registers with an owned address space (re-park after a switch).
    pub const fn new(regs: Regs, space: A::PageTable) -> Self {
        Vcpu { regs, space }
    }
    /// A cleared context with a default (empty) address space.
    pub fn empty() -> Self {
        Vcpu { regs: Regs::empty(), space: A::PageTable::default() }
    }
}
