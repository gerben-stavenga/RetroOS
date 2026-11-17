# RetroOS arch layer review

First written 2026-11-12 against `master` at `30ab2be8`. Updated 2026-11-15
against `8632920a`, after the eight commits that reworked the arch interface
(`1f5ea10e` through `8632920a`).

Companion documents: `ARCH_DESIGN_REVIEW.md` (the shape of the layer) and
`KERNEL_REVIEW.md` (the kernel above it).

## Scope and confidence

Everything here comes from reading the code. Nothing was built or run, so each
finding is a claim to verify.

| Part | Depth |
| --- | --- |
| `arch-abi`: `arch.rs`, `page_entry.rs`, `mapping.rs`, `page_supply.rs`, `monitor.rs`, `lib.rs` | Read in full |
| `arch-abi`: `cmdline.rs`, `net.rs`, `serial.rs` | Not read |
| `arch-metal`: `traps.rs`, `paging2.rs`, `irq.rs`, `descriptors.rs`, `entry.asm`, `smp.rs`, `memory.rs`, `mapping.rs`, `high_paging.rs`, `backend.rs`, `vcpu.rs`, `lib.rs` | Read in full at `30ab2be8`; changed parts re-read at `8632920a` |
| `arch-metal`: `x86.rs`, `acpi.rs`, `boot_mem.rs`, `exec_profile.rs`, `mem.rs` | Spot checks only |
| `arch-interp` | Trait implementation, guest-memory path, paging and tests; CPU engines, devices and KVM shim not reviewed |

## Status at `8632920a`

| # | Finding | Status |
| --- | --- | --- |
| 1 | Guest memory access is an unchecked raw dereference | **Open** |
| 2 | `arch_prctl` with a non-canonical base panics at ring 0 | **Open** |
| 3 | `set_tls_entry` writes `IA32_FS_BASE` unconditionally | **Open** |
| 4 | `toggle_mode` re-enables interrupts inside the trap handler | **Open** |
| 5 | Interrupt vector range and the LAPIC spurious vector | **Partly fixed**: PCI INTx routing removed; spurious vector still open |
| 6 | The IDT is shared by all cores but swapped per planar slice | **Open, low**: the planar shortcut itself is by design |
| 7 | Root tables must sit below 4 GiB, nothing enforces it | **Open** |
| 8 | Wild kernel-mode faults are satisfied with a zero page | **Partly fixed**: kernel-space addresses now fail; user-range addresses still demand-zero |
| 9 | Ring 1 has no memory isolation; arch calls trust raw ranges | **Mostly fixed** for mappings (`UserPage`); the isolation point is a design choice |
| 10 | Kernel code runs at ring 0 through arch callbacks | **Changed**: refill redirect and `DEVICE_POLL` removed; a new interrupt-time callback (N1) |
| 11 | No handling for NMI, double fault or machine check | **Open** |
| 12 | `entries()` hands out aliased `&'static mut` | **Open** |
| 13 | The I/O permission policy is installed in `TSS32` only | **Open** |
| 14 | The `Arch` trait is wide and carries two memory models | **Fixed** |
| 15 | The kernel heap never returns memory | **Unchanged**; release path is now dead code |

New at `8632920a`: N1 (interrupt-time callback into the kernel), N2 (one
global paging lock on every fault), N3 (remaining raw-bit mapping flags).

## Priority order

1. Finding 1: the unchecked guest-memory primitive. It is the root cause of the
   Linux read-only-pointer panic and of kernel-range writes from any
   personality, and it is now the most important item left.
2. Findings 2, 3 and 4: each is a one-line change.
3. Finding 5 (spurious vector) and finding 13 (`TSS64` I/O bitmap).
4. N1: decide whether the interrupt sink is an arch-owned queue or a
   documented interrupt-safe contract.
5. Finding 7 before the SMP work runs on machines with RAM above 4 GiB.

## Open findings

### 1. Guest memory access is an unchecked raw dereference

`arch-metal/src/vcpu.rs:103-150`: `read`, `write`, `copy_to`, `copy_from`,
`copy_cstr`, `zero` and `copy_within` cast the address to a pointer and access
it at supervisor privilege, with no range check and no failure result. This is
unchanged by the rework. The `GuestBytes` documentation now says the caller
must supply enough fault backing, but it still offers no way to fail.

Consequences:

- Safe code can pass a kernel address and write the kernel, the recursive page
  tables or arch state. The DOS personality and the instruction monitor build
  addresses from guest segment bases and guest SP/IP
  (`arch-abi/src/monitor.rs:143-170`, `287`), and the monitor runs at ring 0.
- A kernel write to a page the guest made read-only still reaches
  `panic_with_regs("Unhandled page fault in kernel")` (`traps.rs:824`).
- The hosted backend cannot expose this class of bug, since the kernel is not
  in the guest address space there.

High-address copies already have the right contract: `high_copy` returns
`false` for `EFAULT`. The new `UserPage` type and `read_mappings` give the
kernel what it needs to validate, but nothing routes the low-address
accessors through them.

Fix direction: make the low-address primitive fallible and range-checked in
arch, with a fault fixup so a failed access returns an error instead of
panicking.

### 2. `arch_prctl(ARCH_SET_FS/GS)` with a non-canonical value panics the machine

- `kernel/src/kernel/linux/mod.rs:3692-3693` stores the user value in
  `regs.fs` / `regs.gs` unvalidated.
- `arch-metal/src/entry.asm` writes those values to `IA32_FS_BASE` and
  `IA32_GS_BASE` with `wrmsr` on every exit to a 64-bit process.
- `wrmsr` of a non-canonical address raises `#GP` at ring 0, which
  `handle_ring0` turns into a panic.

Validate canonicality in the syscall (Linux returns `EPERM`), and consider
sanitising in arch as well, since arch is the one executing `wrmsr`.

### 3. `set_tls_entry` writes `IA32_FS_BASE` unconditionally

`traps.rs:322` executes `wrmsr(0xC000_0100, base)` for every
`set_thread_area`. That MSR exists only on CPUs with long mode; elsewhere it
raises `#GP` at ring 0. Guard it with `cpu_supports_long_mode()`. If 32-bit
Linux binaries run on the 86Box Pentium targets without hitting this, the
reading is wrong somewhere and worth understanding.

### 4. `toggle_mode` re-enables interrupts inside the trap handler

`descriptors.rs:751` still ends `toggle_mode` with `x86::sti()`. It is called
from `toggle_mode_if_needed` inside `isr_handler` (`traps.rs:355`), so the rest
of the handler and the assembly exit run at ring 0 with IF set. An alarm that
fires in that window is consumed by `handle_irq` and the exit continues into
the guest. It only exists on a VM86/64-bit switch, so it would show as a rare
missed wakeup in mixed workloads. Drop the `sti`; the IRET restores IF.

### 5. The LAPIC spurious vector is handled as a real interrupt

The spurious vector is `0x2F` (`irq.rs:204`), in the device IRQ range. In APIC
mode `handle_irq` (`irq.rs:954`) treats vector `0x2F` as line 15: it masks I/O
APIC pin 15, sends an EOI, and posts `Irq::Hw(15)`. A spurious interrupt must
not be EOI'd, and pin 15 now stays masked until something unmasks it. Use a
vector outside the device range (conventionally `0xFF`) and return without an
EOI.

The I/O APIC address is still hard-coded (`irq.rs:588`) and the MADT is not
consulted for interrupt source overrides. With PCI INTx routing removed, this
now affects only ISA lines.

Resolved: PCI INTx lines 16 and above can no longer reach soft-interrupt
vectors, because `route_device_irq` was removed. Drivers use MSI or poll.

### 6. The IDT is shared by all cores but swapped per planar slice

The planar fast path (`kernel/src/kernel/dos/planar.rs:73-83`) is an
intentional shortcut: planar and port faults are too frequent for a ring-1
round trip. The remaining concern is narrower. `IDT32`/`IDT64` are single
statics (`descriptors.rs:410`), and `replace_interrupt_handlers`
(`descriptors.rs:425`) writes the offset halves separately. It is safe only
because workers are stopped before a DOS thread runs. Either make the IDT
per-core, assert the precondition, or adopt the constant-IDT design discussed
separately (vectors 13 and 14 branch in `entry.asm` when the planar context is
armed).

### 7. Root tables must sit below 4 GiB, and nothing enforces it

CR3 is loaded from 32-bit code everywhere, and each AP's root table, PML4 and
hardware PDPT live in its TLS block, which `kernel/src/arch/smp.rs:192`
allocates with `alloc_zeroed` from the ordinary heap. Today the AP blocks are
allocated early, so they get low frames, but that is an accident of ordering.
Allocate those blocks with an explicit below-4-GiB constraint.

### 8. User-range addresses touched by the kernel are demand-zeroed

Fixed half: kernel-space faults now resolve only when the page is already
resident on another core's root (`traps.rs:885-887`); anything else returns
failure and the kernel panics at the faulting instruction.

Open half: a not-present user-range address touched from ring 1 still gets
the zero page (`traps.rs:901`, `910`). A bad pointer passed to the kernel never
becomes an error. Finding 1's fallible primitive is the place to stop this.

### 11. No handling for NMI, double fault or machine check

All IDT gates still use the same stack (`ist: 0`, `descriptors.rs:185,198`).
There is no task gate or IST for `#DF`, so an arch-stack overflow cannot be
reported, and NMI and `#MC` reach the generic handlers. `syscall_entry_64` has
the usual window between `swapgs` and the stack switch.

### 12. `entries()` hands out aliased `&'static mut`

`paging2.rs:835` still creates a new `&'static mut [E; 1 << 20]` over the
recursive mapping on each call, and callers nest them. A raw-pointer accessor
with explicit volatile reads and writes would match what the hardware walker
requires.

### 13. The I/O permission policy is installed in `TSS32` only

`install_io_policy` (`descriptors.rs:286`) writes `TSS32.iopb`; `TSS64` keeps
its deny-all bitmap. A 32-bit protected-mode client running while the CPU is in
long mode sees every port trap regardless of policy. This is per-mode state
kept in step by hand (see `ARCH_DESIGN_REVIEW.md` section B).

### 15. The kernel heap never returns memory

The heap is now backed explicitly before use (`kernel/src/arch/boot.rs:25-67`,
through `arch::map_heap_page`), which is what allowed the refill redirect to be
removed. Pages are still never released. `paging2::release_heap_pages`
(`paging2.rs:1097`), its `RELEASE_HEAP` arch call (`traps.rs:280`) and the
wrapper in `calls.rs:94` have no caller.

## New findings

### N1. The interrupt top half calls into the kernel

`irq.rs:35-37` stores a kernel function in `INPUT_SINK` and calls it from
`handle_irq` at ring 0 with interrupts disabled. The kernel installs
`irq_dispatch::post` (`kernel/src/arch/boot.rs:513`).

The queue it writes (`kernel/src/kernel/irq_dispatch.rs`) is well built:
bounded, lock-free, allocation-free, and it drops input when full rather than
waiting. But it is kernel code running in interrupt context, which the earlier
design deliberately avoided, and nothing in the type or documentation of
`init_interrupts` states what a sink may do.

Two ways out:

- Keep the arch-owned queue, as before, and let the kernel drain it.
- Keep the sink, but state the contract in arch ("called at ring 0 with
  interrupts off; must not lock, allocate or block") and keep the
  implementation next to that contract.

The i8042 setup and PS/2 decoding that feed the sink are still in arch.

### N2. One global spinlock serialises all paging on every core

`PagingGuard` (`paging2.rs:523-551`) replaced the eager table privatisation
with a single lock around every transition involving shared tables. It is
taken on every page fault (`traps.rs:839`) and every mapping operation in both
the low and high halves.

This is correct and much simpler than what it replaced. The cost is
contention: parallel Linux workloads fault heavily (fork, exec, copy-on-write),
and every fault on every core now takes the same ring-0 spinlock with
interrupts off, including across 4 KiB copies. Worth measuring once the
parallel build workload runs, before deciding whether finer-grained locking is
needed.

### N3. Raw-bit mapping flags are still exported

`MAP_MMIO`, `MAP_PHYS_CACHE_DISABLE` and `MAP_PHYS_FOREIGN`
(`arch-abi/src/lib.rs`) are now labelled "legacy physical-window" flags, but
they are still used in eight files across the kernel and both backends. They
are the last place where callers compose x86 PTE bits; `PageEntry` and
`Attributes` cover the same ground with checking.

## Fixed

- **Finding 14, the wide trait.** `Arch` is split into `Arch` (execution and
  lifecycle), `X86`, `Memory` and `Diagnostics`, about half the previous
  surface. DOS and VGA operations, allocation, raw page-table operations and
  exposed internals have left the boundary (see `ARCH_DESIGN_REVIEW.md`
  section D).
- **Typed mappings.** `PageEntry` with `Owned`/`Borrowed` backing replaces raw
  PTE bits, `UserPage` can only name user space, and mapping operations report
  `NeedPages` with the completed prefix. The encoding is tested in
  `arch-abi/src/page_entry.rs`.
- **The refill redirect** (`refill_ip`, `defer_fault`, the naked
  `frame_refill_entry`) is gone. A kernel fault with an empty reserve now
  panics.
- **`DEVICE_POLL`** is gone.
- **Hot-call batching.** The alarm deadline is passed as `execute(max_time)`.
- **The two physical-memory models** are unified: hosted uses the same
  `PageSupply` and typed mappings, with tests in `arch-interp/tests/mmu.rs`
  covering exhaustion, batching and concurrent forks.
- **MMIO pages** (LAPIC, HPET, I/O APIC) are mapped through
  `map_kernel_page` (`irq.rs:252`) instead of a user-bit mapping.
- **Duplicate arch-call number:** `MAP_VGA_TEXT_APERTURE` is gone, so
  `HASH_PHYS_PAGE` (`traps.rs:121`) no longer collides.

## Smaller points still open

- **Guest memory in diagnostics:** `traps.rs:191,780` build `&[u8]` slices
  over guest addresses at ring 0, against the rule `GuestBytes` sets out.
- **High-address paths** still flush the whole TLB per operation
  (`high_paging.rs:175,197`), though less often than before.
- **TSC:** workers require the TSC clock and assume it is synchronised across
  cores; nothing checks.
- **Descriptor reads:** `read_descriptor` (`descriptors.rs:673`) ignores the
  LDT limit by design.
- **Stale comments:** `monitor.rs:276,323` refer to a `step_virtual_if` that no
  longer exists; `vcpu.rs:9,102` describe a single-core system.

## What holds up

- PAE page-table entries are published atomically with `lock cmpxchg8b`, and
  the hardware PDPT is sanitised separately from the software root.
- Frame refcount transitions are atomic, and copy-on-write is now additionally
  serialised by `PagingGuard`.
- `idle` uses `sti; hlt` so a wakeup cannot be lost between check and halt.
- The per-CPU fault reserve has a stated and asserted bound, and mapping
  operations now take their pages as explicit input and return what they did
  not use.
- The physical aperture serialises remaps and tracks per-CPU staleness.
- espfix, the `m16:32` far-jump form, the RSP high-half fix and the
  calibration fallbacks are carefully done and well explained.
- Boot-time hardware probing is bounded everywhere it waits.
