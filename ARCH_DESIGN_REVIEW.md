# RetroOS arch layer: design review

First written 2026-11-12 against `30ab2be8`. Updated 2026-11-15 against
`8632920a`, after the rework of the arch interface. Companion to
`ARCH_REVIEW.md`, which lists concrete defects with a status table. This
document is about the shape of the layer: what the boundary is, what it costs,
and where it has drifted from its stated intent.

Basis: `arch-abi` and `arch-metal` read in full (apart from `x86.rs`,
`acpi.rs`, `boot_mem.rs`, `cmdline.rs`, `net.rs`, `serial.rs`), with changed
parts re-read at `8632920a`; `arch-interp` read at the level of its trait
implementation, guest-memory path, paging module and tests. Its CPU engines,
devices and the KVM shim were not reviewed. Nothing was run.

## The design in one paragraph

A ring-0 supervisor (`arch-metal`) owns the CPU: traps, page tables,
descriptors, interrupt controllers and the clock. The kernel runs at ring 1 as
an event loop: it calls `execute`, the guest runs, and control comes back as
one `KernelEvent`. Everything the kernel asks of the machine goes through the
`Arch` trait and its supporting traits `X86`, `Memory` and `Diagnostics`,
which a second backend (`arch-interp`, with TCG and KVM engines) implements
over a hosted process.

The purpose is to run DOS programs natively, in virtual-8086 and protected
mode on the real CPU, on a 64-bit machine that also runs 64-bit programs. The
kernel is 32-bit so that it keeps running while ring 0 moves the CPU between
PAE mode (where VM86 exists) and long mode (where 64-bit code runs).

## Progress since the first review

The rework addressed most of the boundary problems this document raised:

| Section | Status at `8632920a` |
| --- | --- |
| D. Trait speaks raw page tables | **Resolved**: typed `PageEntry` and `UserPage` operations |
| E. Arch is not policy-free | **Partly**: DOS/VGA mapping operations gone; fault policy, i8042 and DPMI state remain |
| F. Callbacks into the kernel | **Partly**: refill redirect, `DEVICE_POLL`, `FrameAccess` gone; a new interrupt sink |
| G. `&mut A` safety claim | **Resolved**: claim dropped, raw-pointer parameters removed |
| H. Backend differences as `Option` probes | **Resolved**: one page-supply model in both backends |
| I. Paging implemented twice | **Open**, though hosted is now tested against the same contract |
| J. Hosted does not model arch | **Open** |
| K. `arch-abi` is not pure data | **Open** |
| L. Documentation behind the code | **Partly** |

What remains is mostly the guest-memory contract (C), the interrupt sink (F),
and per-mode state (B).

## What works well

- **Interrupts arrive as events.** Top halves at ring 0 acknowledge and queue;
  the kernel drains the queue from its loop and never runs a handler of its
  own. The new interrupt sink (F) narrows this property but does not undo it,
  as long as the sink stays a lock-free queue.
- **Execution as a function call.** `execute(&mut Regs, io, max_time) ->
  KernelEvent` gives both backends the same contract and makes the
  personalities testable on a hosted engine. Folding the alarm deadline into
  `execute` removed a separate trap per entry.
- **One flat page-table model.** `entries[i]` with `parent_index` covers
  2-, 3- and 4-level paging with the same generic code, including
  demand-paged, copy-on-write page-table pages.
- **Pages as data across the boundary.** `PageInput` travels by value into
  each mapping operation and the unused part comes back; exhaustion is an
  error with a completed prefix, not a callback.
- **Semantic mappings.** `PageEntry` states what a mapping means (absent,
  intercepted, no-access, read-only, writable, copy-on-write) and who owns the
  frame, and the x86 encoding is a tested, checked conversion.
- **Per-CPU state through TLS.** The root table, descriptors, trap state and
  fault reserve are thread-local, which made the SMP bring-up tractable.
- **A shared sensitive-instruction monitor.** One decoder for both backends
  is the canonicalisation principle applied where it matters most.

## Central trade-offs

These are the choices everything else follows from. A and C are forks with a
defensible side each. B is the constraint the system is built around.

### A. The ring-1 kernel

Ring 1 gives instruction-level confinement (the kernel cannot `cli`, `hlt` or
write control registers) and keeps the kernel out of interrupt context. It
gives no memory confinement: x86 paging has one supervisor level and the
ring-1 segments are flat, so the kernel can write every arch structure.

The cost is a trap round trip for every arch call and a register frame
conversion on every guest entry and exit. The rework reduced the number of
traps on the hot path by passing the alarm deadline to `execute`;
`activate`, mapping operations and high-address copies still pay one each.

Recommendation, unchanged: keep ring 1 as a discipline rather than a memory
boundary, say so in the docs, and keep batching the hot calls. The property
worth protecting is "no kernel code runs in interrupt context".

### B. A 32-bit kernel that survives leaving long mode (the founding constraint)

The goal is to run DOS programs natively on a 64-bit machine that also runs
64-bit programs. Virtual-8086 mode does not exist in long mode, so the CPU has
to leave long mode to run real-mode DOS code on the hardware, and return to it
for 64-bit code. A 64-bit kernel cannot execute while the CPU is out of long
mode. A 32-bit kernel can: its code runs unchanged in protected mode and in
compatibility mode, so only ring 0 needs to know which mode the CPU is in.
Short of a hypervisor, this is the only arrangement that meets the goal, and
it is a good one. It is not a fork.

What follows from it are inherent costs, to be made cheap and safe, not
avoided:

- The kernel cannot address user memory above 4 GiB, so 64-bit processes need
  a windowed access path (`high_paging`).
- Physical memory is reached through an aperture, and the page cache lives in
  frames with no kernel mapping.
- CR3, the IDT base and every root table must sit below 4 GiB.
- The mode toggle runs with paging off through an identity-mapped trampoline,
  and there are two IDTs and two TSSs.
- Kernel virtual space is 1 GiB regardless of RAM.

Design consequences worth acting on:

- **The two-mode state deserves a single owner.** Several defects in
  `ARCH_REVIEW.md` come from state that exists once per mode and is kept in
  step by hand: interrupts re-enabled after the toggle (finding 4), the I/O
  policy installed in only one of the two TSSs (13), root tables that must be
  below 4 GiB with nothing enforcing it (7), and an MSR write that assumes
  long mode exists (3). All four are still open. One module should own "what
  must be true in each mode", with the per-mode state (IDT, TSS, I/O bitmap,
  CR3 form) switched as a unit, and a test that alternates a VM86 guest and a
  64-bit guest.
- **The toggle is rare, so its cost is not a concern; its correctness is.**
  It happens only when a core switches between a VM86 guest and a 64-bit
  guest (`toggle_mode_if_needed`, `traps.rs:355`). Kernel excursions, 32-bit
  Linux and protected-mode DPMI stay in whatever mode the CPU is in. The flip
  side of rare is under-exercised: the path only runs in mixed VM86 and 64-bit
  workloads, which is why it needs the dedicated test above.
- **The windowed paths are permanent, so their cost matters.** High-address
  operations still flush the whole TLB (`high_paging.rs:175,197`). A larger
  per-CPU window with `invlpg` would cut the cost of the 64-bit side without
  changing the model.
- **The below-4-GiB requirement should be a property of the allocator
  interface**, not of boot ordering: a "low frame" request for anything CR3
  or a descriptor register will point at.

### C. No record of mappings other than the page tables

There is still no VMA layer, and a not-present user entry still means
"demand-zero". That is why a kernel copy to a bad user address cannot return
`EFAULT`, and why wild pointers materialise pages.

The rework added the right vocabulary: `PageEntry::Absent` and
`PageEntry::NoAccess` are distinct, and `Intercepted` marks device apertures.
What is missing is using it at fault time. If not-present user entries that
were never mapped faulted instead of demand-zeroing, and anonymous
reservations were recorded explicitly the way `high_paging` already marks
reserved subtrees, the fault handler would stop deciding policy and the
fallible user copy in `ARCH_REVIEW.md` finding 1 would have a clean
definition of "bad address".

The eager table privatisation this section used to mention is gone; shared
tables are now resolved under a lock (see the global paging lock below).

## Where the boundary stands

### D. Typed mapping operations (resolved)

The raw page-table operations (`copy_page_entries`, `swap_page_entries`,
`unmap_range`, `set_page_flags`, `map_phys_range`,
`redirect_physical_aliases`, `map_fresh_range`) are gone from the trait. In
their place `Memory` offers `read_mappings`, `read_mapping_run`,
`replace_mappings` and `fill_mappings` over `UserPage` ranges, taking
`PageEntry` values and supplied pages. The kernel builds DOS and VGA layouts
from these, which is where that policy belongs. Low and high addresses share
the same interface.

One leftover: the raw-bit `MAP_MMIO`, `MAP_PHYS_CACHE_DISABLE` and
`MAP_PHYS_FOREIGN` flags are still exported and used in eight files
(`ARCH_REVIEW.md` N3). `PageEntry` and `Attributes` cover the same ground.

### E. Arch is not yet policy-free

Gone: the DOS and VGA mapping operations, `framebuffer_map_policy` and the
QEMU detection behind it, and `execute_firmware`.

Still decided in arch:

- **What a legal page fault is.** Demand-zero for any not-present user entry,
  a 64 KiB null guard for user mode only, NX off for VM86 and LDT code
  (`traps.rs:838-920`). See C.
- **How keyboard and mouse input is acquired.** i8042 initialisation and PS/2
  packet decoding remain in `irq.rs`, and the `Irq::Key` / `Irq::Mouse`
  variants remain in the ABI.
- **DOS interrupt virtualisation.** `VifWindow`, `EmulatedStep`, `DebugTrap`,
  the virtual-IOPL stash and the TF shadow bits are DPMI policy in
  `KernelEvent`, `Regs` and `isr_handler`. Some of this has to run at ring 0
  for speed, as the planar shortcut does; the honest form is to treat it as a
  declared fast path, like planar, rather than as part of the general
  contract.

### F. Callbacks into the kernel

Gone: the refill redirect (`refill_ip` and the naked `frame_refill_entry`),
`DEVICE_POLL`, and the `FrameAccess` and `PhysicalFrameIo` function tables.
The heap is now backed before use, so the asynchronous case that forced the
redirect no longer exists.

New: `INPUT_SINK` (`irq.rs:35`). The interrupt top half now calls a
kernel-supplied function at ring 0 with interrupts off, instead of writing an
arch-owned queue. The kernel's implementation is a good lock-free queue, so
this is not a correctness problem today. It is a contract problem: nothing
says what the sink may do, and the obvious next change ("just wake the
worker from the sink") would put real kernel logic in interrupt context.
Either restore the arch-owned queue, or document the sink as "interrupt
context; no locks, no allocation, no blocking" at its definition.

Still present by design: the planar fast path installs kernel entry points in
the IDT. That is an intentional shortcut, discussed in `ARCH_REVIEW.md`
finding 6.

### G. `&mut A` (resolved)

The trait header no longer claims that threading `&mut A` proves the absence
of aliasing, and `activate` and the page-input interface no longer take raw
pointers in safe signatures. The handle is a dependency-injection device and
is now described as one.

### H. One physical-memory model (resolved)

Both backends now take pages from the kernel through `supply_pages` and
`PageInput`, and the `page_supply()`, `frame_access()` and
`physical_frame_io()` probes are gone, along with the metal methods that
panicked. Hosted now exercises the same allocator contract as metal.

### I. Two independent implementations of paging

`arch-metal/src/paging2.rs` (2,115 lines) and `arch-interp/src/paging.rs`
(1,192 lines) still each implement demand paging, fork, copy-on-write and
teardown. The gap is narrower than before: both now consume `PageInput`,
speak `PageEntry`, and the hosted tests (`arch-interp/tests/mmu.rs`) cover
exhaustion, batching, ownership and concurrent forks against the shared
contract. But the metal implementation is still tested only through QEMU.

Making the metal algorithms generic over a table accessor (recursive mapping
on metal, frame pointer on hosted, an array in a unit test) would let the
same tests run against the code that ships on hardware.

### J. The hosted backend does not model what the system exists to do

Hosted remains the oracle for the personalities, not for arch:

- **One paging mode.** Hosted is 2-level, 32-bit paging with a derived 4-level
  twin for KVM's 64-bit slices. PAE, the compatibility-mode root and the
  PAE/long-mode toggle do not exist there.
- **No high address space.** `Interp` does not implement `high_copy`, so the
  trait default (`false`) applies.
- **One CPU.** `interrupt_processor` is the default no-op, and only
  `kernel/src/arch/smp.rs` provisions workers.
- **Guest-memory access never fails**, on either backend.

So the mode switch, dual-mode paging and SMP can only be tested on metal under
QEMU. That is acceptable if it is acknowledged. The concurrent-fork tests in
`arch-interp/tests/mmu.rs` are a welcome step: they exercise the paging lock
logic that metal's `PagingGuard` mirrors.

A related design point from the rework: all paging on metal is now serialised
by one global spinlock (`PagingGuard`, `ARCH_REVIEW.md` N2). That is the right
first step, since it replaced a far more fragile protocol, but it sets the
scaling limit for the parallel Linux work.

### K. `arch-abi` is not pure data

Unchanged. It holds the 600-line monitor, the command-line parser,
`BootConfig` with DOS drive mapping, audio policy and serial-port ownership
(and, since the rework, the user TSC calibration), a network module, and an
`ExecutionProfile` whose fields name metal's ring transitions. The boot
configuration in particular is kernel policy, not machine contract.

### L. Documentation

Improved: the `arch-interp` crate root no longer describes itself as an
unimplemented milestone, and the `arch-abi` and `arch.rs` headers now
describe the trait split accurately and no longer contradict themselves on
`GuestBytes`.

Still stale:

- `arch-metal/README.md` says workers "allocate no heap storage" and that the
  design "does not provide concurrent kernel syscall execution"; workers now
  run syscall handlers. Its paragraph on kernel mappings ("not a general
  concurrent kernel-mapping or TLB-shootdown protocol") should be rewritten to
  describe `PagingGuard` and what workers are now allowed to do.
- `arch-metal/src/vcpu.rs:9,102` describe a single-core system.
- `arch-abi/src/monitor.rs:276,323` refer to `step_virtual_if`, which no
  longer exists.

## Suggested order

1. Give guest memory a fallible, range-checked contract, and stop
   demand-zeroing user addresses the kernel touches (C, and `ARCH_REVIEW.md`
   findings 1 and 8).
2. Fix the per-mode state as a unit and add the alternating VM86 / 64-bit test
   (B, findings 3, 4, 7 and 13).
3. Settle the interrupt sink contract (F).
4. Retire the raw-bit mapping flags in favour of `PageEntry` (D).
5. Share one paging implementation between the backends so the host tests
   cover the metal code (I).
6. Move the i8042 driver and the boot configuration out of the arch crates
   (E, K), and update the README (L).
