# retroos-arch-interp — the `unicorn` arch backend (seed)

RetroOS's `arch` is a swappable boundary. There are two backends:

- **metal** — the current bare-metal implementation (`kernel/src/arch/`): runs
  the guest on the real CPU, `no_std`, built with the Bazel freestanding
  toolchain, boots on hardware/QEMU.
- **unicorn** — this: runs the guest in a software x86 core (Unicorn = QEMU's
  TCG extracted), `std`, built with cargo. The kernel runs natively in the host
  process; guest apps run interpreted (the gVisor / User-Mode-Linux shape).

They are selected by **build environment**, not a flag inside one binary —
`no_std`+Bazel vs `std`+cargo are incompatible targets. The shared contract is
the arch *public interface* the kernel was refactored onto this round:

| arch interface (kernel-facing) | metal backend | unicorn backend |
|---|---|---|
| `do_arch_execute() -> KernelEvent` | IRET to ring 3, trap back | `emu_start` in instruction-counted slices |
| `arch::mem()` read/write/slice | deref the active page tables | `uc.mem_read`/`mem_write` over guest RAM |
| software `INT n` → Syscall/SoftInt | IDT vector → ring-1 handler | `add_intr_hook` |
| `IN`/`OUT` → Port event | I/O-bitmap trap | `add_insn_out`/`in_hook` |
| page fault → demand-page / COW | `#PF` handler | `add_mem_hook(MEM_UNMAPPED)` → map + retry |
| timer/HW IRQ | real PIC/PIT trap | slice boundary (instruction-counted ⇒ deterministic) |
| `arch::calls::*` (switch_to, fork, map…) | `int 0x80` stubs | direct functions over software page tables |

`src/main.rs` is a self-contained proof that all of the above maps cleanly:
it builds a tiny 32-bit guest and drives it through every event kind. Run it:

```
cargo run
```

It vendors and builds Unicorn's C core (needs `cmake` + a C compiler).

## Status

This is the **seed**, not the backend. It demonstrates the event/memory model.
To grow it into a real backend:

1. Present the kernel's arch interface as a library here (`Vcpu`, `GuestMem` /
   `mem()`, the `calls`, `KernelEvent`) with the same signatures the kernel
   imports, implemented over Unicorn.
2. Make the kernel buildable as a **hosted** binary (std target) that links this
   crate as its `arch` instead of `kernel/src/arch/`.
3. First guest target: the **32-bit flat PM Linux personality** — it skips x86
   protection/segmentation entirely (base-0 segments, `INT 0x80` syscalls), so
   it's the cheapest end-to-end proof: boot the kernel as a host process and run
   a 32-bit ELF fully interpreted, same kernel logic, no real CPU.

The expensive part that remains is breadth of x86 semantics — but that's
Unicorn's problem, not ours; the kernel side is unchanged.
