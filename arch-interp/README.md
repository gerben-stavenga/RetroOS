# retroos-arch-interp — the `unicorn` arch backend

RetroOS's `arch` is a swappable boundary. There are two backends:

- **metal** (`arch-metal/`) — the bare-metal implementation: runs the guest on
  the real CPU, `no_std`, built with the Bazel freestanding toolchain, boots on
  hardware/QEMU.
- **interp** (this crate) — runs the guest in a software x86 core (Unicorn =
  QEMU's TCG extracted), `std`. The kernel runs natively in the host process;
  guest apps run interpreted (the gVisor / User-Mode-Linux shape).

Both implement the same kernel-facing interface defined in `arch-abi/`. They are
selected by **build environment**, not a flag inside one binary — `no_std`+Bazel
vs `std` are incompatible targets. The contract maps as:

| arch interface (kernel-facing) | metal backend | interp backend |
|---|---|---|
| `execute() -> KernelEvent` | IRET to ring 3, trap back | `emu_start` in instruction-counted slices |
| `arch::mem()` read/write/slice | deref the active page tables | `uc.mem_read`/`mem_write` over guest RAM |
| software `INT n` → Syscall/SoftInt | IDT vector → ring-1 handler | `add_intr_hook` |
| `IN`/`OUT` → Port event | I/O-bitmap trap | `add_insn_out`/`in_hook` |
| page fault → demand-page / COW | `#PF` handler | `add_mem_hook(MEM_UNMAPPED)` → map + retry |
| timer/HW IRQ | real PIC/PIT/APIC trap | slice boundary (instruction-counted ⇒ deterministic) |
| `arch::calls::*` (switch_to, fork, map…) | `int 0x80` stubs | direct functions over software page tables |

## Status

This is a **full backend**, not a demonstrator. The kernel builds as a hosted
binary that links this crate as its `arch`, and runs the same kernel logic over
interpreted guests:

- VM86/DOS, protected mode with descriptors (DPMI), and the device bus all work;
  it runs real DOS games and Borland C++ self-builds.
- The interp backend owns CPU, MMU/paging, descriptors, and a device bus
  (`cpu.rs`, `mmu.rs`, `paging.rs`, `desc.rs`, `devices.rs`, `machine.rs`); VGA
  emulation is the kernel's single shared model, not duplicated here.
- `play/` (`retroos-play`) wraps this backend in a windowed host emulator —
  real-time audio, a presentation window fed by the emulated VGA, and host
  keyboard/mouse input. `kernel/src/main.rs` is the headless hosted entry point
  (DOS command + screenshot/WAV workflow).

Run via the unified launcher (see the repo root `run.sh`):

```
./run.sh hosted --cmd GAMES/SKYROADS        # windowed
./run.sh hosted --cmd GAMES/X --screenshot out.ppm   # headless
```

The crate vendors and builds a patched Unicorn C core (needs `cmake` + a C
compiler); both the Bazel and cargo paths must link the *same* patched fork.

Design parity is the rule: differences between metal and interp live **below**
the arch boundary (emulated devices, a deadline-budget virtual timer), never as
kernel-side `cfg`/hooks. The expensive remaining work is breadth of x86
semantics — but that's Unicorn's problem, not the kernel's.
