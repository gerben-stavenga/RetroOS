# RetroOS Design

A single 32-bit kernel binary that runs DOS, 32-bit, and 64-bit programs
on any x86 from a 386 to a modern x86-64 processor.

## Design principle: canonicalize and unify

RetroOS should try to make different execution modes behave the same internally.
The preferred shape is:

- one canonical representation of CPU state
- one canonical event loop in the kernel
- one canonical paging model across x86 paging modes
- one canonical set of core abstractions for processes, files, memory, and events

When hardware forces special cases, the special case should be normalized at the
boundary as early as possible.

This is especially important for the `arch` layer. `arch` is the trust boundary:

- it should stay small
- it should avoid policy
- it should avoid compatibility-specific hacks
- it should expose a minimal, mode-independent interface upward

Compatibility layers can be looser. DOS/Linux/Windows support may need pragmatic
or application-specific behavior while being brought up, but that code should sit
above the `arch` boundary. Ideally those compatibility layers share a common core
library for reusable pieces such as image loading, path handling, handle tables,
argv/environment marshaling, and ABI canonicalization.

## Arch and ring-1 kernel

RetroOS is split into two layers running at different privilege levels:

- **arch**: ring-0 supervisor (~2MB code/data)
- **kernel**: ring-1 OS kernel with event loop

The boundary between them is enforced by the language, not the CPU: the kernel
is `#![forbid(unsafe_code)]` and can only touch the machine through the safe
`arch` API (see *Privilege model*). Ring 1 vs ring 0 buys arch the privileged
instructions and a distinct trap origin, not memory isolation from the kernel.

`arch` is intentionally small. It does not implement OS policy. Its job is
to abstract the real machine into a simpler idealized computer for the
`kernel`.

The `kernel` owns everything that gives the system meaning:

- scheduling policy
- process and thread abstractions
- filesystems
- ELF loading
- DOS/VM86 runtime
- device policy and higher-level drivers
- shell/init/session management

The guiding rule is:

- if it requires privilege or isolation, it belongs in `arch`
- if it is policy, interpretation, or emulation, it belongs in `kernel`
- if it is a hardware-specific oddity, normalize it before it spreads upward
- if it is a compatibility-specific quirk, keep it out of `arch`

## Two arch backends behind one interface

`arch` is a swappable boundary. The kernel is written against a single
kernel-facing interface (`arch-abi`) and links one of two implementations,
selected by build environment rather than a runtime flag:

- **metal** (`arch-metal`): runs the guest on the real CPU. `no_std`, built
  with the Bazel freestanding toolchain, boots on hardware and QEMU. Events
  arrive as real traps; `arch::mem()` dereferences the active page tables.
- **interp** (`arch-interp`): runs the guest in a software x86 core (Unicorn,
  QEMU's TCG extracted). `std`, runs as an ordinary host process — the kernel
  executes natively, guest apps are interpreted (the gVisor / User-Mode-Linux
  shape). Events arrive at instruction-counted slice boundaries; `arch::mem()`
  is `uc.mem_read`/`mem_write` over a host-owned guest RAM buffer.

The two map the same small contract onto very different machinery:

| arch interface (kernel-facing) | metal backend | interp backend |
|---|---|---|
| `execute() -> KernelEvent` | IRET to ring 3, trap back | `emu_start` in instruction-counted slices |
| `arch::mem()` read/write/slice | deref active page tables | `uc.mem_read`/`mem_write` over guest RAM |
| software `INT n` → Syscall/SoftInt | IDT vector → ring-1 handler | intr hook |
| `IN`/`OUT` → Port event | I/O-bitmap trap | in/out insn hook |
| page fault → demand-page / COW | `#PF` handler | unmapped-mem hook → map + retry |
| timer / HW IRQ | real PIC/PIT/APIC | slice boundary (deterministic, instruction-counted) |
| `arch::calls::*` (switch_to, fork, map…) | `int 0x80` stubs | direct fns over software page tables |

The design goal is **parity**: the kernel above the boundary is byte-for-byte
identical across backends. Differences in how a device behaves (a real card vs.
an emulated one, a real PIT vs. a deadline-budget virtual timer) are pushed
*below* the arch boundary, not branched on in the kernel. The interp backend is
a full backend — it runs DOS games, DPMI clients, and Borland C++ self-builds —
not a demonstrator.

`retroos-play` (the `play/` crate) wraps the interp backend in a windowed host
emulator: a real-time audio sink, a presentation window fed by the kernel's
emulated VGA, and host keyboard/mouse input routed into the guest. This is the
DOSBox-shaped path — RetroOS *is* the emulator, with its own kernel underneath
rather than a bespoke DOS layer.

## Privilege model

RetroOS uses three of the four x86 privilege rings:

| Ring | Role | Paging | Privileged insns | Segments |
|------|------|--------|-----------------|----------|
| 0 | arch | supervisor (U/S=0) | yes | flat |
| 1 | kernel | supervisor (U/S=0) | no | flat |
| 3 | user | user (U/S=1) | no | flat |

Paging U/S gives the only *hardware* privilege boundary that matters here:
ring 3 (U/S=1) cannot touch the supervisor pages that hold the kernel, arch,
and page tables. Ring 1 is supervisor for paging purposes, so the CPU does
**not** hardware-isolate the kernel from arch — and that is deliberate. The
arch ↔ kernel boundary is enforced by the *language*, not by segments or rings.

### Language-enforced arch isolation

The kernel crate is compiled `#![forbid(unsafe_code)]`. Safe Rust cannot
fabricate a pointer, index out of bounds, or write the page tables — so the
kernel is, by construction, incapable of corrupting arch or violating memory
safety, regardless of any logic bug. It can only affect the machine through the
safe `arch` API (`arch::mem()`, `arch::calls::*`, the `KernelEvent` stream).

This replaces an earlier plan to wrap the ring-1 code/data segments
(base `0xC0C0_0000`, limit excluding `0xC000_0000..0xC0BF_FFFF`) so a stray
kernel write to the arch/page-table region would `#GP`. That scheme was
dropped: a segment limit only nets stray writes to *one* region, while
`forbid(unsafe_code)` makes the entire kernel unable to violate memory safety
against *any* region — a strictly stronger and compile-time-checkable property
— and it removes the per-pointer `user_ptr` base-translation tax that the
non-zero segment base would have imposed on every guest pointer.

The guarantee is **conditional on arch's `unsafe` being sound**. Safe code is
only as safe as the `unsafe` beneath it, so the trusted computing base is
exactly arch's `unsafe` surface:

- the page-table writes and CR3 loads (`arch::calls::map`, `fork`, …)
- the user/guest-memory accessors (`arch::mem()` — on metal a page-table
  deref, on interp a bounds-checked index into host-owned guest RAM)
- the trap entry that enqueues IRQs and packages `KernelEvent`s
- on interp, the FFI to the Unicorn C core

That set is small and enumerable, and it is where the engineering discipline
now lives: **keep arch's `unsafe` tiny and audited.** Both backends present the
*same* safe API to the *same* kernel source, so the kernel never needs `unsafe`
no matter which one it links — arch-interp already demonstrates this end to end.

*Open work to make the attribute compile:* a few pieces that legitimately need
`unsafe` still sit inside the kernel crate and must move below the arch line (or
behind a safe capability) first — the metal device drivers that do raw MMIO /
port I/O (`nvme`, `ac97`, `hda`, `pci`, `xhci`) and the runtime plumbing
(`heap`, `stacktrace`). The placement rule that falls out: **code that needs
`unsafe` hardware access belongs below arch; the kernel stays safe.**

## Interrupt dispatch

All interrupts and exceptions enter ring 0 via the IDT. `arch` inspects
the saved CS RPL to determine the source:

- **Ring 3 → ring 0**: user event. Package as `Event` (syscall, fault,
  IRQ), IRET to ring-1 kernel for handling.
- **Ring 1 → ring 0**: kernel arch call. Handle the primitive directly
  (`map`, `fork`, `clean_low`, `activate`, `execute`), IRET back to ring 1.

Same IDT entry, same INT vector. The CS RPL in the saved frame
distinguishes the two cases. No call gates needed.

This works because INT/IRET round-trips correctly between any two
privilege levels. Unlike SYSCALL/SYSRET or SYSENTER/SYSEXIT (which
always return to ring 3), INT/IRET returns to whatever ring the caller
was in.

## Event loop

The `kernel` is an event loop:

1. pick a runnable task
2. `activate(task.as)` — INT to arch, sets address space, IRET back
3. `event = execute(&mut task.state)` — INT to arch, IRET to user,
   user runs until interrupt, arch packages event, IRET back to kernel
4. handle the event
5. repeat

`arch` does not own scheduler policy. It only resumes execution and
reports why execution stopped.

Threads are a kernel concept, not an `arch` concept. From the `arch`
point of view, there are only:

- address spaces
- saved CPU states
- events returned from `execute`

## Memory layout

### Virtual address map

```
0x0000_0000 - 0x0000_FFFF  Null guard (unmapped)
0x0001_0000 - 0xBFFF_FFFF  User space (~3 GB)
0xC000_0000 - 0xC0BF_FFFF  Supervisor-only (12 MB, page tables + arch)
0xC0C0_0000 - 0xFFFF_FFFF  Kernel (~1012 MB)
```

### Root page as PD (through recursive mapping)

The root page table (PD for legacy, PDPT for PAE/compat) has a recursive
entry that makes itself appear as the page directory for the high region.
Each entry acts as a PD entry covering 4MB (legacy) or 2MB (PAE/compat):

**PAE/Compat layout** (PDPT entries as PD entries, 2MB each):

| Entry | Address       | U/S | Purpose                          |
|-------|---------------|-----|----------------------------------|
| [0]   | `0xC000_0000` | 0   | PT entries for user 0-1GB        |
| [1]   | `0xC020_0000` | 0   | PT entries for user 1-2GB        |
| [2]   | `0xC040_0000` | 0   | PT entries for user 2-3GB        |
| [3]   | `0xC060_0000` | 0   | Recursive (PD entries themselves) |
| [4]   | `0xC080_0000` | 0   | PML4 (compat only)               |
| [5]   | `0xC0A0_0000` | 0   | arch code/data                   |
| [6+]  | `0xC0C0_0000` | 1   | kernel                           |

**Legacy layout** (PD entries, 4MB each):

| Entry | Address       | U/S | Purpose                    |
|-------|---------------|-----|----------------------------|
| [768] | `0xC000_0000` | 0   | Recursive (page tables)    |
| [769] | `0xC040_0000` | 0   | (reserved)                 |
| [770] | `0xC080_0000` | 0   | arch code/data             |
| [771+]| `0xC0C0_0000` | 1   | kernel                     |

The kernel starts at `0xC0C0_0000` in all modes. The U/S split here is what
isolates ring-3 user processes from the supervisor region (kernel + arch +
page tables); it does **not** separate the ring-1 kernel from ring-0 arch, since
ring 1 is itself supervisor. That arch ↔ kernel boundary is enforced by the
language instead (`#![forbid(unsafe_code)]` on the kernel — see *Privilege
model*), not by paging or segments.

## Minimal arch interface

`arch` only needs a very small set of primitives, invoked by the ring-1
kernel via INT:

- **fork() -> as**
  Clone the current address space using shared/refcounted mappings.
- **clean_low(as)**
  Remove all low-region mappings from an address space while preserving the
  high kernel mapping.
- **map(as, ...)**
  Map memory into the low region of an address space.
- **activate(as)**
  Install an address space's low region beneath the high kernel mapping.
  This changes memory visibility but does not execute.
- **execute(state) -> event**
  Run the CPU using the currently active address space until something
  interesting happens, then return updated CPU state and an event.

This is the core idea: every entry into `arch` from ring 3 is reflected
as a return from `execute` to ring 1.

Typical events are:

- syscall
- irq
- page fault
- protection fault
- vm86 trap
- halt
- yield
- exit

`arch` captures these events but does not interpret them beyond what is
required for safety.

The point is not just minimality. It is also canonicalization: different
hardware modes should be translated into the same small kernel-facing model.

## Refcounted address spaces

`arch` refcounts physical pages and page-table structures.

This makes lifecycle operations simple:

- **fork**
  `fork()` creates a child address space sharing pages with the parent.
- **spawn fresh process**
  `fork()` followed by `clean_low()` gives a fresh low address space with the
  high kernel mapping intact.
- **exec**
  `clean_low()` followed by `map(...)` replaces the current process image.
- **exit**
  `clean_low()` drops all user mappings; refcounting frees pages whose count
  reaches zero.

In other words, `arch` is responsible for backing memory safely, while the
`kernel` decides what those address spaces mean.

## VM86 as just another execution mode

VM86 is not a special in-kernel subsystem. It is just another saved CPU mode
handled by `execute()`.

The `kernel` can build a DOS machine by:

- creating or reusing an address space
- `clean_low()` on it
- mapping the first 1 MiB of DOS-visible memory
- loading PSP, IVT, BIOS-visible state, and program image
- calling `execute()` with VM86 state

If 16-bit execution stops for a privileged reason, `execute()` returns a
`vm86 trap` event. The `kernel` then decides what that means:

- DOS interrupt emulation
- BIOS-facing policy
- virtual PIC/PIT/keyboard state
- IRQ reflection by editing guest stack/registers
- DOS `EXEC` and parent/child semantics

This keeps VM86 mechanism in `arch` and DOS policy in the `kernel`.

The same rule should apply to future Linux and Windows compatibility work:
keep the execution primitive and memory primitive generic, keep the ABI and API
translation in compatibility code, and share common helpers wherever possible.

### Mode toggling for VM86

VM86 requires PAE mode (cannot IRET to VM86 from long mode). On x86-64
CPUs, `arch` toggles from compat to PAE before executing a VM86 task, and
toggles back afterward. This toggle only happens on actual mode switches
(not on every timer tick while the same VM86 task is running).

## One binary, all x86 generations

The kernel is compiled once as a 32-bit ELF. At boot, it detects the CPU
via CPUID and configures paging accordingly:

| CPU           | Paging mode | Entry size | Levels | Userspace         |
|---------------|-------------|------------|--------|-------------------|
| 386/486       | Legacy      | 4 bytes    | 2      | DOS, 32-bit       |
| Pentium Pro+  | PAE         | 8 bytes    | 3      | DOS, 32-bit (+NX) |
| x86-64        | Compat      | 8 bytes    | 4      | DOS, 32-bit, 64-bit |

No conditional compilation, no `#[cfg(target_arch)]`. The same code paths
handle all three modes, parameterized only by entries-per-page (1024 vs 512)
and paging depth (2, 3, or 4 levels).

## Recursive paging as a linear array

The central design insight: one entry in the root page table points back to
itself. This makes the entire page table hierarchy appear as a flat array
at a fixed virtual address:

```
entries[i]           — page table entry for virtual page i
parent(i)            = BASE + i / epp
recursive_idx        = fixed point of parent()
root_base            = (recursive_idx - BASE) * epp
```

The recursive index is the fixed point of the parent function. It divides
the array into user entries (below) and kernel entries (at and above).
These formulas are the same for 2-level, 3-level, and 4-level paging.
Only `epp` differs (1024 for 32-bit entries, 512 for 64-bit entries).

There is no page table walk code anywhere in the kernel. The CPU performs
the walk implicitly when `arch` accesses `entries[i]` — the recursive
mapping *is* the walk. Every paging operation reduces to array indexing:

- **Map a page**: `entries[page_idx] = phys | flags`
- **Fork**: iterate user entries, share and COW-protect
- **COW fault**: `entries[fault_page] = new_copy | writable`
- **Free**: walk `parent()` upward, decrement refcounts

Each operation is one function, generic over entry type (Entry32/Entry64),
working identically for all paging depths.

## Constant root page table

The root page table (PD for legacy, PDPT for PAE/compat) is a static page
in the kernel BSS. It never moves. Kernel entries live permanently in this
page and are shared by all processes automatically.

Per-process state is just the user entries, saved and restored at context
switch:

- **Legacy**: 768 PD entries (3 KB)
- **PAE/Compat**: 3 PDPT entries (24 bytes)

Context switch loads the thread's user entries into the constant root and
reloads CR3. The kernel half of the address space never changes.

## Free mode toggling between PAE and compat

The constant root page is both the PAE PDPT and the compat-mode PDPT under
PML4. The same page, same entries, same recursive mapping — the only
difference is what CR3 points to:

```
PAE mode:    CR3 → HW_PDPT → PDPT (constant page, recursive at [3])
Compat mode: CR3 → PML4 → PDPT (same constant page, PML4[0] → PDPT)
```

Toggling between modes is:

1. Disable paging
2. XOR EFER.LME (flip long mode enable)
3. Load new CR3 (PML4 or HW_PDPT)
4. Enable paging

No page table rebuilding. No address space migration. The kernel's virtual
addresses, recursive mapping, and all user mappings are identical before and
after the toggle. The kernel literally cannot tell the difference except by
reading EFER.

This is what makes 64-bit userspace possible from a 32-bit kernel: toggle
to compat mode, IRET to the 64-bit process, and toggle back on interrupt.

## Unified interrupt handling across modes

`arch` handles interrupts from 16-bit (VM86), 32-bit, and 64-bit
userspace through a single Rust handler. The assembly entry point normalizes
the register save area:

- **32-bit entry**: zero-extends every register to 64 bits (`push 0; push eax`)
- **64-bit entry**: saves native 64-bit registers, then far-jumps to a
  32-bit trampoline that calls the same Rust handler

Both produce an identical `Regs` layout. The Rust interrupt handler sees one
type regardless of origin mode. After handling, `exit_kernel` dispatches to
the right return path (IRET for 32-bit/VM86, far jump + IRETQ for 64-bit).

## Typed IRQ event queue

Hardware interrupts push typed events (`enum Irq { Tick, Key(u8) }`) into
a global queue. The queue is drained when returning to the kernel:

- **VM86 threads**: events are reflected through the IVT as real-mode
  interrupts, with per-thread virtual PIC and keyboard
- **Protected mode threads**: keyboard scancodes are converted to ASCII
  and buffered for `sys_read`

This separates "record the event" (IRQ context, minimal work) from
"process the event" (safe context, arbitrary complexity).

## Copy-on-write fork with child-first scheduling

Fork shares the parent's pages read-only and returns to the child first.
The child typically calls exec immediately, which frees its share of the
COW pages. The parent resumes as sole owner — no page copies needed.

If the parent ran first, it would immediately fault on stack writes,
copying pages the child is about to discard.

## VM86 for DOS

DOS .COM programs run in VM86 mode with:

- Per-thread virtual PIC (IMR, ISR, EOI emulation)
- Per-thread virtual keyboard (scancode buffer, port 0x60/0x64 emulation)
- VGA I/O ports allowed via IOPB (direct hardware access)
- VGA BIOS ROM mapped read-only (INT 10h goes through real BIOS code)
- INT 16h/20h/21h intercepted via interrupt redirection bitmap
- PSP stub restores text mode on exit

Protected-mode DOS extends the same model. DPMI (0.9 with 1.0 extensions) is a
kernel personality layered over the VM86/PM execution modes — INT 31h services,
an LDT, PM interrupt reflection, exception handlers, and RM⇔PM transitions —
sufficient to run DJGPP/Watcom/Borland clients (Quake, Hexen, Borland C++).

## One emulated VGA, presented through a sink

There is exactly one VGA model in the kernel (`kernel/src/vga.rs` and
`lib/vga_render`). When no real card is present (interp, or a UEFI machine with
only a framebuffer), `VgaState` is the live register file the guest reads and
writes; the kernel renders it through `lib::vga_render` at a divided tick
cadence and hands finished frames to a **present sink**:

- on metal it blits into the GOP framebuffer (`fbcon`);
- hosted parks the frame in a mailbox for the `retroos-play` window.

Backends supply only a framebuffer; they never emulate VGA themselves. Planar
EGA and Mode X are handled uniformly by trapping the unmapped `A0000` window as
a page fault and decoding the faulting instruction against the VGA's planar
logic — the same code on both backends, with no arch-specific path.

## Devices: passthrough when present, emulate when absent

The guiding rule for retro hardware (VGA, Sound Blaster, …) is to give
**direct/passthrough access when the real device is available** and **emulate it
when absent**, with the same kernel adapting per-machine rather than forking.

- **Platform is probed once** at startup into typed values
  (`kernel::platform`): `Host { Qemu | Metal | Interp }`,
  `Display { VgaCard | Framebuffer | HostWindow | Headless }`,
  `Firmware { NativeBios | Substitute }`, audio, media. No lazy re-probes.
- **Focus** (`kernel::focus`) owns the singleton console hardware — display,
  keyboard, mouse — and moves on F11. Singleton-hardware globals are correct
  because focus owns them; per-thread state is the *model*, transferred in and
  out on focus change.
- **I/O policy** (`kernel::io_policy`) rebuilds the TSS I/O bitmap on every
  swap-in from (personality, platform, focus). DOS-with-focus gets the VGA
  window on a real card; background DOS gets only its granted device windows;
  Linux gets no ports (its dispatcher faults `IN`/`OUT`). The arch mechanism is
  `reset_io_bitmap` + `allow_io_ports`; the policy lives in the kernel.
- **Sound**: a canonical kernel sound API behind which sit a metal AC'97 driver,
  an Intel HDA driver, and a cardless software Sound Blaster 16. Only the 8237
  DMA controller is virtualized for passthrough cards (remap the guest buffer
  contiguous, program the real 8237, relay the card IRQ); the SB/AWE64 register
  path itself is passthrough.

## Running on a real modern machine

The kernel boots unchanged on a UEFI x86-64 laptop, with no RetroOS-specific
firmware:

- **Boot**: `kernel.elf` is multiboot-loadable by the machine's existing GRUB
  (see [BOOTING.md](BOOTING.md)); it is self-contained — DN, COMMAND.COM and a
  fallback CONFIG.SYS are embedded, so a diskless boot mounts `/boot` from the
  embedded bootfs. RetroOS's own MBR bootloader remains the path on legacy/BIOS.
- **Console**: when GRUB hands over a GOP linear framebuffer, `arch/fbcon.rs`
  renders the emulated VGA into it.
- **No-ROM firmware**: machines without a real BIOS get a personality Rust BIOS
  (`dos/bios.rs`) providing the IVT, BDA projection, and INT 10h/16h/etc.
- **Storage**: an NVMe driver (read-only) discovers ext partitions on GPT/MBR
  disks; the root and extra disks mount read-only into the DOS namespace.
- **Interrupts**: APIC bringup — LAPIC timer (HPET-calibrated, xAPIC MMIO or
  x2APIC MSR) with a PIT fallback, IOAPIC-routed keyboard/mouse. This is what
  keeps the event loop's `hlt` waking on machines with no usable PIT.
- **Input**: i8042 where the EC emulates one, plus an xHCI USB-HID boot-keyboard
  driver (works on real full-speed hardware).

## Goal

Run DOS .COM programs, 32-bit Linux ELF binaries, and 64-bit Linux ELF
binaries on the same kernel. One binary, compiled once, running on any
x86 from a 386 to a modern processor.
