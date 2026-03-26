# RetroOS Design

A single 32-bit kernel binary that runs DOS, 32-bit, and 64-bit programs
on any x86 from a 386 to a modern x86-64 processor.

## Arch and ring-1 kernel

RetroOS is split into two layers with hardware-enforced isolation:

- **arch**: ring-0 supervisor (~2MB code/data)
- **kernel**: ring-1 OS kernel with event loop

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

## Privilege model

RetroOS uses three of the four x86 privilege rings:

| Ring | Role | Paging | Privileged insns | Segment limits |
|------|------|--------|-----------------|----------------|
| 0 | arch | supervisor (U/S=0) | yes | flat (full access) |
| 1 | kernel | supervisor (U/S=0) | no | wrapped (arch region excluded) |
| 3 | user | user (U/S=1) | no | flat |

Ring 1 is supervisor for paging purposes — it can access U/S=0 pages. But
x86 segment limits with 32-bit wrapping exclude the arch/page-table region
from ring-1 access, providing full hardware isolation between arch and
kernel.

This is the x86 protection model used as Intel originally intended:
paging for user/supervisor isolation, rings for privilege separation,
and segments for fine-grained memory partitioning between rings.

### Segment-based arch isolation

The ring-1 code and data segments use base/limit wrapping to punch a hole
in the address space:

```
Ring-1 CS/DS: base = 0xC0C0_0000, limit = 0xFF3F_FFFF

Accessible (wraps around 4GB):
  0xC0C0_0000 → 0xFFFF_FFFF  (kernel high region)
  0x0000_0000 → 0xBFFF_FFFF  (user space)

Excluded (#GP on access):
  0xC000_0000 → 0xC0BF_FFFF  (page tables + arch)
```

Ring-0 arch uses flat segments (base=0, limit=4GB) for full access.
The segment swap happens automatically on ring transitions — interrupt
from ring 1 loads ring-0 SS from TSS (flat), IRET back restores
ring-1 SS (wrapped).

User pointer translation: since the ring-1 data segment has a non-zero
base, user pointers from `Regs` (which are raw `u64` values, not Rust
pointers) must be translated via a single function:

```rust
fn user_ptr<T>(addr: u32) -> *const T {
    addr.wrapping_sub(SEGMENT_BASE) as *const T
}
```

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
0xC000_0000 - 0xC0BF_FFFF  Supervisor-only (12 MB, ring-1 excluded by segments)
0xC0C0_0000 - 0xFFFF_FFFF  Kernel (~1012 MB, ring-1 accessible)
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

The kernel starts at `0xC0C0_0000` in all modes. U/S=0 entries are
supervisor-only; U/S=1 entries are the ring-1 kernel. The segment limits
provide the actual isolation between ring-1 kernel and the arch/page-table
region — paging U/S is defense in depth against ring-3 user processes.

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

## Goal

Run DOS .COM programs, 32-bit Linux ELF binaries, and 64-bit Linux ELF
binaries on the same kernel. One binary, compiled once, running on any
x86 from a 386 to a modern processor.
