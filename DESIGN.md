# RetroOS Design

A single 32-bit kernel binary that runs DOS, 32-bit, and 64-bit programs
on any x86 from a 386 to a modern x86-64 processor.

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
the walk implicitly when the kernel accesses `entries[i]` — the recursive
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

The kernel handles interrupts from 16-bit (VM86), 32-bit, and 64-bit
userspace through a single Rust handler. The assembly entry point normalizes
the register save area:

- **32-bit entry**: zero-extends every register to 64 bits (`push 0; push eax`)
- **64-bit entry**: saves native 64-bit registers, then far-jumps to a
  32-bit trampoline that calls the same Rust handler

Both produce an identical `Regs` layout. The Rust interrupt handler sees one
type regardless of origin mode. After handling, `exit_kernel` dispatches to
the right return path (IRET for 32-bit/VM86, far jump + IRETQ for 64-bit).

## Single exit point

All interrupt and exception handlers return normally with an optional
context-switch request. Only `isr_handler` calls `switch_to_thread`. This
means:

- RAII works: Rust destructors run before any context switch
- One place to drain the IRQ event queue
- One place to handle VM86 segment swapping
- Stack traces always unwind through a clean call chain

## Typed IRQ event queue

Hardware interrupts push typed events (`enum Irq { Tick, Key(u8) }`) into
a global queue. The queue is drained only when returning to userspace:

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
