# RetroOS Codebase Explanation

RetroOS is a 32-bit Rust operating-system kernel designed to execute several
different kinds of x86 programs:

- 16-bit DOS programs through VM86
- 32-bit DOS extenders through DPMI
- 32-bit Linux ELF programs
- 64-bit Linux ELF programs

The unusual part is that the same kernel policy code can run on bare-metal x86,
inside a host process using Unicorn/TCG, or inside a host process using KVM.

## System Shape

Conceptually, RetroOS has four layers:

```text
DOS programs       Linux ELF programs
      |                    |
      v                    v
 DOS/DPMI personality   Linux personality
             |          |
             +----+-----+
                  v
       Safe-oriented policy kernel
  threads, scheduler, VFS, exec, devices
                  |
                  v
              arch-abi
  execution, memory, paging, ports, IRQs
          +-------+--------+
          v                v
      arch-metal       arch-interp
       real CPU        Unicorn or KVM
```

The layers are linked into one executable for each deployment mode. This is
function-call composition, not IPC or dynamically loaded modules.

## `arch-abi`: The Machine Contract

[`arch-abi/src/arch.rs`](arch-abi/src/arch.rs) defines the interface between the
kernel and whatever executes user code.

The central trait is `Arch`. It provides operations such as:

```rust
fn execute(&mut self, regs: &mut Regs) -> KernelEvent;
fn activate(
    &mut self,
    incoming: Self::PageTable,
    fx_ptr: *mut Self::Fx,
    hash_ptr: *mut u64,
) -> Self::PageTable;
fn user_fork(&mut self, child: &mut Self::PageTable);
fn map_low_mem(&mut self);
fn load_ldt(&mut self, ldt: &[u64]);
```

It also provides port I/O, timer access, IRQ handling, page operations, FPU
switching, TLS, DMA and descriptor lookup.

`Arch` has two backend-specific associated types:

- `PageTable`: an owned address-space handle
- `Fx`: saved FPU/SSE state

The kernel is generic over `A: Arch`, so it is compiled from the same source for
each backend.

`Regs` is the canonical CPU-state representation. It can represent VM86, 32-bit
protected-mode, compatibility-mode and 64-bit execution. Different hardware
entry frames are normalized into this structure at the architecture boundary.

## Execution Model

The kernel is organized as an explicit event loop in
[`kernel/src/kernel/startup.rs`](kernel/src/kernel/startup.rs):

```text
prepare current thread
        |
        v
arch.execute(registers)
        |
        v
KernelEvent
        |
        v
DOS or Linux personality
        |
        v
KernelAction
        |
        v
scheduler
```

`execute()` runs user code until something noteworthy happens. It returns a
`KernelEvent`, such as:

- system call
- software interrupt
- hardware interrupt
- page fault
- general fault
- port input or output
- halt

The relevant personality interprets that event and returns a `KernelAction`,
such as:

- continue
- yield
- exit
- fork
- exec
- wait
- switch thread

This avoids hidden kernel control flow. Most policy code behaves like ordinary
Rust code that calls a function and receives an event.

## Execution Context and Address Spaces

[`kernel/src/kernel/exec_ctx.rs`](kernel/src/kernel/exec_ctx.rs) represents
ownership of the currently executing CPU context.

A parked thread owns:

```text
Vcpu
+-- saved Regs
+-- owned PageTable handle
```

When a thread starts running:

- its registers move into `ExecutionContext`;
- its address space moves into the backend;
- the previously active address space moves back into the outgoing thread;
- FPU state is exchanged;
- the thread's I/O permissions and descriptor state are restored.

This move-based model is one of the better abstractions in the project. An
address-space handle is not `Copy` or `Clone`, so accidental duplication is
prevented at the type level.

## Bare-Metal Backend

[`arch-metal`](arch-metal) implements `Arch` using real x86 hardware.

It owns or controls:

- trap and interrupt entry;
- recursive page tables;
- legacy, PAE and PML4 paging;
- VM86 and long-mode transitions;
- GDT, IDT, TSS and LDT state;
- physical-page allocation;
- APIC/PIC/PIT handling;
- NVMe and xHCI;
- privileged port and MMIO access.

On metal, `execute()` eventually performs an `IRET` into user space. A trap or
interrupt re-enters ring 0, which normalizes the resulting frame and returns
control to the ring-1 policy kernel.

### Ring Organization

RetroOS uses:

- ring 0 for the architecture supervisor;
- ring 1 for most kernel policy;
- ring 3 for applications and DOS guests.

Ring 1 and ring 0 both use supervisor pages, so the CPU does not provide memory
isolation between them. The intended boundary is Rust API safety: policy code
should reach privileged state only through `Arch`.

That boundary is not fully enforced yet because the kernel still contains
unsafe code and mutable global state.

## PAE, PML4 and VM86

The most technically distinctive code is in:

- [`arch-metal/src/paging2.rs`](arch-metal/src/paging2.rs)
- [`kernel/src/arch/entry.asm`](kernel/src/arch/entry.asm)
- [`arch-metal/src/traps.rs`](arch-metal/src/traps.rs)

VM86 cannot execute while the processor is in long mode. RetroOS therefore
switches between:

- 32-bit protected mode with PAE for VM86;
- long mode with a 32-bit compatibility-mode kernel for 64-bit users.

The PAE hierarchy and PML4 hierarchy are arranged to describe effectively the
same address space. A small identity-mapped assembly routine:

1. disables paging;
2. switches CR3;
3. toggles `EFER.LME`;
4. enables paging again;
5. returns under the new paging interpretation.

The kernel remains linked at the same high virtual addresses. Consequently, the
system can alternate between a VM86 DOS thread and a 64-bit Linux thread without
running the DOS thread in a hardware virtual machine.

## Hosted Backend

[`arch-interp`](arch-interp) implements the same `Arch` contract inside a normal
host process.

There are two engines:

- TCG through Unicorn for interpreted execution
- KVM for hardware-assisted execution

The kernel itself executes as native host code. Only the guest application's CPU
instructions are interpreted or virtualized.

The hosted backend implements:

- software page tables and COW;
- guest physical memory;
- CPU register synchronization;
- port-I/O interception;
- descriptor-table modeling;
- virtual interrupts and timers;
- optional KVM setup and execution.

Because the kernel code is unchanged, hosted execution is useful for ordinary
debugging, deterministic testing and eventually fuzzing.

## Personalities

[`kernel/src/kernel/thread.rs`](kernel/src/kernel/thread.rs) defines two
personalities.

### DOS

[`kernel/src/kernel/dos`](kernel/src/kernel/dos) implements:

- DOS `INT 21h` services;
- BIOS interrupts;
- VM86 execution;
- DPMI;
- EMS and XMS;
- DOS process state;
- virtual PIC, PIT, DMA and keyboard;
- VGA behavior;
- Sound Blaster and OPL emulation.

DOS is therefore more than a syscall personality. It includes a virtualized PC
hardware environment.

### Linux

[`kernel/src/kernel/linux/mod.rs`](kernel/src/kernel/linux/mod.rs) implements a
partial Linux ABI:

- file operations;
- fork, clone, exec and wait;
- pipes;
- directory operations;
- memory mapping;
- polling;
- selected socket operations;
- 32-bit and 64-bit syscall dispatch.

It is sufficient for selected static or musl-linked programs, but it is not
intended to provide the complete Linux ABI yet.

## Shared Kernel Services

[`kernel/src/kernel`](kernel/src/kernel) contains common policy and services:

- `thread.rs`: process and thread state
- `sched.rs`: current scheduling policy
- `exec.rs`: executable loading support
- `vfs.rs`: virtual filesystem
- `ext4fs.rs`: ext4 adapter
- `tarfs.rs`: embedded boot filesystem
- `kpipe.rs`: kernel pipes
- `console.rs`: input and console routing
- `focus.rs`: foreground-task ownership
- `io_policy.rs`: per-thread port permissions
- `platform.rs`: injected platform services
- `sound.rs`: common sound policy

The scheduler currently follows the focused task rather than providing general
round-robin preemption. F11 transfers focus and execution between tasks.

## Build Composition

Bazel assembles several products from the same kernel library:

```text
kernel rlib + arch-metal + entry.asm
    -> bootable kernel ELF

kernel rlib + arch-interp/TCG
    -> ordinary hosted executable

kernel rlib + arch-interp/KVM
    -> KVM-hosted executable

kernel rlib + arch-interp + window/audio frontend
    -> retroos-play
```

The build logic is primarily in
[`kernel/BUILD.bazel`](kernel/BUILD.bazel).

## Current Engineering State

The architecture is ahead of some implementation details. In particular:

- `Metal` and `Interp` are still zero-sized facades over mutable global state.
- The kernel is not yet compiled with `#![forbid(unsafe_code)]`.
- Guest-pointer operations are infallible and do not reliably reject
  kernel-range addresses.
- Generic `GuestBytes::read<T: Copy>` is not a sound safe interface.
- Some hardware and hosted operations remain incomplete.
- Several large personality modules need further decomposition and focused
  tests.

These are meaningful problems, but they do not invalidate the central design.
They show that RetroOS is in the middle of converting a working system into the
architecture its interfaces already describe.

In one sentence: RetroOS is a multi-personality kernel that treats bare-metal
x86, interpreted x86 and KVM as interchangeable implementations of the same
abstract execution machine.
