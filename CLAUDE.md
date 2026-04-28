# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RetroOS is an educational x86 operating system written mostly in Rust with minimal assembly. The core design principle is to canonicalize and unify behavior: normalize hardware and ABI differences into a small set of common kernel abstractions instead of growing separate execution paths everywhere.

`arch` is the hard boundary and should stay minimal, stable, and policy-free. Compatibility layers above it may be more pragmatic while DOS/Linux/Windows support is being developed, but should ideally share a common core library.

## Build Commands

```bash
bazelisk build //:image    # Build complete 16MB disk image
bazelisk build //kernel:kernel_elf  # Build kernel only
./run_qemu.sh [386|686|x64]        # Run local proprietary image in QEMU
```

Build outputs (via Bazel):
- `bazel-bin/boot/bootloader.bin` - MBR bootloader
- `bazel-bin/kernel/kernel.elf` - Kernel ELF
- `bazel-bin/image.bin` - Final bootable disk image
- `bazel-bin/image_proprietary.bin` - Local image with proprietary assets when present

## Architecture

### Directory Structure

- `boot/` - Bootloader (MBR assembly + Rust stage2)
- `kernel/` - Kernel (entry.asm + Rust)
  - `kernel/src/arch/paging2.rs` - Virtual memory with recursive paging
  - `kernel/src/kernel/thread.rs` - Process/thread management, scheduler
  - `kernel/src/arch/traps.rs` - Interrupt/exception handling and arch call boundary
  - `kernel/src/kernel/syscalls.rs` - System call implementations
  - `kernel/src/kernel/vm86.rs` - VM86 runtime and DOS compatibility layer
  - `kernel/src/kernel/heap.rs` - Kernel heap allocator
  - `kernel/src/arch/phys_mm.rs` - Physical page allocator
- `lib/` - Freestanding library (VGA, ELF, TAR, MD5)
- `apps/` - User applications, stress tests, and DOS binaries
- `toolchain/` - Bazel toolchain configuration for bare-metal Rust

### Boot Process

1. **MBR** (`boot/mbr.asm`) - Loads rest of bootloader from sector 1
2. **Bootloader** (`boot/src/lib.rs`) - Switches to protected mode, sets up GDT, enables A20, reads kernel from TAR filesystem, verifies MD5
3. **Kernel Entry** (`kernel/entry.asm` + `kernel/src/lib.rs`) - Sets up paging, IDT, remaps PIC
4. **Init Process** - Userland init/shell that can fork/exec ELF and DOS programs

### Memory Layout (Virtual)

```
0x00000000 - 0xBFFFFFFF  User space
0xC0000000 - 0xC07FFFFF  Recursive page-table view
0xC0800000 - 0xC09FFFFF  PML4 region (compat mode)
0xC0A00000 - 0xC0AFFFFF  Low memory / BIOS / VGA mapping
0xC0B00000 - 0xFFFFFFFF  Kernel space
```

### Key Design Patterns

- **Canonicalization**: normalize mode/ABI differences into shared kernel abstractions
- **Recursive Paging**: one flat `entries[]` model across legacy, PAE, and compat mode
- **Copy-on-Write Forking**: Fork shares parent pages read-only, allocates on write fault
- **Event Loop Kernel**: ring-3 execution always comes back as a kernel-facing event
- **TAR Filesystem**: Entire filesystem is a TAR archive
- **VM86 Mode**: DOS `.COM` and MZ `.EXE` execution is handled as another execution mode

### Syscall Interface

INT 0x80 with: EAX=syscall#, EDX=arg0, ECX=arg1, EBX=arg2, ESI=arg3, EDI=arg4

Key syscalls: Exit(0), Yield(1), Fork(4), Exec(5), Open(6), Read(8), Write(9)
