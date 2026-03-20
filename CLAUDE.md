# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RetroOS is an educational x86-32 operating system written in Rust with minimal assembly. Design philosophy prioritizes simplicity and readability over performance. The project aspires to be self-hosting.

## Build Commands

```bash
bazelisk build //:image    # Build complete 16MB disk image
bazelisk build //kernel:kernel_elf  # Build kernel only
./run_qemu.sh [386|686|x64]        # Run in QEMU emulator
```

Build outputs (via Bazel):
- `bazel-bin/boot/bootloader.bin` - MBR bootloader
- `bazel-bin/kernel/kernel.elf` - Kernel ELF
- `bazel-bin/image.bin` - Final bootable disk image

## Architecture

### Directory Structure

- `boot/` - Bootloader (MBR assembly + Rust stage2)
- `kernel/` - Kernel (entry.asm + Rust)
  - `kernel/src/paging2.rs` - Virtual memory with recursive paging
  - `kernel/src/thread.rs` - Process/thread management, scheduler
  - `kernel/src/traps.rs` - Interrupt/exception handlers (single exit point via switch_to_thread)
  - `kernel/src/syscalls.rs` - System call implementations
  - `kernel/src/vm86.rs` - VM86 mode for DOS .COM execution
  - `kernel/src/heap.rs` - Kernel heap allocator
  - `kernel/src/phys_mm.rs` - Physical page allocator
- `lib/` - Freestanding library (VGA, ELF, TAR, MD5)
- `crt/` - C runtime / user linker scripts
- `apps/` - User applications (init, shell, stress tests, hello.com)
- `toolchain/` - Bazel toolchain configuration for bare-metal Rust

### Boot Process

1. **MBR** (`boot/mbr.asm`) - Loads rest of bootloader from sector 1
2. **Bootloader** (`boot/src/lib.rs`) - Switches to protected mode, sets up GDT, enables A20, reads kernel from TAR filesystem, verifies MD5
3. **Kernel Entry** (`kernel/entry.asm` + `kernel/src/lib.rs`) - Sets up paging, IDT, remaps PIC
4. **Init Process** - Shell that can fork/exec programs

### Memory Layout (Virtual)

```
0x00000000 - 0x0000FFFF  Null page (protection)
0x00010000 - 0xDFFFFFFF  User space (~3.5 GB)
0xE0000000 - 0xFF6FFFFF  Kernel space (512 MB)
0xFF700000 - 0xFFC00000  Low physical memory mapped (0-1MB)
0xFFC00000 - 0xFFFFFFFF  Page tables + page directory (recursive paging)
```

### Key Design Patterns

- **Recursive Paging**: Page directory self-reference at entry[last], all page tables accessible at 0xFFC00000
- **Copy-on-Write Forking**: Fork shares parent pages read-only, allocates on write fault
- **Single Exit Point**: All interrupt handlers return normally (RAII), only `isr_handler` calls `switch_to_thread`/`exit_kernel`
- **TAR Filesystem**: Entire filesystem is a TAR archive
- **VM86 Mode**: DOS .COM programs run via VM86 with virtual PIC/keyboard per thread

### Syscall Interface

INT 0x80 with: EAX=syscall#, EDX=arg0, ECX=arg1, EBX=arg2, ESI=arg3, EDI=arg4

Key syscalls: Exit(0), Yield(1), Fork(4), Exec(5), Open(6), Read(8), Write(9)
