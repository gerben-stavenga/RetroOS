# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RetroOS is an educational x86-32 operating system written in C++20 with minimal assembly. Design philosophy prioritizes simplicity and readability over performance. The project aspires to be self-hosting.

## Build Commands

```bash
make image              # Build complete 16MB disk image
make                    # Build all components without creating image
make clean              # Remove build artifacts
qemu-system-i386 image  # Run in QEMU emulator
```

Build outputs:
- `build/bootloader.bin` - 512-byte MBR bootloader
- `build/kernel.bin` - Kernel binary with MD5 verification
- `build/init.elf` - Init process (shell)
- `image` - Final bootable disk image

## Architecture

### Directory Structure

- `src/arch/x86/` - Platform-specific x86-32 code (boot, paging, interrupts, descriptors)
- `src/kernel/` - Platform-independent kernel (threads, syscalls, drivers)
- `src/freestanding/` - Utility library with no std dependencies (Vector, String, print, ELF loader, TAR reader)
- `src/libc/` - Standard C library implementation for userspace
- `src/apps/` - User applications

### Boot Process

1. **MBR** (`src/arch/x86/boot/mbr.asm`) - Loads rest of bootloader from sector 1
2. **Bootloader** (`src/arch/x86/boot/boot.cpp`) - Switches to protected mode, sets up GDT, enables A20, reads kernel from TAR filesystem, verifies MD5, passes BootData to kernel
3. **Kernel Entry** (`src/arch/x86/start32.cpp`) - Sets up paging (recursive scheme), IDT, remaps PIC, loads init.elf
4. **Kernel Startup** (`src/kernel/startup.cpp`) - Initializes filesystem, creates init thread
5. **Init Process** (`src/kernel/init.cpp`) - Shell that can fork/exec programs

### Memory Layout (Virtual)

```
0x00000000 - 0x0000FFFF  Null page (protection)
0x00010000 - 0xDFFFFFFF  User space (~3.5 GB)
0xE0000000 - 0xFF6FFFFF  Kernel space (512 MB)
0xFF700000 - 0xFFC00000  Low physical memory mapped (0-1MB)
0xFFC00000 - 0xFFFFFFFF  Page tables + page directory (recursive paging)
```

### Key Design Patterns

- **Recursive Paging**: Page directory entry[1023] points to itself, allowing kernel to access all page tables at 0xFFC00000
- **Copy-on-Write Forking**: Fork shares parent pages read-only, allocates on write fault
- **BIOS Bridging**: Bootloader switches PM↔RM for BIOS calls (INT 0x10 video, INT 0x13 disk)
- **TAR Filesystem**: Entire filesystem is a TAR archive - kernel, init, apps stored sequentially

### Syscall Interface

INT 0x80 with: EAX=syscall#, EDX=arg0, ECX=arg1, EBX=arg2, ESI=arg3, EDI=arg4

Key syscalls: Exit(0), Yield(1), Fork(4), Exec(5), Open(6), Read(8), Write(9)

## Cross-Compilation

Uses clang++ with: `-m32 -march=i386 -ffreestanding -fno-exceptions -fno-rtti -std=c++20 -mno-red-zone`

NASM for assembly, ld for linking with custom linker scripts (`src/arch/x86/kernel.ld`, `src/arch/x86/boot/bootloader.ld`).

## Key Files

- `src/arch/x86/paging.cpp` - Virtual memory management with recursive paging
- `src/arch/x86/entry.asm` - Interrupt/exception entry handlers (49 vectors)
- `src/kernel/thread.cpp` - Process/thread management, scheduler
- `src/kernel/syscalls.cpp` - System call implementations
- `src/freestanding/utils.cpp` - Core utilities (Vector, String, print, ELF loader, TAR reader, MD5)
