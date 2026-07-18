# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RetroOS is an educational x86 operating system written mostly in Rust with minimal assembly. The core design principle is to canonicalize and unify behavior: normalize hardware and ABI differences into a small set of common kernel abstractions instead of growing separate execution paths everywhere.

`arch` is the hard boundary and should stay minimal, stable, and policy-free. Compatibility layers above it may be more pragmatic while DOS/Linux/Windows support is being developed, but should ideally share a common core library.

## Build Commands

```bash
bazelisk build //:image            # Build complete bootable disk image
bazelisk build //kernel:kernel_elf  # Build kernel only (multiboot-loadable ELF)
./run.sh qemu [--arch 386|686|x64] # Run in QEMU (unified launcher; see ./run.sh header)
./run.sh hosted --cmd GAMES/X      # Run the hosted backend (add --kvm for the KVM engine)
bazelisk test //arch-interp:all --platforms=@platforms//host  # arch unit tests (tcg + kvm proofs)
```

Bazel is the ONLY build system (no cargo): third-party crates are declared as
`crate.spec` entries in MODULE.bazel, pinned by `Cargo.Bazel.lock` +
`cargo-bazel-lock.json` (repin with `CARGO_BAZEL_REPIN=1 bazelisk build ...`
after changing a spec). Engine/feature selection is per-target
`crate_features` in BUILD files.

`run.sh` is the single launcher for every backend/firmware (`qemu`, `bochs`,
`86box`, `hosted`); the old `run_qemu.sh` / `run_uefi.sh` / `run_interp.sh` are
thin shims that forward to it.

Build outputs (via Bazel):
- `bazel-bin/boot/bootloader.bin` - MBR bootloader
- `bazel-bin/kernel/kernel.elf` - Kernel ELF (self-contained: embeds DN + COMMAND.COM)
- `bazel-bin/image.bin` - Final bootable disk image
- `bazel-bin/image_proprietary.bin` - Local image with proprietary assets when present

## Architecture

### Directory Structure

The `arch` boundary is a shared interface (`arch-abi`) with two swappable
backends — `arch-metal` (real CPU, `no_std`/Bazel) and `arch-interp` (Unicorn,
`std`). The `kernel` links one of them and is otherwise backend-agnostic.

- `boot/` - Bootloader (MBR assembly + Rust stage2)
- `arch-abi/` - Kernel-facing arch interface both backends implement (`src/arch.rs`, `src/monitor.rs`)
- `arch-metal/` - Bare-metal arch backend + metal drivers
  - `arch-metal/src/paging2.rs` - Virtual memory with recursive paging
  - `arch-metal/src/traps.rs` - Interrupt/exception handling and arch call boundary
  - `arch-metal/src/phys_mm.rs` - Physical page allocator
  - `arch-metal/src/xhci.rs` - USB-HID boot keyboard; APIC/LAPIC bringup in `irq.rs`
- `arch-interp/` - Hosted (Unicorn) arch backend: software CPU/MMU/paging/devices
- `kernel/` - Ring-1 kernel (Rust); `kernel/src/arch/entry.asm` is the asm entry
  - `kernel/src/kernel/thread.rs` - Process/thread, personalities, event dispatch
  - `kernel/src/kernel/sched.rs` - Scheduler
  - `kernel/src/kernel/heap.rs` - Kernel heap allocator
  - `kernel/src/kernel/dos/` - DOS personality (machine.rs = PC hardware, dos.rs, dpmi/)
  - `kernel/src/kernel/linux/` - Linux ABI personality (32/64-bit ELF syscalls)
  - `kernel/src/kernel/{platform,focus,io_policy}.rs` - machine probe, console owner, IOPB
  - `kernel/src/kernel/{block,sound,net,console,vfs,portio,pci}.rs` - the driver/fs APIs
    the personalities call; they own the policy and dispatch downward
  - `kernel/src/kernel/drivers/` - concrete hardware only (hdd, nvme, hda, ac97, alc298_amp)
  - `kernel/src/kernel/fs/` - filesystem backends (tarfs, hostfs, lwext4)
  - `kernel/src/vga.rs` - the single emulated VGA model
- `lib/` - Freestanding library (VGA render, ELF, TAR, MD5)
- `play/` - `retroos-play` windowed host emulator (on `arch-interp`)
- `apps/` - User applications, stress tests, and DOS binaries; `apps-boot/` = embedded bootfs
- `toolchain/` - Bazel toolchain configuration for bare-metal Rust

### Boot Process

RetroOS boots two ways on metal: its own MBR bootloader, or the machine's
existing GRUB (`kernel.elf` is multiboot-loadable — see BOOTING.md).

1. **MBR** (`boot/mbr.asm`) - Loads rest of bootloader from sector 1
2. **Bootloader** (`boot/src/lib.rs`) - Switches to protected mode, sets up GDT, enables A20, reads kernel from TAR filesystem, verifies MD5
3. **Kernel Entry** (`kernel/src/arch/entry.asm` + `kernel/src/lib.rs`) - Sets up paging, IDT, remaps PIC (or APIC bringup); fbcon console on a GOP framebuffer
4. **Init Process** - Userland init/shell (DN + COMMAND.COM, embedded as a fallback bootfs) that can fork/exec ELF and DOS programs

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
- **Kernel layering**: personalities → kernel APIs → `drivers`/`fs`. Arrows point down only; a personality never names a driver or a filesystem, it calls `block`/`sound`/`vfs`/`net`
- **Swappable arch backend**: `arch-metal` (real CPU) and `arch-interp` (Unicorn) implement one `arch-abi`; differences live *below* the boundary, never as kernel `cfg`/hooks
- **Recursive Paging**: one flat `entries[]` model across legacy, PAE, and compat mode
- **Copy-on-Write Forking**: Fork shares parent pages read-only, allocates on write fault
- **Event Loop Kernel**: ring-3 execution always comes back as a kernel-facing event
- **Personalities**: ELF → Linux ABI personality; DOS `.COM`/MZ `.EXE` → DOS personality (VM86 + DPMI), both layered on the same execution modes
- **TAR Filesystem**: the boot image is a TAR archive; VFS also mounts ext (read-only) and hostfs
- **One emulated VGA**: a single VGA model presented through a sink (metal GOP fbcon / hosted window); backends supply only a framebuffer
- **Probe once**: `platform` reads the machine into typed ADTs at startup; `focus` owns singleton console hardware; `io_policy` rebuilds the TSS IOPB per swap-in

### Syscall Interface

Userspace uses the **Linux ABI** (the kernel's Linux personality handles ELF):

- 32-bit: `INT 0x80`, EAX=syscall#, args in EBX, ECX, EDX, ESI, EDI, EBP (Linux i386 numbering)
- 64-bit: `SYSCALL` instruction, args in RDI, RSI, RDX, R10, R8, R9 (Linux x86-64 numbering)

Both land at the same dispatch in `kernel/src/kernel/linux/mod.rs`. DOS programs
instead use the INT 21h/DPMI surface in `kernel/src/kernel/dos/`.
