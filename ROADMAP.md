# RetroOS Roadmap

## In Progress

## Pending

### Userspace & Mode Switching
- [ ] Harden and expand 64-bit userspace support
- [ ] Continue reducing mode-specific special cases at the kernel boundary

### Filesystem
- [ ] Write filesystem implementation (replace TAR)

### Compatibility Core
- [ ] Factor shared compatibility helpers out of DOS-specific code
- [ ] Reuse that core for DOS/Linux/Windows compatibility layers where possible

### DOS Compatibility
- [ ] Expand DOS INT 21h coverage and correctness

### Linux Compatibility
- [ ] Implement Linux API for 32-bit
- [ ] Implement Linux API for 64-bit

### Windows Compatibility
- [ ] Define an initial Windows compatibility strategy above the shared compat core

### Architecture
- [ ] Make the kernel crate compile `#![forbid(unsafe_code)]`: move the metal
      device drivers (`nvme`/`ac97`/`hda`/`pci`/`xhci`) and runtime plumbing
      (`heap`/`stacktrace`) below the arch boundary or behind safe capabilities
- [ ] Keep arch's `unsafe` surface (the TCB) small and audited
- [ ] Keep `arch` minimal, stable, and free of compatibility policy

## Completed

### Architecture & paging
- [x] 3-ring architecture: separate Arch (Ring 0) primitives from Kernel (Ring 1) policy
- [x] Swappable arch backend: `arch-abi` contract with `arch-metal` and `arch-interp` implementations
- [x] PAE paging with 64-bit page table entries
- [x] NX (No-Execute) bit support
- [x] Demand paging via page fault handler
- [x] Zero page COW fix
- [x] Kernel hardening (R-X .text, R-- NX .rodata, RW- NX .data)

### Userspace
- [x] ELF32 loading with proper permissions
- [x] ELF64 loading support
- [x] VM86 execution support in the trap/event path
- [x] 32-bit Linux ABI personality (runs BusyBox)

### DOS / DPMI
- [x] DOS .COM / MZ .EXE execution under VM86
- [x] DPMI 0.9 (+1.0 extensions): runs Quake, Commander Keen, Hexen, Borland C++ self-builds
- [x] DFS path-translation VFS layer; hostfs (DOSBox-style hosted root)

### Devices & hosted backend
- [x] Single emulated VGA model presented through a sink (metal GOP fbcon / hosted window)
- [x] Planar EGA + Mode X via page-fault VRAM trap (shared across backends)
- [x] Sound: canonical kernel API + metal AC'97, Intel HDA, cardless software SB16; 8237 DMA virtualization
- [x] `retroos-play` windowed host emulator on the interp backend

### Modern-hardware boot (metal)
- [x] UEFI boot via the machine's existing GRUB (multiboot); embedded bootfs for diskless boot
- [x] GOP framebuffer console; personality Rust BIOS for no-ROM machines
- [x] NVMe driver (read-only) + GPT/MBR ext-partition discovery
- [x] APIC bringup: LAPIC timer (HPET-calibrated) + IOAPIC, with PIT fallback
- [x] xHCI USB-HID boot keyboard (works on real full-speed hardware)
