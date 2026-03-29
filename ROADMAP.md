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
- [ ] Implement DPMI/VCPI support

### Linux Compatibility
- [ ] Implement Linux API for 32-bit
- [ ] Implement Linux API for 64-bit

### Windows Compatibility
- [ ] Define an initial Windows compatibility strategy above the shared compat core

### Architecture
- [ ] Hardware-enforced isolation (Ring 1 segment limits)
- [ ] Keep `arch` minimal, stable, and free of compatibility policy

## Completed

- [x] 3-ring architecture: separate Arch (Ring 0) primitives from Kernel (Ring 1) policy
- [x] PAE paging with 64-bit page table entries
- [x] NX (No-Execute) bit support
- [x] Demand paging via page fault handler
- [x] Zero page COW fix
- [x] ELF32 loading with proper permissions
- [x] ELF64 loading support
- [x] VM86 execution support in the trap/event path
- [x] Kernel hardening (R-X .text, R-- NX .rodata, RW- NX .data)
