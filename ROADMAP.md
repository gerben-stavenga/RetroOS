# RetroOS Roadmap

## In Progress

## Pending

### Userspace & Mode Switching
- [ ] Create userspace with 0xF000 identity mapped to trampoline (for mode switching)
- [ ] Load ELF64 and test 64-bit userspace support

### Real Mode Support
- [ ] Add VM86 support in GP handler (enables BIOS calls for disk, video, etc.)

### Filesystem
- [ ] Write filesystem implementation (replace TAR)

### DOS Compatibility
- [ ] Implement DOS INT 21h API
- [ ] Implement DPMI/VCPI support

### Linux Compatibility
- [ ] Implement Linux API for 32-bit
- [ ] Implement Linux API for 64-bit

## Completed

- [x] PAE paging with 64-bit page table entries
- [x] NX (No-Execute) bit support
- [x] Demand paging via page fault handler
- [x] Zero page COW fix
- [x] ELF32 loading with proper permissions
- [x] Kernel hardening (R-X .text, R-- NX .rodata, RW- NX .data)
