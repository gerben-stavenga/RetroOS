# Contributors

RetroOS is written by Gerben Stavenga. The people below have contributed
changes that are part of the tree; thank you.

## István Nagy (<https://github.com/nistvan86>)

István contributed several substantial hardware, boot, and host-integration
improvements:

- **DPMI physical address mapping.** He implemented `INT 31h AX=0800h` and
  `AX=0801h` using a dedicated, downward-growing mapping window. This made VESA
  linear framebuffers usable by protected-mode DOS programs, preserved
  sub-page offsets, correctly released mappings during unmap, exit, and nested
  `EXEC`, and kept externally owned device pages out of the allocator. He also
  traced the accompanying SVGA palette problem to the host VGA BIOS, leading to
  the `VGABIOS_ROM` guidance in `run.sh`.

- **GRUB Multiboot module filesystems.** In
  [PR #43](https://github.com/gerben-stavenga/RetroOS/pull/43) and
  [PR #44](https://github.com/gerben-stavenga/RetroOS/pull/44), he added
  raw ext4 Multiboot modules as root or additional mounts. The implementation
  introduced a reusable 64 KiB physical-memory aperture so module data can be
  read without copying entire images into the kernel heap, retained physical
  disks as fallback mounts, and added compact metadata and real QEMU boot
  coverage for base and games modules.

- **HDA output and volume controls.**
  [PR #45](https://github.com/gerben-stavenga/RetroOS/pull/45) added codec-aware
  speaker, jack, and headphone output selection, CONFIG.SYS
  defaults, live OSD controls, and logarithmic volume scaling. It also improved
  QEMU and 86Box test-launch determinism.

- **HostFS and serial transport.**
  [PR #50](https://github.com/gerben-stavenga/RetroOS/pull/50) modularized HostFS
  around a reusable COM1/COM2 16550 UART driver and a size-bounded,
  CRC-protected framed protocol. It made HostFS explicitly configurable and
  optional, added physical RS-232 serving without modem-control wiring, removed
  the misleading RAM write overlay, and added timeout, reconnect, session-reset,
  path-containment, and lifecycle coverage for guest, server, and QEMU restarts.
