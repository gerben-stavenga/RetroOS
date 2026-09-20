FreeDOS boot components for the persistent data disk.

Everything here that CAN be built from source IS built from source, with the
stock NASM already in this toolchain:

  bootnorm.asm  FreeDOS MBR (FDISK /MBR): finds the active partition, loads
                its VBR, jumps.  From the FreeDOS 1.4 fdisk package sources.
                Verified byte-identical to the MBR that boots the legacy
                freedos/freedos_hdd.img, so this is not a re-implementation.
  boot32lb.asm  FAT32 LBA volume boot record: loads KERNEL.SYS.  From the
                FreeDOS 1.4 kernel package sources (boot/boot32lb.asm).
                SYS.COM writes this same sector; we splice the BPB ourselves.

  KERNEL.SYS    The FreeDOS kernel and shell.  Binaries by necessity, taken
  COMMAND.COM   from freedos/FD14LIVE.iso.

Provenance: freedos/FD14LIVE.iso, packages/base/{kernel,fdisk}.zip ->
SOURCE/.../SOURCES.ZIP.  All GPL; see DOC/KERNEL/COPYING in those packages.
