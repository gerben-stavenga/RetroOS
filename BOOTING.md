# Booting RetroOS on a real (UEFI) machine via its existing GRUB

RetroOS's production boot path on modern hardware is the GRUB already
installed on the machine: `kernel.elf` is multiboot-loadable and
self-contained (DN + COMMAND.COM + a fallback CONFIG.SYS are embedded in the
image — see TODO.md project 6), so installing it is copying one file and
adding one menuentry. No partitioning, no images, no bootloader install.

## Install

```bash
bazelisk build //kernel:kernel_elf
sudo mkdir -p /boot/retroos
sudo cp bazel-bin/kernel/kernel.elf /boot/retroos/
```

Append to `/etc/grub.d/40_custom`:

```
menuentry "RetroOS" {
    insmod part_gpt
    insmod ext2
    insmod multiboot
    insmod efi_gop
    set gfxmode=auto
    set gfxpayload=keep
    search --no-floppy --file /retroos/kernel.elf --set=root
    multiboot /retroos/kernel.elf
    boot
}
```

then `sudo update-grub` and reboot.

- Path subtlety: GRUB paths are relative to the partition holding them. A
  separate `/boot` partition → `/retroos/kernel.elf` (as above); `/boot` on
  the root filesystem → `/boot/retroos/kernel.elf` in both lines.
- `insmod efi_gop` is load-bearing: the kernel's multiboot header requests a
  linear framebuffer, and without the GOP driver GRUB fails with
  "no suitable video mode found".
- `gfxpayload=keep` makes the framebuffer handoff explicit instead of relying
  on GRUB's platform-specific payload default.
- **Secure Boot must be disabled** in firmware setup: GRUB under Secure Boot
  lockdown refuses `multiboot` of unsigned binaries.

## What happens

GOP text console (the kernel renders into the framebuffer GRUB hands over —
`kernel/src/arch/fbcon.rs`), then a diskless boot: a GPT disk's protective
MBR matches no RetroOS partition types, so `/boot` is mounted from the
embedded bootfs and DN starts from it. The machine's own disk is never
mounted, and the NVMe driver is read-only regardless.

Keyboard: the i8042 path (most laptops expose one via EC emulation) feeds
the personality BIOS's INT 09. A machine with USB-only input needs the xHCI
driver (not yet written).

Caveats on real hardware (vs the `run_uefi.sh` mock):
- fbcon accepts 32bpp direct-RGB framebuffers and converts its pixels using the
  channel positions and widths reported by GRUB.
- ACPI shutdown isn't wired on metal: reboot/power off by holding the power
  button. Nothing persists; Secure Boot can be re-enabled afterwards.
- An old MBR-partitioned disk with a type-0x83 partition WILL be mounted
  (read-only) as the RetroOS root — harmless, but your files appear in DN.
