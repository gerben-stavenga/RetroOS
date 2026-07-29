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

## Persistent disk writes

Real-hardware boots are safe by default: RetroOS places a volatile RAM overlay
over every detected disk, so writes work during the session but disappear on
reboot. To deliberately let writes reach the physical disks, add the explicit
Multiboot argument:

```
multiboot /retroos/kernel.elf disk-writes=persistent
```

The boot screen prints a red `Disk writes: PERSISTENT` warning when this mode is
active. This applies to every physical disk RetroOS detects; use it only when
that is intentional. `CONFIG.SYS` cannot enable the mode because it is read
from disk after the storage policy has already been installed.

## What happens

GOP text console (the kernel renders into the framebuffer GRUB hands over —
`kernel/src/arch/fbcon.rs`), then storage discovery. RetroOS walks MBR or GPT
partitions, mounts the selected ext4 root, and overlays its embedded bootfs at
`/boot` so DN and COMMAND.COM remain available. On a default metal boot, block
writes land in the volatile overlay rather than on the physical device.

Keyboard: the i8042 path (most laptops expose one via EC emulation) feeds
the personality BIOS's INT 09. Machines with USB-only input are handled by the
xHCI USB-HID boot-keyboard driver, which works on real full-speed hardware
(verified on a Razer Blade — SkyRoads played from USB keyboard input).

Caveats on real hardware (vs the `run_uefi.sh` mock):
- fbcon accepts 32bpp direct-RGB framebuffers and converts its pixels using the
  channel positions and widths reported by GRUB.
- ACPI shutdown isn't wired on metal: reboot/power off by holding the power
  button. By default nothing persists; Secure Boot can be re-enabled afterwards.
- An MBR- or GPT-partitioned disk containing ext4 can become the RetroOS root.
  Its files appear in DN, but physical changes still require the explicit
  persistent-write switch above.
