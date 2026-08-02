# Booting RetroOS on a real (UEFI) machine via its existing GRUB

RetroOS's production boot path on modern hardware is the GRUB already
installed on the machine: `kernel.elf` is multiboot-loadable, so installing it
is copying one file and adding one menuentry. No partitioning, no images, no
bootloader install.

The kernel carries no filesystem of its own. It mounts the machine's ext4
root and takes `C:` from `/home/retroos`, so the DOS system directory
`C:\BOOT` (DN, COMMAND.COM, LOADFIX.CFG, SHELL.ELF) has to exist there —
`setup-cdrive.sh` puts it there, or run `tools/install_boot_dir.sh` on its
own. Without it the kernel boots but has no shell to start.

## Install

```bash
bazelisk build //kernel:kernel_elf
sudo mkdir -p /boot/retroos
sudo cp bazel-bin/kernel/kernel.elf /boot/retroos/
sudo ./setup-cdrive.sh          # C: content, including C:\BOOT
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

## Booting from a GRUB hard disk (`//:image_grub`)

This is for a *self-contained* disk — one you write to a spare drive or a USB
stick and boot without touching that machine's GRUB, and what QEMU/Bochs/86Box
boot. Installing on a machine that already has GRUB does not need it; use the
one-file install above. `bazelisk build //:image_grub` produces a disk with
**no RetroOS bootloader**:
GRUB's `boot.img` in sector 0, `core.img` in the MBR gap, and a single ext4
partition holding `/boot/kernel.elf`, `/boot/grub/grub.cfg` and the usual
content. Run it with `./run.sh qemu -i grubhdd`.

The legacy `//:image` (our own MBR + a 0xDA boot-bundle partition holding
`kernel.elf` as a TAR member) still builds. `//:image_grub` is the candidate
replacement: same job, a stock loader, and one fewer on-disk format to
maintain.

The image is assembled by `tools/build_grub_hdd.py`, which does GRUB's two
embed steps itself (`boot.img`'s core LBA, `core.img`'s block list) because
`grub-install` wants a real block device and `grub-bios-setup` is not always
packaged. It needs `grub-mkimage` plus the i386-pc modules (`grub-pc-bin`).

## What happens

GOP text console (the kernel renders into the framebuffer GRUB hands over —
`kernel/src/arch/fbcon.rs`), then storage discovery. RetroOS walks MBR or GPT
partitions and mounts the selected ext4 root. DN and COMMAND.COM come from
`C:\BOOT`, an ordinary directory on that root — a boot with no RetroOS
filesystem has no DOS system directory. On a default metal boot, block
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
