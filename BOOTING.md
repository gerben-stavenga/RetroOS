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
sudo ./setup-cdrive.sh            # C: content, including C:\BOOT  (first time)

bazelisk build //kernel:kernel_elf //kernel:kernel_sym   # as yourself
sudo tools/install_kernel.sh      # kernel + symbols                (every rebuild)
```

`install_kernel.sh` is the one to re-run after a build. It installs **two**
files, and they must come from the same build:

| file | destination | what it is |
|---|---|---|
| `kernel.elf` | `/boot/retroos/kernel.elf` | what GRUB multiboots — stripped, ~763 KB |
| `kernel.sym` | `<C:>/BOOT/KERNEL.SYM` | symbol table for panic backtraces, ~276 KB |

`kernel.elf` carries no symbol table, so a backtrace is named only if
`KERNEL.SYM` is present *and* matches. A stale symbol file is worse than a
missing one — the addresses still resolve, to the wrong functions — which is
why one script does both rather than two steps you might do separately. The
boot line `Loading kernel symbols (N bytes)` confirms it took.

Append to `/etc/grub.d/40_custom`:

```
menuentry "RetroOS (protected disk)" {
    insmod part_gpt
    insmod ext2
    insmod multiboot
    insmod efi_gop
    set gfxmode=auto
    set gfxpayload=keep
    search --no-floppy --file /retroos/kernel.elf --set=root
    multiboot /retroos/kernel.elf ram-overlay
    boot
}

menuentry "RetroOS (writable disk)" {
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

Two entries, because **`ram-overlay` is the only thing standing between RetroOS
and your real filesystem** — see below. Having both means the choice is at the
boot menu rather than in a file you have to remember to edit, and backing out
is a reboot.

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
- Edit `/etc/grub.d/40_custom`, **not** `/boot/grub/grub.cfg`. The generated
  file carries `### BEGIN /etc/grub.d/40_custom ###` markers, so hand-edits
  inside them look permanent and are not: any kernel or grub package update
  regenerates `grub.cfg` from the sources and silently drops them — taking
  `ram-overlay` with them.

## Disk writes and `ram-overlay`

**RetroOS writes to its disk.** That is the default, on every backend
including real hardware: a DOS program saves its game, a test leaves its
verdict behind, and the changes are still there next boot.

Add the Multiboot argument `ram-overlay` and every write to a physical disk
goes into volatile RAM instead. Writes appear to work for the whole session
and vanish on reboot:

```
multiboot /retroos/kernel.elf ram-overlay
```

The boot screen says which you got, and it is the ground truth — not the menu
entry's name:

```
Disk writes: volatile RAM overlay (ram-overlay) — changes will NOT persist
Disk writes: PERSISTENT — physical devices are writable        (in red)
```

### Which disk is at stake

RetroOS picks its root by probing each ext partition for `/etc` and `/usr` —
it deliberately looks for **a Linux root**, and on a laptop that is the one you
boot Linux from. `C:` is `/home/retroos` on that same filesystem. So without
`ram-overlay`, a DOS program is writing into your live system's root.

What it can and cannot reach:

- **Cannot**, structurally: the partition table, the EFI System Partition
  (where GRUB's own binary lives), any other partition, firmware. Every write
  goes through `Volume::write`, which is volume-relative and bounds-checked, so
  a filesystem cannot address past its own extent. GRUB will always still come
  up.
- **Can**: the contents of that one filesystem — which includes `/boot`. A bug
  in the ext4 write path could therefore leave Linux unbootable until you fsck
  it from a live USB. Recoverable, not catastrophic, but plan for it.

A second gate limits ordinary file writes: a file is writable only if its group
matches the `C:`-root's group **and** it is group-writable (`chgrp retroos` +
`chmod g+w`). That bounds deliberate writes; it does not bound a metadata bug.

### Status

Writing to a real laptop root has been exercised once, successfully: a file
created from DOS survived the reboot with correct contents and ownership, ext4
recorded no errors, and the next Linux mount needed no journal recovery. That
is one data point, not a guarantee — every other write test has run against a
~1 GiB image, in a layer that has had big-disk-only bugs before. There is also
no way yet to point RetroOS at a scratch partition instead of the real root,
so there is nowhere safe to stress it.

Until that exists, `ram-overlay` is the sensible default for a machine you care
about, and the writable entry is for when you specifically want persistence and
have a live USB within reach.

Why an argument rather than a probe: nothing can infer whether a disk is
precious. An earlier version tried — protect on "real hardware", detect
emulators by their southbridge — and got this project's own audience backwards,
since a real Pentium with a PIIX4 is a first-class RetroOS target and the
likeliest machine to be holding someone's data. Only the owner knows, so only
the owner says.

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
filesystem has no DOS system directory. Block writes reach the physical device
unless `ram-overlay` was passed.

Keyboard: the i8042 path (most laptops expose one via EC emulation) feeds
the personality BIOS's INT 09. Machines with USB-only input are handled by the
xHCI USB-HID boot-keyboard driver, which works on real full-speed hardware
(verified on a Razer Blade — SkyRoads played from USB keyboard input).

Caveats on real hardware (vs the `run_uefi.sh` mock):
- fbcon accepts 32bpp direct-RGB framebuffers and converts its pixels using the
  channel positions and widths reported by GRUB.
- ACPI shutdown is wired for QEMU/Bochs/VirtualBox and PIIX4 boards; on a
  modern laptop it falls through to a halt, so power off by holding the button.
- An MBR- or GPT-partitioned disk containing ext4 can become the RetroOS root,
  and its files appear in DN. Whether changes reach the medium is the
  `ram-overlay` question above.
- Returning to Linux after a RetroOS session has been seen to add ~34 s to the
  next boot, stalling just before the root mount. The filesystem is clean when
  it gets there (no journal recovery), so this looks like a device-handoff
  problem — RetroOS parks the HDA codec on the way out but not storage or USB.
  Under investigation.
