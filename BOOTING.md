# Booting RetroOS with GRUB

GRUB supplies the kernel and two ordinary configuration files: `BOOT.INI`
for bundle backing and mounts, and `RETROOS.INI` for user settings.

## Disk-backed installation (ext4)

```sh
tools/install_kernel.sh --prepare
# Review build/machine-install/<release>/BOOT.INI and grub.cfg
sudo tools/install_kernel.sh
```

The installer keeps kernel/runtime files under `/boot/retroos/releases/<version>/`,
mount policy at `/boot/retroos/BOOT.INI`, and user settings permanently at
`/home/retroos/RETROOS/RETROOS.INI` (`C:\RETROOS\RETROOS.INI`).
GRUB loads both INIs separately. RetroOS opens the bundle directory by the UUID
and `subdir` in `[bundle]`, so no filesystem image is loaded into RAM and no
RAM-to-disk handoff is needed. Runtime writes use a sparse session overlay;
user settings and C: data persist in the persistent entry. Upgrades preserve
user settings and existing mount choices. The installer currently requires
`/boot` and C: on the ext4 Linux root.

## USB and optical boot

The boot partition contains `/boot/grub/grub.cfg`, editable
`/boot/retroos/BOOT.INI` and `/boot/retroos/RETROOS.INI`, and versioned boot files
under `/boot/retroos/releases/<version>/`. GRUB loads the core image as a module
because RetroOS cannot read USB storage yet. `[bundle] source=module` selects
that image. Default boot loads the 16 MiB core (runtime libraries, DN and
BusyBox) plus one 256 MiB showcase module with VC, MC, RC, NDN
(DOS/Windows/OS/2), DN/2 (DOS/Windows/OS/2) and games. The “Core only
(less RAM)” choice omits the showcase module. The user INI is exposed at `C:\RETROOS\RETROOS.INI` as session content;
edit the ordinary USB file from another OS for persistent changes.

## Module installation for filesystems RetroOS cannot read

Use Linux with GRUB 2 installed. The USB image supplies both the kernel and RAM base
module. Build and prepare as your normal user, review the generated entry, then
install it as root:

```sh
tools/install_kernel.sh --module --prepare
# Review build/grub-module-install/<image hash>/grub.cfg
sudo tools/install_kernel.sh --module
```

Linux enumerates FAT and ext4 partitions on non-USB disks. If several could be
C:, preparation prints their paths and UUIDs; rerun with
`--c-uuid=ABCD-1234` (FAT) or an ext4 UUID. A selected ext4 volume may be
unmounted in Linux: installation temporarily mounts it to check or create
`home/retroos`, then unmounts it. Installation also creates the `retroos`
group when needed. With no supported
data volume, the RAM module supplies C:. Use `--c-ram` to choose this explicitly.
For ext4, add `--c-dir=/path/on/volume` during preparation to use a different
C: directory; the installer creates that directory and passes the same path
through the INI mount configuration. The default is `/home/retroos` on the selected ext4 volume.
When Linux `/` is Btrfs, RAM C: is the default; use `--c-uuid` to select a
separate supported data volume. The RAM module always supplies
`C:\RETROOS`, even when C: data lives on a physical disk.

For example, with Linux `/boot` on Btrfs and a separate FAT32 data partition,
find that partition's UUID and prepare the entry with it:

```sh
lsblk -o NAME,FSTYPE,UUID,PARTTYPE,MOUNTPOINTS
tools/install_kernel.sh --module --prepare --c-uuid=ABCD-1234
# Review build/grub-module-install/<image hash>/grub.cfg
sudo tools/install_kernel.sh --module
```

Replace `ABCD-1234` with the FAT32 data partition's UUID, not the EFI System
Partition's UUID. The installer stores `kernel.elf` and
`retroos-base.img.gz` under Linux `/boot/retroos/releases/...`, with both INIs
at `/boot/retroos/`; GRUB reads
them from Btrfs before starting RetroOS. RetroOS then reads the selected
FAT32 partition as C:. It cannot read Btrfs itself, so `C:\RETROOS` comes
from the RAM base module and the Btrfs boot filesystem is not C:.

The installer detects whether `/boot` is separate, including a Btrfs boot
filesystem, copies versioned files there, and installs two GRUB entries:
protected disk and persistent disk. It does not partition or format a disk. A prebuilt USB image can be supplied
with `--image=/path/to/retroos_grub_module_usb.img`; preparation then needs no Bazel
build. The Linux `/` filesystem is used only for discovery. RetroOS cannot
mount Btrfs yet; with no supported physical root it uses the RAM module for
its own `/` and C:.

## Manual GRUB deployment

Use this when GRUB is already installed and you want to choose the kernel and
base files yourself. The kernel and base image must come from the same build.
The base image holds `C:\RETROOS`, startup defaults, and a RAM fallback C:.
It is a GRUB Multiboot module, not a partition to extract onto the disk.

Build `//:grub_module_usb` and copy the selected version from `/boot/retroos/releases/<version>/` and both
INI files from `/boot/retroos/`
to a directory on a filesystem GRUB can read:

```text
kernel.elf
retroos-base.img.gz
BOOT.INI                  # bundle backing and mounts
RETROOS.INI               # editable user settings
retroos-showcase.img.gz       # optional showcase content
```

The image is also distributed as `retroos_grub_module_usb.img`. On Linux,
replace `VERSION` with the selected release directory and copy from the first
FAT32 partition with mtools:

```sh
mkdir -p /tmp/retroos-manual
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/releases/VERSION/kernel.elf /tmp/retroos-manual/
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/releases/VERSION/retroos-base.img.gz /tmp/retroos-manual/
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/BOOT.INI /tmp/retroos-manual/
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/RETROOS.INI /tmp/retroos-manual/
sudo mkdir -p /boot/retroos/manual
sudo cp /tmp/retroos-manual/* /boot/retroos/manual/
findmnt -no UUID --target /boot/retroos/manual
```

Keep the kernel and module images together when upgrading. If `/boot`
is a separate filesystem, GRUB paths start at that filesystem's root; the
example's `/boot/retroos/manual/` becomes `/retroos/manual/`.

Choose physical filesystems with `lsblk -o NAME,FSTYPE,UUID,MOUNTPOINTS`.
Copy [etc/BOOT.INI](etc/BOOT.INI) and [etc/RETROOS.INI](etc/RETROOS.INI)
alongside the kernel, replace the BOOT.INI session mount with your UUID mounts, and set their paths and access modes.
A FAT C: normally uses `path=/home/retroos`, `drive=C`, and `subdir=/`.
An ext4 C: can use `subdir=/home/retroos` with a matching `grant` directory.
The base module supplies `C:\RETROOS`, `C:\DN`, and `/bin` independently.
For persistent DN settings, explicitly mount a writable directory at the
C: namespace's `DN` path; the default bundled DN stores changes in RAM.
`C:\TEMP` is always RAM-backed.

`BOOT_FS_UUID` below is the UUID of the filesystem containing the kernel,
base image and INI. Physical data UUIDs belong in the INI.
Add this entry to GRUB's custom configuration, adjusting the paths if needed.
On Debian or Ubuntu, use `/etc/grub.d/40_custom` and run
`sudo update-grub`; on other distributions, regenerate `grub.cfg` with the
distribution's GRUB command. `grub-script-check` can check the entry first.

```grub
menuentry "RetroOS (manual, protected disk)" {
    insmod multiboot2
    insmod gzio
    search --no-floppy --fs-uuid --set=root BOOT_FS_UUID
    multiboot2 /boot/retroos/manual/kernel.elf ram-overlay
    if [ "$grub_platform" = "pc" ]; then
        set gfxpayload=text
    else
        insmod all_video
        set gfxmode=auto
        set gfxpayload=auto
    fi
    module2 /boot/retroos/manual/retroos-base.img.gz retroos.mount=/
    module2 /boot/retroos/manual/BOOT.INI retroos.config=boot
    module2 /boot/retroos/manual/RETROOS.INI retroos.config=ini
    # Optional showcase content, separate from physical game directories:
    # module2 /boot/retroos/manual/retroos-showcase.img.gz retroos.mount=/showcase
    boot
}
```

The example starts with physical writes protected. Remove `ram-overlay` to
persist writes on mounts configured `access=rw`. For a boot log that stays
on screen, add `boot-log-only`. Missing or ambiguous data UUIDs produce a
diagnostic and stop boot; no other partition is selected.
Unlisted physical filesystems remain unmounted. RetroOS does not read USB
mass storage after GRUB hands off.

## Mount setup and file images

F12 → Disk → Mnt lists detected FAT/ext4 partitions and their UUIDs. Use
Left/Right on the drive and access rows to stage choices. Select an export
destination, then **Export RETROOS.INI**. The export follows the destination's
active write permissions and the Protected Disk setting. Copy the exported
file onto the GRUB boot medium from another OS, next to the base image, and
load it with `retroos.config=ini`. Staging does not change active mounts.

An image on a mounted filesystem can itself supply a drive without copying:

```ini
[mount "linux"]
source=UUID=<ext4-filesystem-UUID>
path=/
access=rw
grant=/home/priv-gerben

[mount "data"]
source=file:/home/priv-gerben/project/RetroOS/build/data.bin
partition=1
path=/home/retroos
drive=C
access=rw

[mount "cd"]
source=file:/home/priv-gerben/game.iso
format=iso9660
path=/cdrom
drive=D
access=ro
```

Image dependencies determine mount order. `partition` is numbered from 1;
raw filesystem images need no partition selector. With multiple supported
partitions, select one explicitly. File images currently must be smaller
than 4 GiB, matching the VFS file-offset limit. ISO9660 is read-only.
`access=ram` overlays a disk or image with session writes. `access=ro`
rejects write opens and mutations. Bundle content always has a RAM overlay,
so applications can open bundled DLLs or settings for writing safely.

## Legacy installer for a Linux ext4 root

The installer uses the existing GRUB and ext4 root. It does not repartition the
machine or use emulator image files. `/home/retroos` is the persistent DOS C:.

Run the build/preparation as your normal user, then install the prepared release:

```sh
tools/install_kernel.sh --prepare
# Review build/machine-install/<release>/grub.cfg
sudo tools/install_kernel.sh
```

Preparation builds one `//:machine_boot_tar` containing the matching kernel,
symbols, COMMAND.COM, SHELL.ELF, and DN program/resources. Installation puts that
release under `/boot/retroos/releases/<release>/`, installs managed entries in
`/etc/grub.d/41_retroos`, and runs `update-grub`. No reboot is performed. Previous
releases and unrelated GRUB entries remain. The obsolete RetroOS entries are
backed up and replaced by managed entries named
**RetroOS (current, persistent)** and **RetroOS (current, protected disk)**.

Both disk-protection entries use the same video policy. When GRUB boots through
legacy BIOS (`grub_platform=pc`), it hands over text mode (`gfxpayload=text`),
so RetroOS uses native BIOS video and hardware VGA, including planar/Mode X.
When GRUB boots through UEFI, it keeps the GOP framebuffer and RetroOS uses
its substitute BIOS and software VGA rendering. RetroOS selects this path from
the display handoff, not by searching memory for a BIOS ROM. Custom GRUB entries
should use the same policy: forcing a linear framebuffer on BIOS selects the
software rendering path too.

Select the firmware boot mode before entering GRUB, using the machine's
firmware setup or boot-device menu (the key and entry names vary by manufacturer).
A UEFI entry loads GRUB's EFI executable and reports `grub_platform=efi`.
A legacy entry starts the disk's BIOS bootloader and reports `grub_platform=pc`.

To use native BIOS video, enable Legacy/CSM if supported and select the legacy
boot entry. The disk must also have BIOS GRUB installed: enabling CSM alone
does not install a BIOS bootloader, and selecting a UEFI entry still uses GOP.
On UEFI-only machines, RetroOS uses its substitute BIOS and software rendering
to support DOS applications. The RetroOS installer adds menu entries to the
existing GRUB; it does not install another firmware variant or enable CSM.
Choosing persistent versus protected inside GRUB only changes disk writes.

After updating RetroOS's installer, rerun preparation and installation to apply
the generated video policy to an existing machine's GRUB entries.

The directory installer locates its matched release using Multiboot arguments.
The release's `RETROOS/RETROOS.INI` selects Linux `/` and DOS `C:` by UUID,
with writes granted to the chosen C: directory. The module installer supplies
that same policy as a GRUB configuration module.

There is one configuration format: `RETROOS.INI`. Startup arguments go in
`[system] start=`, regional settings in `[locale]`, and guest environment
variables in `[environment]`. `--cmd` and `[environment] TEST=` override
normal startup for command execution and tests.

The boot bundle supplies `C:\RETROOS`, `C:\DN`, and `/bin` as writable RAM
content. When a Linux filesystem supplies `/`, its `/bin` and `/usr/bin` are used.
Bundled BusyBox serves the RAM root, or an explicit bundle mount at `/bin`.

Application settings stay with the application unless its own
configuration selects another directory. To persist application settings,
configure an explicit writable directory mount. `C:\TEMP` is RAM-backed.

For a direct hosted C: directory, `tools/install_boot_dir.sh /path/to/c-root`
installs the same flat bundle layout and `RETROOS/RETROOS.INI`.

## Disk writes and `ram-overlay`

Mounts configured `access=rw` persist writes. The VM launcher generates rw
mounts for its explicitly attached data disk. The default standalone bundle
uses RAM and leaves physical partitions unmounted.

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

The installed-machine entries select the ext4 filesystem by UUID. `C:` is
`/home/retroos` on that filesystem. INI layouts mount only their listed sources. Without `ram-overlay`,
permitted writes persist on the selected filesystem.

What it can and cannot reach:

- **Cannot**, structurally: the partition table, any unselected partition,
  firmware. A separate EFI System Partition stays read-only unless selected
  as the root itself. Every write
  goes through `Volume::write`, which is volume-relative and bounds-checked, so
  a filesystem cannot address past its own extent.
- **Can**: the contents of that one filesystem — which includes `/boot`. A bug
  in the ext4 write path could therefore leave Linux unbootable until you fsck
  it from a live USB. Recoverable, not catastrophic, but plan for it.

A second gate limits ordinary ext4 file writes: a file is writable only if its group
matches the `C:`-root's group **and** it is group-writable (`chgrp retroos` +
`chmod g+w`). FAT has no such ownership gate. That bounds deliberate ext4
writes; it does not bound a metadata bug.

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

## Booting GRUB Multiboot module images

For a USB boot, build `//:grub_module_usb` and write
`bazel-bin/retroos_grub_module_usb.img` to the whole stick. It has an ordinary
MBR with one FAT32 EFI partition; the editable menu is
`/boot/grub/grub.cfg` on partition 1. The GRUB menu contains protected
and persistent disk choices for the base-plus-games image, plus a base-only
submenu with the same choices for framebuffer video (GOP on UEFI,
VBE on BIOS). BIOS boots also offer native BIOS VGA entries, selected by
default; the framebuffer entries explicitly select software VGA rendering.
UEFI boots default to GOP. Disk protection (`ram-overlay`) is the default in
both firmware modes. To persist changes, configure rw data mounts in the INI
and select persistent disk. The module artifacts are raw ext4
images, not partitioned disks; GRUB expands the reproducible gzip files before
the Multiboot handoff:

```text
multiboot /boot/kernel.elf
module /boot/retroos-base.img.gz retroos.mount=/
module /boot/retroos-showcase.img.gz retroos.mount=/showcase
boot
```

Filesystem modules use `retroos.mount=<absolute-vfs-path>` and replacement
mounts. Raw FAT12/16/32 images are also accepted. Plain-text configuration uses
`retroos.config=ini`. The base module supplies system files, DN, BusyBox and the
bundled RETROOS.INI. Module filesystems have writable RAM overlays; physical
filesystems are selected explicitly by the INI and follow its access modes.
Optional game modules remain separate even with a physical C:.
Unlisted physical filesystems remain unmounted.

Module images remain resident in the physical RAM where GRUB loaded them, but
they are not permanently mapped into a size-matched kernel virtual window.
Reads and writes use a reusable 64 KiB physical aperture immediately below the
framebuffer. Legacy 32-bit paging and PAE both support module access; available
physical RAM and the Multiboot address format remain the practical limits.
Boot the USB image through QEMU's USB controller, for example:

```sh
bazelisk build //:grub_module_usb
qemu-system-i386 -m 512 -device qemu-xhci,id=usb \
  -drive if=none,id=stick,file=bazel-bin/retroos_grub_module_usb.img,format=raw,snapshot=on \
  -device usb-storage,bus=usb.0,drive=stick,bootindex=1
```

## FAT roots

GRUB loads `kernel.elf` as usual. The kernel probes filesystem contents and
accepts FAT12/16/32 partitions, unpartitioned FAT media, and raw FAT Multiboot
modules. On a selected FAT root, `C:` maps to the volume root: put the DOS
system files in `/RETROOS` (`C:\RETROOS`), alongside the partition's existing
Windows/DOS files and games. No `/home/retroos` directory is needed on FAT.
On a Unix/ext4 root, `C:` remains `/home/retroos` even if that directory is
missing; it never silently falls back to `/`. Explicit C-drive overrides
still take precedence. FAT root modules use the same mapping as physical FAT.

Preserve the exact spelling of the VFS startup paths, including `RETROOS`.
When multiple filesystems are present, `/etc` plus `/usr` take precedence,
followed by a filesystem containing its DOS home (top-level `RETROOS` for FAT).
This keeps a separate EFI system partition from displacing an installed DOS
root. GRUB's kernel location does not override this root-selection policy.

A selected physical FAT root is writable; FAT has no Unix ownership/group
grant. Use `ram-overlay` to keep physical writes volatile. FAT modules write
directly to their volatile RAM, and secondary disk mounts remain read-only.

FAT directory entries expose both the long name and the stored 8.3 alias.
VFS uses exact names on every storage format; DOS case folding belongs to
DosFS. DosFS preserves FAT's alias; ext4 entries receive generated aliases.
DOS applications can use the INT 21h/AH=71h LFN services on either format;
see [DOS LFN support](test/dos/lfnprobe/README.md) for the implemented calls
and remaining limits.

Regression test: `python3 test/grub_fat.py` (GRUB, QEMU, gcc, dosfstools,
and mtools required).

## Booting from a GRUB hard disk (`//:image_grub`)

This is for a *self-contained* disk — one you write to a spare drive or a USB
stick and boot without touching that machine's GRUB, and what QEMU/Bochs/86Box
boot. Installing on a machine that already has GRUB does not need it; use the
one-file install above. `bazelisk build //:image_grub` produces a disk with
**no RetroOS bootloader**:
GRUB's `boot.img` in sector 0, `core.img` in the MBR gap, and a single ext4
partition holding `/boot/kernel.elf`, `/boot/grub/grub.cfg` and the usual
content. To test that standalone legacy image directly, use
`qemu-system-i386 -drive file=bazel-bin/image_grub.bin,format=raw,snapshot=on`.
Normal `./run.sh qemu` launches use the shared boot/data layout.

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
partitions and applies BOOT.INI to FAT/ext4 volumes and file images. The
bundle supplies writable RAM views of `C:\DN`, `C:\RETROOS` and `/bin`. Writes
on rw data mounts persist unless `ram-overlay` was passed. Disk boots require both INI modules; unlisted physical partitions stay unmounted.

Keyboard: the i8042 path (most laptops expose one via EC emulation) feeds
the personality BIOS's INT 09. Machines with USB-only input are handled by the
xHCI USB-HID boot-keyboard driver, which works on real full-speed hardware
(verified on a Razer Blade — SkyRoads played from USB keyboard input).

Caveats on real hardware (vs the `run_uefi.sh` mock):
- fbcon accepts packed 16/24/32bpp direct-RGB framebuffers and converts its pixels using the
  channel positions and widths reported by GRUB.
- If boot stops with white bars at the top of an otherwise black screen, count
  the bars: one means unsupported framebuffer type, two means unsupported RGB
  layout, three means pitch smaller than the pixel row, and four means the mode
  is below the 640x400 boot console minimum. Each bar is four scanlines tall,
  followed by four black scanlines.
- ACPI shutdown is wired for QEMU/Bochs/VirtualBox and PIIX4 boards; on a
  modern laptop it falls through to a halt, so power off by holding the button.
- An MBR- or GPT-partitioned disk containing ext4 or FAT can become the RetroOS root,
  and its files appear in DN. Whether changes reach the medium is the
  `ram-overlay` question above.
- Returning to Linux after a RetroOS session has been seen to add ~34 s to the
  next boot, stalling just before the root mount. The filesystem is clean when
  it gets there (no journal recovery), so this looks like a device-handoff
  problem — RetroOS parks the HDA codec on the way out but not storage or USB.
  Under investigation.
