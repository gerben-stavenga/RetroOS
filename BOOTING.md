# Booting RetroOS with GRUB

There are two boot arrangements on a physical machine: boot the standalone
USB image, or add RetroOS to an existing GRUB installation. For existing
GRUB, the installer below finds disks and UUIDs with Linux, stages the matching
kernel and RAM base module, and generates the GRUB entries. Manual deployment
uses the same boot path. The older ext4 installer later in this document
remains available for machines that keep the runtime on their Linux root.

## Install into an existing GRUB menu

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
to RetroOS. The default is `/home/retroos` on the selected ext4 volume.
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
`retroos-base.img.gz` under Linux `/boot/retroos/releases/...`; GRUB reads
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

Build `//:grub_module_usb` and copy these files from its `/boot` directory
to a directory on a filesystem GRUB can read:

```text
kernel.elf
retroos-base.img.gz
retroos-games.img.gz       # optional
```

The image is also distributed as `retroos_grub_module_usb.img`. On Linux,
copy from its first FAT32 partition with mtools like this:

```sh
mkdir -p /tmp/retroos-manual
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/kernel.elf /tmp/retroos-manual/
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos-base.img.gz /tmp/retroos-manual/
sudo mkdir -p /boot/retroos/manual
sudo cp /tmp/retroos-manual/* /boot/retroos/manual/
findmnt -no UUID --target /boot/retroos/manual
```

Keep the kernel and module images together when upgrading. If `/boot`
is a separate filesystem, GRUB paths start at that filesystem's root; the
example's `/boot/retroos/manual/` becomes `/retroos/manual/`.

Choose the physical C: volume before editing GRUB. `lsblk -o NAME,FSTYPE,UUID,MOUNTPOINTS`
shows its filesystem UUID. For FAT, C: is the volume root; existing games and
other files stay there. For ext4, create `/home/retroos` on that volume and
put data there. The base module supplies `C:\RETROOS` and default CONFIG files,
so the data volume does not need a copy of the kernel or runtime. Use the
chosen volume's UUID for `C_UUID` below. This selects C: even when it is on a
second AHCI controller or several other disks have `CONFIG` or `GAMES`.
To keep settings between boots, put `CONFIG/CONFIG.SYS` and the `CONFIG/DN`
templates on that volume (`etc/CONFIG.SYS` and the `DN.EDT`, `DN.EXT`,
`DN.HGL`, `DN.MNU`, `DN.VWR`, `DN.XRN` files in `apps-boot/dn/`; the machine
release also carries the templates). Missing CONFIG
files use session copies of the base image's defaults, so edits to those
copies disappear on reboot. Keep `TEMP` empty: RetroOS maps it to RAM.

`BOOT_FS_UUID`, `C_UUID`, and the optional `EXT4_UUID` below are placeholders,
not shell or GRUB variables. Replace them with the UUID values printed by
`findmnt` and `lsblk`; do not leave their names in the installed entry.
Add this entry to GRUB's custom configuration, adjusting the paths if needed.
On Debian or Ubuntu, use `/etc/grub.d/40_custom` and run
`sudo update-grub`; on other distributions, regenerate `grub.cfg` with the
distribution's GRUB command. `grub-script-check` can check the entry first.

```grub
menuentry "RetroOS (manual, protected disk)" {
    insmod multiboot2
    insmod gzio
    search --no-floppy --fs-uuid --set=root BOOT_FS_UUID
    multiboot2 /boot/retroos/manual/kernel.elf ram-overlay retroos.c-uuid=C_UUID
    if [ "$grub_platform" = "pc" ]; then
        set gfxpayload=text
    else
        insmod all_video
        set gfxmode=auto
        set gfxpayload=auto
    fi
    module2 /boot/retroos/manual/retroos-base.img.gz retroos.mount=/
    # Optional, for games when C: is backed by RAM:
    # module2 /boot/retroos/manual/retroos-games.img.gz retroos.mount=/home/retroos/GAMES
    boot
}
```

The example starts with physical writes protected. Once C: is confirmed in the
boot log, remove `ram-overlay` to persist changes there. For a boot log that
stays on screen, add `boot-log-only` to the `multiboot2` line. A missing or
duplicate `C_UUID` stops boot rather than selecting another disk. Remove the
`retroos.c-uuid` argument to use automatic selection; with no physical data
volume, the base module supplies a RAM-backed C:. A separate GRUB boot
filesystem does not select C:. The kernel currently recognizes IDE, AHCI and
NVMe disks, including disks on multiple controllers, but does not read USB
mass storage after GRUB hands off.
If Linux `/` should come from a particular ext4 volume, add
`retroos.root=EXT4_UUID` to the same `multiboot2` line; it selects `/`
independently of `retroos.c-uuid`.

## Installer for a Linux ext4 root

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

The generated Multiboot arguments explicitly specify:

```text
retroos.root=<ext4-filesystem-UUID>
retroos.c-root=/home/retroos
retroos.runtime=/boot/retroos/releases/<release>/RETROOS
```

The UUID selects the filesystem independently of device order or directory
markers. Missing/duplicate UUIDs fail instead of choosing another writable disk.
The runtime directory is exposed read-only at `C:\RETROOS`; this is a replacement
binding, not a union. The current installer requires `/boot` and C: to reside
on the same ext4 filesystem as Linux `/`, as they do on this laptop.

| Guest path | Location/lifetime |
| --- | --- |
| `C:\RETROOS` | Matching boot runtime, read-only |
| `C:\CONFIG\DN` | Persistent DN settings, history, desktop, menus |
| `C:\CONFIG\LOADFIX.CFG` | Persistent COMMAND.COM launch policy |
| `C:\TEMP` | RAM-only DN swap/flag/temporary files |
| `C:\CONFIG\CONFIG.SYS` | Persistent startup command and environment |

All boot sources use the same composition. The selected ext4 `/home/retroos`
or FAT root supplies `C:`. A RAM boot image, EFI/FAT boot volume, or installed
release supplies read-only `C:\RETROOS` and optional `CONFIG` defaults.
Disk config files take precedence by filename; missing files come from a
writable RAM copy of the boot defaults. Changes to those fallback files last
for the session; files already on the data disk follow its persistent or
`ram-overlay` policy. Boot defaults are never overwritten.
`C:\TEMP` is always empty at boot and RAM-backed. TEMP and fallback CONFIG
share a sparse 32 MiB session filesystem, allocating memory as written.

`C:\CONFIG\CONFIG.SYS` selects the startup program with
`START=C:\RETROOS\DN\DN.COM`. Set another executable and optional arguments
(for example `START=C:\RETROOS\COMMAND.COM /P`) to choose a different shell.
The startup program restarts when it exits; `--cmd` and `TEST=` take precedence
and still shut down after completion. Relative startup paths are relative to C:.
The old root `CONFIG.SYS` is read only when the new file is absent. Migration
copies existing settings to the new location and preserves a custom `START=`.

DN already supports separate paths; no binary patch is needed. The config sets
`DNSWP=C:\TEMP`, `TEMP=C:\TEMP`, then `DN=C:\CONFIG\DN`, in that order. DN.COM
uses the first DNSWP/DN variable for its flag file. DN.PRG uses DN for settings
and history, while overlays, language/dialog resources and help remain next to
the executable. See [the DN 1.51 sources](https://github.com/maximmasiutin/Dos-Navigator)
(`STARTUP.PAS`, `DN.ASM`, `DNUTIL.PAS`, `DNAPP.PAS`).

Installation backs up CONFIG.SYS and copies old `RETROOS/DN` or `BOOT/DN` state
without deleting it or replacing existing `CONFIG/DN` files. Defaults are seeded
only when absent. To migrate an existing emulator disk, stop its emulator first:

```sh
python3 tools/migrate_dn_state.py --image build/data.bin
```

For a direct/hosted C: directory, `tools/install_boot_dir.sh /path/to/c-root`
refreshes the runtime and migrates state. This is distinct from physical-machine
installation, which keeps runtime files under `/boot/retroos`.

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

The installed-machine entries select the ext4 filesystem by UUID. `C:` is
`/home/retroos` on that filesystem. Emulator/legacy entries without an explicit
UUID still use directory evidence to select volumes. Without `ram-overlay`,
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
MBR with FAT32 EFI and data partitions; the editable menu is
`/boot/grub/grub.cfg` on partition 1. The GRUB menu contains protected
and persistent disk choices for the base-plus-games image, plus a base-only
submenu with the same choices for framebuffer video (GOP on UEFI,
VBE on BIOS). BIOS boots also offer native BIOS VGA entries, selected by
default; the framebuffer entries explicitly select software VGA rendering.
UEFI boots default to GOP. Disk protection (`ram-overlay`) is the default in
both firmware modes; select persistent disk to keep changes on the data disk. The module artifacts are raw ext4
images, not partitioned disks; GRUB expands the reproducible gzip files before
the Multiboot handoff:

```text
multiboot /boot/kernel.elf
module /boot/retroos-base.img.gz retroos.mount=/
module /boot/retroos-games.img.gz retroos.mount=/home/retroos/GAMES
boot
```

The only module declaration is `retroos.mount=<absolute-vfs-path>`. Modules
use replacement mounts, and the boot log derives the displayed volume identity
from that path. Raw FAT12/16/32 images are accepted through exactly the same
`retroos.mount=` declaration; there is no filesystem-type boot option.
Each module is writable directly in its resident RAM. The base module supplies
boot runtime and config defaults; physical ext4/FAT data volumes participate
in the normal C: selection and follow the disk-write policy. Without a data
disk, the base module supplies C: too. Extra modules such as GAMES mount only
for this RAM-backed C:, so they cannot hide games on the selected data disk.
Unselected physical filesystems remain read-only at `/disk1`, `/disk2`, and so on.

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
partitions and mounts the selected ext4 or FAT root. DN and COMMAND.COM come from the read-only runtime binding at
`C:\RETROOS`. Block writes reach the physical device
unless `ram-overlay` was passed.

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
