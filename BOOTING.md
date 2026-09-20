# Booting RetroOS on an installed Linux machine

The installer uses the existing GRUB and ext4 root. It does not repartition the
machine or use emulator image files. `/home/retroos` is the persistent DOS C:.

## Install

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
| `C:\TEMP` | Writable DN swap/flag/temporary files |
| `C:\CONFIG.SYS` | Persistent startup environment |

DN already supports separate paths; no binary patch is needed. CONFIG.SYS sets
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

For a diskless boot, build `//:grub_module_iso`. Its GRUB menu contains a
base-only entry and a base-plus-games entry. The module artifacts are raw ext4
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
Each module has its own volatile RAM overlay; physical ext4/FAT
fallback filesystems remain read-only at `/disk1`, `/disk2`, and so on.

Module images remain resident in the physical RAM where GRUB loaded them, but
they are not permanently mapped into a size-matched kernel virtual window.
Reads use a reusable 64 KiB physical aperture immediately below the
framebuffer. Legacy 32-bit paging and PAE both support module reads; available
physical RAM and the Multiboot address format remain the practical limits.
Boot directly with QEMU, for example:

```sh
bazelisk build //:grub_module_iso
qemu-system-i386 -cdrom bazel-bin/retroos_grub_module.iso
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
grant. Use `ram-overlay` to keep physical writes volatile. FAT modules always
use volatile overlays, and secondary disk mounts remain read-only.

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
- fbcon accepts 32bpp direct-RGB framebuffers and converts its pixels using the
  channel positions and widths reported by GRUB.
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
