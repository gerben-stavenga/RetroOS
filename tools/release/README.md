# RetroOS release

Release builds retain panic diagnostics. Kernel panics display the message,
source location, and stack trace on the console and mirror them to the log.

## USB / CD boot: retroos_grub_module.iso

This hybrid ISO boots through either legacy BIOS or UEFI. Write the ISO as a
whole-device image using your USB imaging tool (writing it erases that USB
stick), or attach it as a virtual CD. Merely copying the ISO onto a FAT drive
does not make the drive bootable. Start with 256 MiB RAM; 512 MiB is recommended
for the base-plus-games menu. The base-only submenu uses less RAM.

GRUB loads the kernel and filesystem images into RAM before handing control to
RetroOS. This works for USB boot even though RetroOS itself has no USB
mass-storage driver. The USB stick is not a persistence destination. Firmware
chooses BIOS or UEFI before GRUB starts; GRUB cannot change that firmware mode.

To add RetroOS to an existing GRUB menu by hand, copy `/boot/kernel.elf` and
`/boot/retroos-base.img.gz` from the ISO onto a GRUB-readable filesystem. They
must come from the same ISO. Add a GRUB `multiboot2` entry for the kernel and
`module2 ... retroos.mount=/` for the base image. Set `retroos.c-uuid=` to the
filesystem UUID of the intended FAT or ext4 data volume when several disks are
present. The full example, including the firmware video policy and disk
protection, is in
[BOOTING.md](https://github.com/gerben-stavenga/RetroOS/blob/master/BOOTING.md#manual-grub-deployment).

The machine bundle also has an installer for this ISO. Download both files
from the same release into one directory, then run:

```sh
mkdir retroos-install
tar -xzf retroos-machine.tar.gz -C retroos-install
cd retroos-install
./install.sh --module --prepare --iso="$PWD/../retroos_grub_module.iso"
cat build/grub-module-install/*/grub.cfg
sudo ./install.sh --module
```

Preparation discovers GRUB's boot filesystem and supported data volumes. If
several volumes qualify for C:, rerun the preparation command with
`--c-uuid=<UUID>`. Use `--c-ram` to select the RAM module for C: explicitly.
An ext4 C: volume may be unmounted during preparation; installation mounts it
temporarily to ensure `home/retroos` exists, then unmounts it.
Use `--c-dir=/path/on/volume` during preparation to choose another directory
on that ext4 volume; `/home/retroos` is the default.
On a Btrfs Linux root, RAM C: is the default because RetroOS does not support
Btrfs. The module supplies `C:\RETROOS` from RAM in every case.

If `/boot` is on Btrfs and a separate FAT32 data partition should be C:,
replace the preparation line above with:

```sh
lsblk -o NAME,FSTYPE,UUID,PARTTYPE,MOUNTPOINTS
./install.sh --module --prepare --iso="$PWD/../retroos_grub_module.iso" --c-uuid=ABCD-1234
```

Use the FAT32 data partition's UUID in place of `ABCD-1234`; do not choose the
EFI System Partition. GRUB reads the kernel and base module from
`/boot/retroos/releases/...` on Btrfs. After GRUB hands off, RetroOS uses the
FAT32 partition for C: data and the RAM module for `C:\RETROOS`; RetroOS does
not need to read Btrfs.

The default entry protects physical disks: reads use their existing contents,
while writes are diverted to RAM and disappear on reboot. Choose **persistent
disk** to write to the selected data disk. On BIOS, each choice is available
with native BIOS VGA or a VBE framebuffer; on UEFI it uses GOP. Both framebuffer
choices use software VGA rendering. VBE is the BIOS equivalent of this display
path, not GOP running under BIOS.

## The same C: layout across boot sources

A selected ext4 `/home/retroos` or FAT data volume supplies C:. With no data
volume, the RAM image supplies C: instead. Booting from a USB RAM image no
longer relegates the data disk to a read-only `/disk1` mount. Unselected extra
disks still mount read-only there.

- `C:\RETROOS` comes from the matching RAM image, EFI/FAT boot volume, or installed
  release, and is read-only.
- `C:\CONFIG` prefers files on the data disk. Missing files fall back to editable
  RAM copies of the boot source's CONFIG defaults. Edits to fallback files last
  for the session; existing data-disk files follow the chosen disk-write policy.
- `C:\TEMP` is always in RAM and starts empty. TEMP and fallback CONFIG share a
  sparse 32 MiB filesystem; memory is allocated as written.

The boot source itself is not changed by config edits. RAM-backed game modules
are used with RAM-backed C:; they do not cover games on a selected data disk.

## Virtual machine: retroos-vm.tar.gz

Extract into a new directory and run `./run.sh`. Requires Linux, QEMU x86,
`flock`, and an SDL display. No Bazel or Rust toolchain is needed.

- `boot.img`: matched kernel/runtime; a temporary copy is used each session.
- `data.img`: public initial data, shared by every launch; changes persist here.
- `./run.sh --firmware uefi`: Q35 with NVMe data and an added IDE boot controller;
  requires OVMF (default paths `/usr/share/OVMF/*_4M.fd`).
- `./run.sh --firmware uefi --hd ahci`: use the built-in SATA/AHCI controller
  for the data disk; `--hd ata|ahci|nvme` selects its controller.
- `./run.sh --headless --sound none --cmd 'TESTS/HELLO.COM'`: smoke test.

Default BIOS mode uses i440FX with IDE disks. UEFI defaults to NVMe data storage. SPICE/VNC is independent of disk-controller selection.

For UniPCemu on Linux, install or build its executable, then run
`./run.sh --backend unipcemu` (set `UNIPCEMU_BIN=/path/to/UniPCemu` if it is
not on `PATH`). This uses a BIOS/Pentium i430fx machine with the same
disposable boot image and persistent data image as QEMU. UniPCemu stores its
session settings under the launcher's temporary directory and reads the disks
through its `UNIPCEMU` data directory. It supports `--sound sb|none`, BIOS,
ATA, and `--arch 686` in this launcher. Its `sb` choice uses Sound Blaster Pro 2
at IRQ 7. UniPCemu must be installed separately; it is not bundled. See its
[command line documentation](https://bitbucket.org/superfury/unipcemu/src/default/manual/Command-line%20parameters.md)
and [disk image documentation](https://bitbucket.org/superfury/unipcemu/src/default/manual/Disk%20images.rst).

For virt-manager, use i440FX with both disks attached as IDE, boot disk first.
Give the guest at least 128 MiB RAM. The included launcher uses 512 MiB for UEFI.

When upgrading, extract the new release separately and copy only its `boot.img`
over the old boot image while the VM is stopped. Keep your existing `data.img`.
Never overwrite a persistent data disk with a fresh release seed. Data images use the repository's public content targets; the optional
apps-proprietary collection is not bundled.

## Physical machine: retroos-machine.tar.gz

This bundle automates the existing-GRUB setup for a Linux ext4 root. The boot
runtime and `/home/retroos` must be on that root filesystem; a separate `/boot`
partition is not supported by this installer yet. It does not repartition disks.

For a new installation, first create the writable C: directory (as your ordinary
user, invoking sudo only for these setup commands):

```sh
getent group retroos >/dev/null || sudo groupadd --system retroos
sudo install -d -m 2775 -o "$(id -un)" -g retroos /home/retroos
```

Extract the release, then prepare as your normal user and install as root:

```sh
./install.sh --prepare
# Review build/machine-install/<release>/grub.cfg
sudo ./install.sh
```

Requires Python 3.12+, `findmnt`, and the installed GRUB tools. No compilation
is performed. The installer places a matched release under `/boot/retroos`,
updates managed GRUB entries, and retains old files and configuration backups.
Choose **RetroOS (current, persistent)** for normal use; the protected entry
uses a volatile RAM overlay. Installation does not reboot the machine.

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

C:\RETROOS is read-only runtime. DN settings/history live in C:\CONFIG\DN;
its temporary files live in RAM at C:\TEMP. Existing BOOT/DN or RETROOS/DN state is
copied into the new location without overwriting existing settings. C:\CONFIG\CONFIG.SYS selects the startup program with
START=C:\RETROOS\DN\DN.COM and optional arguments. It also selects DNSWP=C:\TEMP, TEMP=C:\TEMP, and DN=C:\CONFIG\DN in that order.

The kernel supports legacy IDE, AHCI/SATA, and NVMe storage; USB storage is not supported.
Bootloader support for a disk does not imply the kernel can access that disk.
