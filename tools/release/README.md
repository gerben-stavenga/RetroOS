# RetroOS release

Release builds retain panic diagnostics. Kernel panics display the message,
source location, and stack trace on the console and mirror them to the log.

For USB testing, use **`retroos_grub_module_usb.img`**. Its partition
table is conventional and its GRUB configuration can be edited on the stick.
For CD-ROM boot, including UniPCemu setups that cannot boot the USB image,
use **`retroos_grub_module.iso`**. It contains the same kernel, RAM modules,
and GRUB menu as the USB image.

## Editable USB boot: retroos_grub_module_usb.img

Use this image when you need to edit GRUB settings on a USB stick. It has a
fixed MBR with one 128 MiB FAT32 partition (type `0x0C`, so Windows can assign
it a drive letter). The menu is
`/boot/grub/grub.cfg`; the matching kernel and RAM modules are under `/boot`
on the same partition. `/boot/RETROOS.INI` is the editable mount, locale,
keyboard, sound and startup configuration; GRUB loads it before RetroOS
probes physical storage. Unlisted physical partitions remain unmounted.
The bundled DN and system files have writable RAM views.
Start with 256 MiB RAM; 512 MiB is recommended for the base-plus-games menu.

Write the IMG to the whole USB device with a disk imaging tool. This replaces
the device's current contents. On Linux, after identifying the device with
`lsblk`, the partition can be mounted as FAT32 and `boot/grub/grub.cfg` edited
directly. Windows can mount the FAT32 partition with a drive letter. No
partition resize is required for a GRUB configuration change. A machine's
firmware still chooses BIOS or UEFI before GRUB starts.

The default framebuffer entry keeps GRUB's automatic video mode on UEFI. If
that mode is below 640×400, try the menu's 1024×768 or 800×600 GOP entries.
Press `c` at this image's GRUB menu and run `videoinfo` to see its modes. For
a permanent default choice, change
`set framebuffer_payload=auto` in `boot/grub/grub.cfg` on partition 1 to a
listed mode such as `set framebuffer_payload=1024x768x32`. This image carries
its own GRUB; commands missing from a different GRUB installation do not
affect it.

RetroOS does not yet have a USB mass-storage driver. It loads the kernel and
RAM images from the stick through GRUB, but RetroOS itself cannot read or write
the USB partition after boot. A separate supported ATA, AHCI, or NVMe disk is
needed for persistent RetroOS data; the protected menu entry diverts its
writes to RAM.

## Small diagnostic USB image

`retroos-usb-diagnostic.zip` contains `retroos-usb-diagnostic.img`, a base-only
USB image for forum troubleshooting. Extract it and write the IMG to the whole
stick. It uses the same fixed MBR and editable GRUB menu as the full image;
the ZIP stays below the 5 MB attachment limit.

## Install into an existing GRUB menu from the USB image

The same USB image also supplies `/boot/kernel.elf` and
`/boot/retroos-base.img.gz` for an existing GRUB installation. They must come
from the same image. GRUB loads the kernel and RAM filesystem before handing
off to RetroOS, so the source image need not remain attached afterward.
The full manual entry, including firmware video policy and disk protection,
is in [BOOTING.md](https://github.com/gerben-stavenga/RetroOS/blob/master/BOOTING.md#manual-grub-deployment).

The machine bundle installer reads those files directly from partition 1 of
the USB image with `mcopy` (mtools). Download both release files into one
directory, then run:

```sh
mkdir retroos-install
tar -xzf retroos-machine.tar.gz -C retroos-install
cd retroos-install
./install.sh --module --prepare --image="$PWD/../retroos_grub_module_usb.img"
cat build/grub-module-install/*/grub.cfg
sudo ./install.sh --module
```

Preparation discovers GRUB's boot filesystem and supported data volumes. If
several volumes qualify for C:, rerun with `--c-uuid=<UUID>`. Use `--c-ram`
to select the RAM module for C: explicitly. An ext4 C: volume may be
unmounted during preparation; installation mounts it temporarily to ensure
`home/retroos` exists, then unmounts it. Use `--c-dir=/path/on/volume` to
choose another directory on that ext4 volume; `/home/retroos` is the default.
On a Btrfs Linux root, RAM C: is the default because RetroOS does not support
Btrfs. The module supplies `C:\RETROOS` from RAM in every case.

If `/boot` is on Btrfs and a separate FAT32 data partition should be C:,
prepare with the FAT32 data partition's UUID, not the EFI partition's:

```sh
lsblk -o NAME,FSTYPE,UUID,PARTTYPE,MOUNTPOINTS
./install.sh --module --prepare --image="$PWD/../retroos_grub_module_usb.img" --c-uuid=ABCD-1234
```

The default entry protects physical disks by diverting writes to RAM. Choose
**persistent disk** to keep writes on the selected data disk. On BIOS, the
menu offers native BIOS VGA and VBE framebuffer entries; on UEFI it uses GOP.
The framebuffer console accepts 640×400 or larger RGB modes. Four short bars
mean GRUB handed over a smaller mode. `videoinfo` lists the modes available
to GRUB.

## Filesystem layout

`RETROOS/RETROOS.INI` selects mounts by UUID or image path. Unlisted disks stay
unmounted. The VM launcher supplies a UUID profile for its attached data disk;
a standalone bundle defaults to a RAM session.

The bundle supplies `C:\RETROOS`, `C:\DN`, `C:\VC`, `C:\MC`, `C:\RC`, and `/bin` as writable RAM content.
When a Linux filesystem supplies `/`, its `/bin` and `/usr/bin` are used.
Bundled BusyBox serves the RAM root, or an explicit bundle mount at `/bin`.

`C:\TEMP` is RAM-backed and starts empty. Mount an application directory with
`access=rw` to persist its settings.

Optional packaged games are a separate `/games` module, normally `G:`.
They are not merged with games on physical disks.

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

For UniPCemu on Linux, install or build its executable and prepare a `ROM`
directory containing a motherboard BIOS ROM for its Pentium/i430fx machine,
such as `BIOSROM.i430fx.BIN`. The emulator and BIOS ROMs are not bundled.
Its internal BIOS cannot boot the Pentium selected by this launcher.
Run the prebuilt disk image with:

```sh
UNIPCEMU_ROM_DIR=/path/to/UniPCemu/ROM ./run.sh --backend unipcemu
```

For CD-ROM boot, download `retroos_grub_module.iso` alongside the VM bundle:

```sh
UNIPCEMU_ROM_DIR=/path/to/UniPCemu/ROM \
UNIPCEMU_ISO_IMAGE=/path/to/retroos_grub_module.iso \
./run.sh --backend unipcemu
```

This mounts the ISO as `cdrom0`, boots from CD-ROM, and attaches `data.img` as
the writable hard disk. To fill the desktop on a high-DPI Wayland display,
pass UniPCemu's `fullscreenwindow` argument after `--`:

```sh
UNIPCEMU_ROM_DIR=/path/to/UniPCemu/ROM \
UNIPCEMU_ISO_IMAGE=/path/to/retroos_grub_module.iso \
./run.sh --backend unipcemu -- fullscreenwindow
```

To try the GRUB module boot with ET4000/W32i video in UniPCemu, use the USB
image as its first virtual hard disk:

```sh
UNIPCEMU_ROM_DIR=/path/to/UniPCemu/ROM \
UNIPCEMU_USB_IMAGE=/path/to/retroos_grub_module_usb.img \
UNIPCEMU_VIDEO=et4000w32 ./run.sh --backend unipcemu
```

The default disk image boots as `boot.img`, with `data.img` as the second
virtual hard disk. `UNIPCEMU_VIDEO` defaults to `vga`; `et4000w32` selects UniPCemu's
ET4000/W32i emulation. The appropriate video option ROM, such as
`ET4000_W32.BIN`, can also be placed in the ROM directory. Set
`UNIPCEMU_BIN=/path/to/UniPCemu` if the executable is not on `PATH`.
The launcher writes CPU, clock, video, sound, and disk settings under
`[i430fxCMOS]`, as required by current UniPCemu. `UNIPCEMU_ARCH=i440fx`
selects `[i440fxCMOS]` and requires `BIOSROM.i440fx.BIN`. Superfury reports
an FPU emulation issue with the current i440fx BIOS, so i430fx remains the
default.
The launcher copies the ROM directory into temporary session storage and
does not modify the originals. UniPCemu may still require its BIOS setup to
detect disks; its `Set` button opens the emulator settings. The author's
report of text followed by a few green lines means his setup got as far as
RetroOS's video switch; these launcher settings alone do not establish the
cause of that display problem. A guest boot with this ROM configuration has
not yet been verified here.

See UniPCemu's [getting started guide](https://bitbucket.org/superfury/unipcemu/src/default/manual/Getting%20started.rst),
[settings and ROM filenames](https://bitbucket.org/superfury/unipcemu/src/default/manual/Settings%20menu.rst),
and [disk image guide](https://bitbucket.org/superfury/unipcemu/src/default/manual/Disk%20images.rst).

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

`RETROOS/RETROOS.INI` controls startup, locale, sound and mounts. The bundle
provides applications at `C:\DN`, `C:\VC`, `C:\MC`, and `C:\RC`,
system libraries under `C:\RETROOS`, and BusyBox under
`/bin`. Bundled files are writable RAM content; configure an explicit writable
directory mount to persist application settings. Temporary files are in RAM
at `C:\TEMP`.

The kernel supports legacy IDE, AHCI/SATA, and NVMe storage; USB storage is not supported.
Bootloader support for a disk does not imply the kernel can access that disk.
