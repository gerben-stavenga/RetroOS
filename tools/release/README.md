# RetroOS release

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
For virt-manager, use i440FX with both disks attached as IDE, boot disk first.
Give the guest at least 128 MiB RAM. The included launcher uses 512 MiB for UEFI.

When upgrading, extract the new release separately and copy only its `boot.img`
over the old boot image while the VM is stopped. Keep your existing `data.img`.
Never overwrite a persistent data disk with a fresh release seed. Data images
are intentionally public-only: no proprietary games or toolchains are bundled.

## Physical machine: retroos-machine.tar.gz

This bundle uses an existing Linux GRUB installation and ext4 root. The boot
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
its temporary files live in C:\TEMP. Existing BOOT/DN or RETROOS/DN state is
copied into the new location without overwriting existing settings. CONFIG.SYS
selects DNSWP=C:\TEMP, TEMP=C:\TEMP, and DN=C:\CONFIG\DN in that order.

The kernel supports legacy IDE, AHCI/SATA, and NVMe storage; USB storage is not supported.
Bootloader support for a disk does not imply the kernel can access that disk.
