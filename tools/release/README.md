# RetroOS release

## Virtual machine: retroos-vm.tar.gz

Extract into a new directory and run `./run.sh`. Requires Linux, QEMU x86,
`flock`, and an SDL display. No Bazel or Rust toolchain is needed.

- `boot.img`: matched kernel/runtime; a temporary copy is used each session.
- `data.img`: public initial data, shared by every launch; changes persist here.
- `./run.sh --firmware uefi`: Q35 with NVMe data and an added IDE boot controller;
  requires OVMF (default paths `/usr/share/OVMF/*_4M.fd`).
- `./run.sh --headless --sound none --cmd 'TESTS/HELLO.COM'`: smoke test.

Default BIOS mode uses i440FX with IDE disks. Q35's built-in SATA/AHCI controller
is not supported yet. SPICE/VNC is independent of disk-controller selection.
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

C:\RETROOS is read-only runtime. DN settings/history live in C:\CONFIG\DN;
its temporary files live in C:\TEMP. Existing BOOT/DN or RETROOS/DN state is
copied into the new location without overwriting existing settings. CONFIG.SYS
selects DNSWP=C:\TEMP, TEMP=C:\TEMP, and DN=C:\CONFIG\DN in that order.

The kernel supports legacy IDE and NVMe storage, not AHCI/SATA or USB storage.
Bootloader support for a disk does not imply the kernel can access that disk.
