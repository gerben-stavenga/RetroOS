# Changelog

Release versions describe the project's development milestones. DOS is the
primary target. Windows, OS/2 and Linux personalities remain experimental.

## [Unreleased]

## [0.8.0] - 2026-10-08

This is the first numbered RetroOS release. It records the current DOS-focused
baseline; it does not promise complete hardware or application compatibility.
Earlier downloads used the moving `retroos` tag.

### DOS and system support

- Real-mode DOS programs, protected-mode DOS extenders and DPMI clients.
- Per-process VGA state, task switching, emulated audio, and DOS memory services.
- BIOS and UEFI boot paths, GRUB RAM modules, and ATA, AHCI and NVMe storage.
- Matched boot runtime and system libraries, with writable settings in
  `C:\CONFIG` and temporary files in RAM at `C:\TEMP`.

### Recent additions and fixes

- Rat Commander on the Linux personality, packaged as
  `C:\RETROOS\RC\RC.EXE`. Its contents are a static x86-64 Linux ELF.
- Linux runtime support for shared threads, TLS, futex waits, eventfd, epoll,
  and timed I/O used by Rat Commander.
- DOS launches from Rat Commander use COMMAND.COM and the existing
  `LOADFIX.CFG` policies. Unix socket-pair support fixes error 22 during launch.
- One shared Linux terminal for a shell and its foreground program, alternate
  screen restoration, and terminal redraws kept out of KLOG.
- FAT `.EXE` and `.COM` files are exposed as executable to Linux clients.
- Navigator and Midnight Commander fixes for directory handling, keyboard
  input, module loading, missing APIs and cross-personality launches.
- The GRUB base image has room for RC; the small diagnostic download omits RC.
- Separate CI checks for lint/unit tests, personality and hardware integration,
  and release packaging. Numbered releases publish only after those checks pass.
- CI retries retain integration logs per attempt and support rebuilt artifacts.
- RC integration checks wait for directory changes and selections to finish.

### Downloads and upgrades

- `retroos-vm.tar.gz`: prebuilt QEMU launcher, boot image and initial public data.
- `retroos-machine.tar.gz`: installer for an existing Linux/GRUB setup.
- `retroos_grub_module_usb.img`: editable GRUB USB boot image.
- `retroos_grub_module.iso`: BIOS/UEFI CD-ROM boot image.
- `retroos-usb-diagnostic.zip`: small boot/input diagnostic image.
- `SHA256SUMS`: checksums for the downloads.

Stop the VM before upgrading. Replace its boot image and preserve the existing
`data.img`; a new release's data image is a seed, not an upgrade of your data.
For physical machines, use the supplied installer to keep the kernel and runtime
matched. See the bundled README for installation and disk protection options.
Rat Commander requires an x86-64 CPU; use `--arch x64` in the development launcher.
Existing data disks may contain an older `/bin/rc`; use the boot copy above.

### Known limitations

- Some systems still fail to boot. Hardware support and BIOS/UEFI behavior need
  more testing, and bootloader support does not imply kernel driver support.
- Usability and consistency issues remain. DOS compatibility is the main focus,
  but applications and extenders can still expose missing or incorrect behavior.
- Windows, OS/2 and Linux API coverage trails DOS support; these personalities
  are experimental and do not provide general compatibility with those systems.
- USB mass storage is not available after boot. GRUB can load RAM modules from
  USB, but persistent data needs a supported disk controller.
- RC networking, mounts and filesystem notifications are not validated or fully
  supported. Its optional audio, RAR and SQLite features are disabled.
- Emulation tests cover specific paths and programs, not every physical machine.
  Sound-underrun diagnostics can still occur.
- Proprietary games and applications are not included in public release assets.
