# RetroOS

RetroOS is an experimental x86 operating system written mostly in Rust and built
with Bazel. It has a small ring-0 `arch` layer, a ring-1 kernel event loop, and
user execution support for 32-bit ELF, 64-bit ELF, native 32-bit OS/2 LX,
native Win32 PE console programs, and VM86/DOS programs
(including DPMI — it runs Quake, Commander Keen, Borland C++ self-builds, and
other real DOS software).

The same kernel runs two ways, selected by the `arch` backend it links:

- **metal** — on the real CPU, from a 386 to a modern UEFI x86-64 laptop. Boots
  via its own MBR bootloader or via the machine's existing GRUB (multiboot), with
  GOP-framebuffer console, ATA/NVMe/AHCI storage, APIC/LAPIC timer, USB (xHCI) and i8042 keyboard,
  and AC'97 / Intel HDA sound.
- **interp** — as an ordinary host process, with guest instructions executed by a
  software x86 core (Unicorn). The kernel logic is identical; this is the
  DOSBox-shaped path for running old software on a new machine.

The main design rule is to canonicalize and unify behavior wherever possible:

- one small privileged `arch` interface, with swappable metal/interp backends
- one event-loop kernel model across execution modes
- one recursive paging model across legacy, PAE, and compat mode
- one shared core for process, file, and compatibility mechanisms where practical

`arch` is the hard boundary and should stay boring, small, and mechanically
defensible. Compatibility layers above it can move faster and be more pragmatic
while DOS/Linux/Windows support is being developed.

See [DESIGN.md](DESIGN.md) for the architecture and [OUTLOOK.md](OUTLOOK.md) for
where it is heading — one safe-Rust core running code for any OS, any ISA, on
any host (native on the diagonal, interpreted off it).

For an existing ext4 Linux machine, see [BOOTING.md](BOOTING.md). Prepare with
`tools/install_kernel.sh --prepare`, then install with
`sudo tools/install_kernel.sh`.

GRUB supplies two ordinary INI files. `BOOT.INI` selects the boot bundle and
filesystem mounts; `RETROOS.INI` holds user settings. Disk installations open
bundle files directly from the configured filesystem, without a RAM bundle
module. USB boots use a small GRUB bundle module because kernel USB storage
is not supported yet. The core contains DN, BusyBox and runtime libraries;
VC, MC, RC, NDN (DOS/Windows/OS/2), DN/2 (DOS/Windows/OS/2), and games
live directly under `showcase-bundle/`, which mirrors their `C:` paths and is
packaged with one recursive glob into a single showcase image. USB loads it by default; the GRUB “Core only
(less RAM)” choice omits it. Disk installations use the games and apps already on their C: filesystem;
the installer supplies only the core runtime and DN.

Runtime files and DN have writable session views; `C:\TEMP` is RAM. A mounted
Linux root keeps its own `/bin` and `/usr/bin`. Bundled BusyBox serves the RAM
root or an explicit bundle mount at `/bin`. Unlisted partitions remain unmounted.

## Releases

`bazelisk build //:release` produces public bundles in `bazel-bin/`:

- `retroos-vm.tar.gz` (`//:release_vm`): boot/data images and prebuilt QEMU and UniPCemu launchers.
- `retroos-machine.tar.gz` (`//:release_machine`): matched kernel/runtime and installer.
- `retroos_grub_module_usb.img` (`//:grub_module_usb`): editable BIOS/UEFI USB image with one FAT32 partition (MBR type `0x0C`).
- `retroos_grub_module.iso` (`//:grub_module_iso`): bootable BIOS/UEFI CD image with the same kernel and RAM modules as the USB image.
- `retroos-usb-diagnostic.zip` (`//:usb_diagnostic_zip`): compact USB image for boot diagnostics.
- `SHA256SUMS` (`//:release_checksums`): checksums for all release artifacts.

The USB image's FAT32 partition holds the GRUB menu, kernel, and RAM modules
and can be edited from a host OS. RetroOS cannot yet access it after boot:
the kernel does not have a USB mass-storage driver. Persistent C: requires a
disk that RetroOS can enumerate, such as NVMe or AHCI.

CI tests these artifacts and uploads them on successful runs. The bundles require
no compiler or Bazel to use. Extract upgrades separately and preserve your existing
data image; replace only the boot image. See the bundled README for installation.

## Build

```bash
bazelisk build //:image \
    --platforms=//toolchain:i686_retro_none \
    --@rules_rust//rust/toolchain/channel:channel=nightly
```

Useful targets:
- `//:image` - public bootable disk image
- `//kernel:kernel_elf` - kernel ELF
- `//boot:bootloader_bin` - bootloader binary

## Run

Everything goes through one launcher, `run.sh`, which picks the backend,
firmware, sound card, and image:

```bash
./run.sh qemu                         # fresh UEFI boot + persistent data
./run.sh qemu --arch x64              # boot as an x86-64 machine
./run.sh qemu --firmware uefi         # OVMF/UEFI: GRUB + GOP framebuffer
./run.sh qemu --hd ahci               # data disk on AHCI (also: ata, nvme)
./run.sh qemu --sound ac97            # AC'97 instead of the default HDA
./run.sh qemu --kvm                   # run on the host CPU (near-metal semantics)
./run.sh hosted --cmd GAMES/SKYROADS  # interp backend: DOSBox-style hosted run
./run.sh bochs | ./run.sh 86box       # other emulators, same flags
./run.sh unipcemu                    # Pentium/i430fx; uses local UniPCemu build and ROM when present
./run.sh rust-dos                    # experimental: native BIOS loader; kernel currently halts
./run.sh rust-dos-games              # Rust-DOS shell with a disposable FAT16 C:
```

`run.sh` defaults to the shared layout on QEMU, Bochs, 86Box and hosted:

- `bazel-bin/boot_disk.bin`: GRUB, kernel and `C:\RETROOS` system files, rebuilt from current sources.
- `build/data.bin`: one writable disk, shared across backends. FAT32 holds `C:` and ext4 holds the Linux root. Guest writes persist.

For Rust-DOS, clone [dividebysandwich/rust-dos](https://github.com/dividebysandwich/rust-dos)
into `tmp/rust-dos` and run `cargo build --release` there. The checkout and
build artifacts are ignored by Git. `./run.sh rust-dos` boots the same BIOS
data disk as the other emulators, but builds `native_boot_disk.bin` with
RetroOS's own BIOS MBR loader instead of GRUB. It keeps the current kernel and
`C:\RETROOS` files on that disposable disk. Use `RUST_DOS_BIN` to select a
different executable. Rust-DOS supports BIOS disk images here, with
up to 64 MiB RAM. The default 486 model reaches the RetroOS kernel, but
Rust-DOS exposes mounted hard disks through BIOS INT 13h only. RetroOS's
runtime probes ATA/AHCI/NVMe directly and finds no storage, so it halts with
`No root filesystem available` before DN starts. This is not yet a playable
setup.

`./run.sh rust-dos-games` runs Rust-DOS itself, with `C:` built from the current
`c_drive_tar` and `boot_dir_tar` packages. It includes `C:\GAMES` and
`C:\RETROOS`; when `apps-proprietary/` is present it uses the proprietary game
package too. The image is FAT16 because Rust-DOS cannot mount the shared
FAT32 data image as a DOS drive yet. It is copied to a temporary file for
each launch, so game saves in this mode are discarded on exit. The launcher
reads `PATH`, `DN`, `DNSWP`, `TEMP` and `start` from `etc/RETROOS.INI`, matching
RetroOS's DOS paths; the default `START` opens DN automatically. After DN
exits, the DOS prompt remains. Rust-DOS's built-in DPMI host uses its default
enabled setting.

The data disk is seeded only when missing, using proprietary content when
`apps-proprietary/` exists. Rebuilding a seed never replaces the live disk.
Use `--data-image /path/to/data.bin` (or `RETROOS_DATA_IMAGE`) to choose another
persistent disk. A launcher lock prevents simultaneous use of the same disk.

Edit [filesystem_layout.bzl](filesystem_layout.bzl) for packaged file destinations
and partition sizes. Size/seed changes apply to newly created data images;
existing disks retain their contents and layout. `C:\RETROOS\RETROOS.INI`
contains COMMAND.COM launch policy in `[launch]`, including Aladdin's `xms32k` setting.
The runtime bundle and DN have writable RAM views, including shipped files;
changes disappear on reboot. Persistent settings can use explicit writable
mounts at the appropriate application directory.

`RETROOS.INI` contains system, locale, sound, environment and launch sections.
`[system] start=C:\DN\DN.COM` selects the startup program; `[locale]
language=it-IT` selects shared regional settings. `keyboard=us` and
`codepage=850` override the locale defaults. Regional policy is shared by DOS,
Windows, OS/2 and Linux.

USB keeps editable `BOOT.INI` and `RETROOS.INI` under `/boot/retroos/`, outside
`releases/<version>/`. GRUB loads them as `retroos.config=boot` and
`retroos.config=ini` modules. RetroOS exposes the supplied user settings as an
editable session copy at `C:\RETROOS\RETROOS.INI`; persistent USB edits require
another OS until kernel USB storage works.

Disk installation keeps `/boot/retroos/BOOT.INI` separate from versioned runtime
files. User settings remain permanently at `/home/retroos/RETROOS/RETROOS.INI`
(`C:\RETROOS\RETROOS.INI`). GRUB loads that file from its permanent location.
The installer preserves it and existing mount choices across upgrades.

| Locale | OEM code page | Windows ANSI | Keyboard |
| --- | --- | --- | --- |
| `en-US` (default) | 437 | 1252 | `us` |
| `de-DE` | 850 | 1252 | `de` |
| `it-IT` | 850 | 1252 | `it` |
| `nl-NL` | 850 | 1252 | `us` |
| `pl-PL` | 852 | 1250 | `pl` (programmer) |
| `ru-RU` | 866 | 1251 | `ru` |

For example, `[locale] language=it-IT` selects Italian country/date/number
settings and keyboard input. `keyboard=us`, `de`, `it`, `pl` or `ru` overrides the keyboard
independently. Right Alt selects AltGr characters; German dead keys compose
accents; Caps Lock changes letter case. Russian input switches between Cyrillic
and Latin with Left Alt+Shift. Dutch defaults to a US keyboard.

`codepage=437`, `850`, `852`, or `866` overrides the locale's OEM encoding;
`CHCP` can change the active OEM page during a session. Neither changes the
regional settings or Windows ANSI page. DOS and OS/2 receive OEM input bytes,
Windows console W APIs receive UTF-16 and A APIs use the console input page,
and Linux receives UTF-8. DOS programs that hook IRQ1 or read the keyboard
controller directly still receive the original scancodes and own their mapping.

DOS/OS/2 country structures use the ISO currency code when their OEM page
cannot encode the Unicode symbol (for example, `EUR` on page 850).
Linux starts with the locale's UTF-8 `LANG`; userspace libraries remain
responsible for their own locale data and formatting.

Mounts are explicit in `BOOT.INI`; unlisted physical partitions remain
unmounted. The default is a self-contained RAM C:. For example, the existing
workspace disk image can supply C: on bare metal without copying it:

```ini
[bundle]
source=UUID=<ext4-filesystem-UUID>
subdir=/boot/retroos/releases/<version>

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
```

`grant` identifies the home directory whose owner UID grants ext4 writes; existing
inode ownership and owner-write permissions still apply. `subdir` exposes a
subtree of a volume. Image mounts are ordered after their containing mount;
cycles are rejected. Partitioned images with several supported partitions
require `partition=`, numbered from 1. Raw filesystem images need no selector.
The current file interface limits images to less than 4 GiB.

Mount access modes are `ro` (reject writes), `rw` (persist writes), and `ram`
(accept writes into a sector overlay). GRUB's **Protected Disk** boot forces
physical `rw` mounts into RAM without editing the INI. Missing configured
sources stop boot with a diagnostic; another partition is never selected silently.

ISO images use `source=file:/path/game.iso`, `format=iso9660`, `path=/cdrom`,
`drive=D`, `access=ro`. The optional showcase module mounts separately at `/showcase`,
normally G:, without merging physical game directories. Explicit mount paths
and drive assignments win over the optional module defaults.

F12 **Disk → Mnt** stages physical partition mappings. On a partition row,
left/right changes its drive; on its access row it selects ro/rw/ram. Choose an
export destination and **Export BOOT.INI** to save the proposed configuration.
Changes take effect on the next boot after copying the export to the boot medium
from another OS. Exporting in Protected Disk mode is RAM-only. RetroOS still
cannot write USB storage. The full partition UUIDs are also printed in KLOG.

The VM launchers generate this mount policy from the explicitly attached data
disk's UUIDs in their disposable boot copy, preserving the shared `build/data.bin`
workflow without modifying the persistent disk or relying on discovery order.


Sound Blaster discovery checks ISA Plug and Play first. A Creative PnP audio
device, including one already initialized by firmware, is configured using the
`BLASTER` setting in `[environment]` in RETROOS.INI, for example
`BLASTER=A220 I7 D1 H5 P330 T6`. Its A/I/D/H/P fields request the SB port,
IRQ, 8-bit DMA, optional 16-bit DMA, and MPU port (`P` defaults to `330`).
RetroOS checks the card's advertised resource alternatives and other active
ISA PnP devices, activates the audio function, then verifies the DSP and reads
back its wiring. In mixed mode, BLASTER also continues to describe the
emulated guest card. Only when no PnP Sound Blaster is found does RetroOS try
legacy DSP probing and mixer restrapping. A PnP configuration failure does
not fall through to legacy restrapping. Discovery always logs the IDs of all
readable ISA PnP logical devices, including non-audio functions.
ESS ES1868/ES1869 audio functions are also activated as SB-compatible devices.
Their FM/MPU port order follows the ESS resource layout, and their verified
PnP IRQ/8-bit DMA settings supply the native card's wiring. SB16 `H` requests
are ignored for ESS; its second DMA engine is disabled for SB compatibility.
Select Sound Blaster Pro in DOS games (for example, `BLASTER=A220 I7 D1 P330 T5`);
ESS extended audio and kernel mixing through the ESS card are not implemented.

When both HDA and a real Sound Blaster are present, native mode gives the SB
to DOS and keeps HDA available for kernel audio. `SB_AUDIO=mixed` starts with
kernel mixing through HDA and parks the SB so DOS sees an emulated card. The
Sound tab (F12) can switch among native SB, mixing through HDA, and mixing
through SB. Mixing through SB requires a 16-bit DMA channel; on systems without
HDA, the original native SB and SB mixing choices remain available.
In native SB16 mode, the Sound tab also adjusts the card's Master, Wave (DSP),
FM/MIDI, and CD input levels independently in 10% steps. The CD control changes
the analog CD input on the card; CD-ROM data support does not provide Redbook
audio playback. These levels are live mixer settings and may be changed by a
DOS program that reprograms the card.

For dISAppointment hardware, select the USB GRUB **dISAppointment ISA bridge**
submenu, or append `isa-lpc=disappointment` to the `multiboot` line (press `e`
in GRUB, edit, then Ctrl-X to boot). This opt-in runs before PnP discovery.
Supported Intel LPC controllers include ICH6/ICH7, 6/7/8/9-series PCH, and
X99 at 00:1f.0, with a Fintek F85226 at 4E/4F. Unknown chipsets or
missing bridges are logged and skipped; the option is not required for normal
PnP discovery or cards with working firmware/DOS routing. Setup replaces the
four generic LPC decode windows with the dISAppointment sound/PnP ranges,
configures the bridge timing, and resets ISA DMA while preserving PIC masks.
It also restores LDRQ1# from GPIO23 mode when GPIO control is unlocked, so
boards that use this pin for LPC DMA can transfer audio data.
Readback failure restores previous bridge/decode settings. Physical validation
is still needed; a bridge strapped to 2E/2F is not supported. Some ASUS
boards reportedly route only ports below 3FFh to LPC, preventing ISA PnP
configuration through the default A00h window. The diagnostic submenu leaves
logs on screen for a photo.
Inspired by [rasteri's dISAppointment / sapphisa](https://github.com/rasteri/dISAppointment/blob/main/software/sapphisa.c);
see `THIRD_PARTY_LICENSES.md` for attribution and adaptation licensing.
Allocation against all legacy/PCI devices and AWE synthesis initialization
are not implemented.

Before the interactive startup program runs, RetroOS saves a boot log snapshot
to the first unused file on C:, starting with `KLOG.TXT`, then `KLOG0001.TXT`,
`KLOG0002.TXT`, and so on. Earlier logs are preserved across boots. The file's
VFS modification time follows the host RTC while the log is written. It then
appends and flushes new log output after each completed line. If the line is emitted from an
interrupt or while the filesystem lock is held, the bytes remain in the log
ring and are flushed at the next safe line or event-loop pass. Failure to save
does not stop startup. Live appends stop at 16 MiB to avoid filling C:. The file survives
reboot only on a persistent data volume; protected-disk and RAM-only boots
keep it in RAM. This captures boots that reach the
startup program even when keyboard input is unavailable, but cannot capture an
earlier boot hang. The USB GRUB submenu **Boot diagnostics
(no DN; stop for photo)** saves the log, displays USB/storage discovery results,
and stops before launching any program. This is also available via the kernel
argument `boot-log-only`.

Saved logs use UTF-8, including characters printed by DOS programs in the
active codepage. The DOS `LOG` command maps UTF-8 text back to that codepage
for display; common Unicode punctuation has ASCII fallbacks, and unavailable
glyphs show as a square.

The shared Uni-VGA 8×16 atlas contains 2,899 Unicode glyphs (about 57 KiB).
Linux terminal cells retain Unicode scalars and render directly from the atlas;
Linux defaults to `LANG=en_US.UTF-8`, selected by `LOCALE=`. Windows and OS/2
window text also looks up
Unicode glyphs directly; DOS VGA fonts
are assembled from the selected OEM page's Unicode mapping. Missing glyphs
render as `?`; CJK, emoji and text shaping are not included. The existing
8×8 and 8×14 fonts are retained for those video modes. Source attribution and
regeneration instructions are in [lib/fonts/uni-vga](lib/fonts/uni-vga/README.md).

`--freedos` boots FreeDOS directly from the same data disk on a BIOS emulator.
`--host DIR` uses the live host tree with the hosted backend, or exports it as
HostFS under QEMU. `--cmd` is supported on QEMU and hosted; the launcher does
not inject temporary commands or serial settings into the persistent disk.
The old `-i` image modes, installer flow, and `--gpt` assembly are removed.

`run.sh` owns the build/data lifecycle; `tools/run/` contains only backend
launch arguments and configuration. See `./run.sh --help` for options.

For 86Box, the disposable boot image is padded to 504 MiB (1024 cylinders)
so the emulated IDE disk advertises LBA support. Its filesystem and the
persistent data image keep their original sizes.
This works around the TX97 BIOS's automatic CHS translation; the kernel also
supports CHS-only IDE disks, using their reported geometry. CHS/LBA addressing
is independent of PIO/DMA transfers.

For booting on a real UEFI machine via its installed GRUB, see [BOOTING.md](BOOTING.md).

New standalone bundles mount physical filesystems only when listed in
BOOT.INI. `access=rw` persists permitted writes; `access=ro` rejects them;
`access=ram` keeps changes in memory. The GRUB `ram-overlay` option protects
all physical writes for that boot. Unlisted physical partitions stay unmounted. See
[BOOTING.md](BOOTING.md#disk-writes-and-ram-overlay).

## Architecture

### Layers

- `arch-abi` - the kernel-facing arch interface (the contract both backends implement)
- `arch-metal` - ring-0 supervisor on the real CPU: paging, traps, descriptor
  tables, mode switching, plus the metal device drivers (NVMe, xHCI, APIC)
- `arch-interp` - the hosted backend: the same interface implemented over a
  software x86 core (Unicorn), running guest code interpreted in a host process
- `kernel` - ring-1 policy code: scheduler, syscalls, VFS, ELF loading,
  VM86/DOS/DPMI runtime, OS/2 LX and Win32 PE personalities, emulated VGA,
  sound, platform/focus/io-policy
- `apps` - user programs and DOS test binaries
- `play` - `retroos-play`, the windowed host emulator built on `arch-interp`

The kernel is backend-agnostic: it links either `arch-metal` (Bazel, `no_std`,
bare metal) or `arch-interp` (`std`, hosted) and behaves the same.
All ring-3 execution is normalized into the same kernel-facing flow: run a task,
capture an event, handle it, repeat.

### Compatibility

Compatibility work should live above the `arch` boundary. The long-term goal is:

- `arch` stays minimal and trustworthy
- kernel core owns generic process/thread/file/event machinery
- compatibility layers reuse a shared core where possible
- DOS/Linux/Windows-specific hacks stay out of `arch`

### Toolchain Bootstrap

Building `core` and `compiler_builtins` from source requires a bootstrap mechanism to break the circular dependency (toolchain needs stdlib, stdlib needs toolchain).

Solution: Single toolchain with config-based stdlib selection:

```
//toolchain:retro_rust_toolchain_impl
    rust_std = select({
        ":is_bootstrap": ":empty_stdlib",      # For building core/compiler_builtins
        "//conditions:default": ":full_stdlib"  # For user code
    })
```

The `with_bootstrap` transition rule flips the config when building stdlib targets.

### Directory Structure

```
RetroOS/
├── boot/           # MBR + protected-mode bootloader
├── arch-abi/       # Kernel-facing arch interface (shared contract)
├── arch-metal/     # Bare-metal arch backend + device drivers
├── arch-interp/    # Hosted (Unicorn) arch backend
├── kernel/         # Ring-1 kernel: scheduler, syscalls, VFS, DOS/DPMI, VGA, sound
├── play/           # retroos-play windowed host emulator
├── lib/            # Shared freestanding library (VGA render, ELF, TAR, MD5)
├── boot-bundle/    # Core static files (DN and BusyBox)
├── showcase-bundle/ # Optional programs and assets in their C: layout
├── boot-bundle/    # Programs shipped in the boot filesystem (DN, VC, MC, RC, BusyBox)
├── stdlib/         # core + compiler_builtins from rust-src
└── toolchain/      # Bazel toolchain definitions
```

RETROOS.INI selects which filesystems are exposed and their DOS drive letters.
Unlisted physical partitions stay unmounted. **H:** is reserved for HostFS;
**A:** and **B:** are floppy drives. Use F12 **Disk → HD** to see active mappings
or **Disk → Mnt** to stage and export a mount profile.

Disk installer preparation asks whether to copy the showcase only when the C:
directory does not yet exist. Existing C: directories skip copying by default.
Use `--copy-showcase` or `--no-copy-showcase` for scripted preparation.
Copying adds missing ordinary files and preserves existing files and symlink
directories. These are disk files, with no showcase mount or RAM image.
