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

For an existing Linux machine, see [BOOTING.md](BOOTING.md). Prepare with
`tools/install_kernel.sh --prepare`, then install with `sudo tools/install_kernel.sh`.
GRUB selects the root by UUID; runtime files at `C:\RETROOS` are read-only,
while DN settings/history live at `C:\CONFIG\DN` and temporary files at `C:\TEMP`.

## Releases

`bazelisk build //:release` produces public bundles in `bazel-bin/`:

- `retroos-vm.tar.gz` (`//:release_vm`): boot/data images and a prebuilt QEMU launcher.
- `retroos-machine.tar.gz` (`//:release_machine`): matched kernel/runtime and installer.
- `SHA256SUMS` (`//:release_checksums`): checksums for both bundles.

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
```

`run.sh` defaults to the shared layout on QEMU, Bochs, 86Box and hosted:

- `bazel-bin/boot_disk.bin`: GRUB, kernel and `C:\RETROOS` system files, rebuilt from current sources.
- `build/data.bin`: one writable disk, shared across backends. FAT32 holds `C:` and ext4 holds the Linux root. Guest writes persist.

The data disk is seeded only when missing, using proprietary content when
`apps-proprietary/` exists. Rebuilding a seed never replaces the live disk.
Use `--data-image /path/to/data.bin` (or `RETROOS_DATA_IMAGE`) to choose another
persistent disk. A launcher lock prevents simultaneous use of the same disk.

Edit [filesystem_layout.bzl](filesystem_layout.bzl) for packaged file destinations
and partition sizes. Size/seed changes apply to newly created data images;
existing disks retain their contents and layout. `C:\RETROOS\LOADFIX.CFG` is
seeded as writable data. The boot volume is read-only:
new state files beside shipped files go to the data disk, while shipped files
cannot be overwritten through that binding.

`--freedos` boots FreeDOS directly from the same data disk on a BIOS emulator.
`--host DIR` uses the live host tree with the hosted backend, or exports it as
HostFS under QEMU. `--cmd` is supported on QEMU and hosted; the launcher does
not inject temporary commands or serial settings into the persistent disk.
The old `-i` image modes, installer flow, and `--gpt` assembly are removed.

`run.sh` owns the build/data lifecycle; `tools/run/` contains only backend
launch arguments and configuration. See `./run.sh --help` for options.

For booting on a real UEFI machine via its installed GRUB, see [BOOTING.md](BOOTING.md).

> **On real hardware, RetroOS writes to your disk.** It mounts the machine's
> Linux root (it probes for `/etc` + `/usr`) and takes `C:` from
> `/home/retroos` there, so guest writes land on the filesystem you boot Linux
> from. Pass the Multiboot argument `ram-overlay` to divert every physical
> write into volatile RAM instead — recommended for a machine you care about.
> The boot banner tells you which mode you got. See
> [BOOTING.md](BOOTING.md#disk-writes-and-ram-overlay).

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
├── apps/           # Userspace ELF binaries and DOS programs
├── apps-boot/      # Programs embedded into kernel.elf (DN, COMMAND.COM)
├── stdlib/         # core + compiler_builtins from rust-src
└── toolchain/      # Bazel toolchain definitions
```
