# RetroOS

RetroOS is an experimental x86 operating system written mostly in Rust and built
with Bazel. It has a small ring-0 `arch` layer, a ring-1 kernel event loop, and
user execution support for 32-bit ELF, 64-bit ELF, and VM86/DOS programs
(including DPMI — it runs Quake, Commander Keen, Borland C++ self-builds, and
other real DOS software).

The same kernel runs two ways, selected by the `arch` backend it links:

- **metal** — on the real CPU, from a 386 to a modern UEFI x86-64 laptop. Boots
  via its own MBR bootloader or via the machine's existing GRUB (multiboot), with
  GOP-framebuffer console, NVMe, APIC/LAPIC timer, USB (xHCI) and i8042 keyboard,
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
./run.sh qemu                         # 386 BIOS image in QEMU (default)
./run.sh qemu --arch x64              # boot as an x86-64 machine
./run.sh qemu --firmware uefi         # OVMF/UEFI: GRUB-less GOP boot path
./run.sh qemu --sound ac97            # AC'97 instead of the default Sound Blaster
./run.sh qemu --kvm                   # run on the host CPU (near-metal semantics)
./run.sh hosted --cmd GAMES/SKYROADS  # interp backend: DOSBox-style hosted run
./run.sh bochs | ./run.sh 86box       # other emulators, same flags
```

`run.sh` defaults to the proprietary image when `apps-proprietary/` is present,
otherwise the public `//:image`. See `./run.sh` header comments for the full
option list (`-i`, `-h HOSTDIR`, `--headless`, screenshots, etc). The old
`run_qemu.sh` / `run_uefi.sh` / `run_bochs.sh` / `run_interp.sh` scripts are thin
shims that forward here.

To drive the raw image yourself:

```bash
qemu-system-i386 -drive file=bazel-bin/image.bin,format=raw -debugcon stdio -no-reboot
```

For booting on a real UEFI machine via its installed GRUB, see [BOOTING.md](BOOTING.md).

## Architecture

### Layers

- `arch-abi` - the kernel-facing arch interface (the contract both backends implement)
- `arch-metal` - ring-0 supervisor on the real CPU: paging, traps, descriptor
  tables, mode switching, plus the metal device drivers (NVMe, xHCI, APIC)
- `arch-interp` - the hosted backend: the same interface implemented over a
  software x86 core (Unicorn), running guest code interpreted in a host process
- `kernel` - ring-1 policy code: scheduler, syscalls, VFS, ELF loading,
  VM86/DOS/DPMI runtime, emulated VGA, sound, platform/focus/io-policy
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
