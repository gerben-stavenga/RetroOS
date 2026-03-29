# RetroOS

RetroOS is an experimental x86 operating system written mostly in Rust and built
with Bazel. It has a small ring-0 `arch` layer, a ring-1 kernel event loop, and
user execution support for 32-bit ELF, 64-bit ELF, and VM86/DOS programs.

The main design rule is to canonicalize and unify behavior wherever possible:

- one small privileged `arch` interface
- one event-loop kernel model across execution modes
- one recursive paging model across legacy, PAE, and compat mode
- one shared core for process, file, and compatibility mechanisms where practical

`arch` is the hard boundary and should stay boring, small, and mechanically
defensible. Compatibility layers above it can move faster and be more pragmatic
while DOS/Linux/Windows support is being developed.

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

For the public image:

```bash
bazelisk build //:image \
    --platforms=//toolchain:i686_retro_none \
    --@rules_rust//rust/toolchain/channel:channel=nightly
qemu-system-i386 -drive file=bazel-bin/image.bin,format=raw -debugcon stdio -no-reboot
```

For local development with proprietary assets present:

```bash
./run_qemu.sh [386|686|x64]
```

## Architecture

### Layers

- `arch` - ring-0 supervisor code: paging, traps, descriptor tables, mode switching
- `kernel` - ring-1 policy code: scheduler, syscalls, VFS, ELF loading, VM86/DOS runtime
- `apps` - user programs and DOS test binaries

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
├── kernel/         # Ring-0 arch + ring-1 kernel
├── crt/            # Freestanding userspace runtime and linker scripts
├── lib/            # Shared freestanding library (VGA, ELF, TAR, MD5)
├── apps/           # Userspace ELF binaries and DOS programs
├── stdlib/         # core + compiler_builtins from rust-src
└── toolchain/      # Bazel toolchain definitions
```
