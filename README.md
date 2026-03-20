# RetroOS Rust Bootloader

Rust implementation of the RetroOS bootloader, built with Bazel and rules_rust.

## Build

```bash
bazelisk build //:image \
    --platforms=//toolchain:i686_retro_none \
    --@rules_rust//rust/toolchain/channel:channel=nightly
```

The image target is at the root level to support future kernel and apps:
- `//boot:bootloader_bin` - Bootloader binary
- Future: `//kernel:kernel_bin` - Kernel binary
- Future: `//apps:*` - User applications

## Run

```bash
bazelisk run //:run \
    --platforms=//toolchain:i686_retro_none \
    --@rules_rust//rust/toolchain/channel:channel=nightly
```

Or directly:
```bash
qemu-system-i386 -drive file=bazel-bin/image,format=raw -serial stdio
```

## Architecture

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
retro-rs/
├── boot/           # Bootloader (MBR + Rust entry)
├── lib/            # Shared library (VGA, MD5, TAR)
├── stdlib/         # core + compiler_builtins from rust-src
├── toolchain/      # Bazel toolchain definitions
└── rules/          # Custom Bazel rules (nasm, linker, disk image)
```
