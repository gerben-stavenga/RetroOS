# Rat Commander for the Linux personality

Upstream: https://github.com/dividebysandwich/rat-commander

This is the unmodified upstream source at commit
`90627f7cd70833cbcdaa883ca9506524d9986c24` (unreleased Cargo version 1.9.8), built as a
static x86_64 Linux musl ELF. It ships on the boot disk as
`C:\RC\RC.EXE` and can be started directly from DN. The `.EXE` suffix
is DOS friendly; the loader recognizes its ELF contents and uses the Linux
personality. The boot bundle provides `/bin/rc` and `/bin/rcedit` symlinks
to this boot copy. `C:\RETROOS\SHELL.ELF` opens the Linux shell from DOS.

The build uses `--no-default-features`: audio playback, RAR and SQLite support
are disabled. The built-in file manager, editor and viewer remain compiled in.
Run on an x86-64 CPU (`--arch x64` with QEMU) or the hosted KVM backend.
The hosted TCG backend currently executes only 32-bit clients. Core navigation,
folder creation, file copy, editor save, DOS subprocess execution and clean exit are covered by
`test/rat_commander.py`.
Filesystem notifications (`inotify`) are unavailable; external changes need
manual refresh. Networking and mounts are not yet validated for this app.

Rebuild with `tools/build_rat_commander.sh`; install the Rust musl target and
put `x86_64-linux-musl-gcc` on PATH. The checked-in binary was built with
Rust 1.96.0 and musl.cc's x86_64 musl cross toolchain (GCC 11.2.1).
The upstream Cargo.lock pins dependencies. Upstream source is GPL-2.0-only;
see LICENSE and the pinned upstream repository for the corresponding source.

Rebuilding the boot disk updates Rat Commander without rebuilding `data.bin`.
