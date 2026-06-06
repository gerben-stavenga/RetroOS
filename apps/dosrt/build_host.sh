#!/bin/bash
# Bazel genrule ACTION (not run by hand): build the hosted RetroOS interpreter
# binary (`retroos-host`, the arch-interp backend) with cargo and emit it to $1.
#
#   build_host.sh <out>
#
# This runs as a `local` (un-sandboxed) genrule because it shells out to the
# host cargo + the developer's CARGO_HOME — which holds the patched Unicorn git
# fork and the registry cache, and on a clean machine fetches them over the
# network and builds Unicorn via CMake. That's the same class of non-hermetic
# host-tool dependency the old qemu_tcc.sh had on a system `qemu`; the payoff is
# a deterministic, headless DOS-program runner with no VM boot. The binary is
# statically linked (no libunicorn.so), so downstream genrules can consume it
# sandboxed.
set -euo pipefail

OUT="$1"

# Bazel scrubs the action environment (no HOME/PATH to cargo), so restore what
# cargo + CARGO_HOME need. Derive HOME from the passwd entry for this uid.
: "${HOME:=$(getent passwd "$(id -u)" | cut -d: -f6)}"
export HOME
export PATH="${HOME}/.cargo/bin:${PATH:-/usr/bin:/bin}"
: "${CARGO_HOME:=${HOME}/.cargo}"
export CARGO_HOME
# A stable target dir so cargo's incremental cache survives `bazel clean` (the
# first build compiles Unicorn + the kernel in release ~1 min; later ones are
# near-instant). Overridable for CI.
: "${CARGO_TARGET_DIR:=${HOME}/.cache/retroos/host-target}"
export CARGO_TARGET_DIR

command -v cargo >/dev/null || { echo "build_host.sh: cargo not on PATH" >&2; exit 1; }

cargo build --release -p kernel --features hosted --bin retroos-host
cp "${CARGO_TARGET_DIR}/release/retroos-host" "$OUT"
chmod +x "$OUT"
