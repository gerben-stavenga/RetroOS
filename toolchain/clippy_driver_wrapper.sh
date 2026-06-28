#!/bin/sh
# clippy-driver launcher for the bare-metal rust_toolchain.
#
# The nightly dist we download (rust_toolchain.BUILD) keeps clippy-driver under
# clippy-preview/bin/ but its librustc_driver dylib under rustc/lib/. rustc finds
# its libs via $ORIGIN/../lib, but clippy-driver's $ORIGIN/../lib (clippy-preview/
# lib/) is empty, so it can't load librustc_driver. rules_rust assembles both the
# clippy_driver file and the rustc_lib sysroot under one <impl>/ root, so from this
# wrapper's bin dir the real binary and its libs are reachable by relative path.
here="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="$here/../rustc/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$here/../clippy-preview/bin/clippy-driver" "$@"
