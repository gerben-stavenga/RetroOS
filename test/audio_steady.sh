#!/usr/bin/env bash
# Sustained HDA playback, checked at the actual QEMU PCM output. The old
# per-driver counters were removed when ring accounting moved to lib:sound.
# Its unit tests cover cursor arithmetic, ring limits and stall recovery.
# Usage: test/audio_steady.sh [--kvm] [seconds]
set -euo pipefail
cd "$(dirname "$0")/.."
source test/lib/qemu_common.sh
qemu_bazel build //:image //kernel:kernel_elf
exec python3 test/audio_steady.py "$@"
