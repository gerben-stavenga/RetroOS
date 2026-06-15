#!/bin/bash
# Run RetroOS in 86box (PCem-derived, period-accurate PC emulator).
# COMPAT SHIM: this now forwards to the unified ./run.sh (86box backend).
# Usage:  ./run_86box.sh [-i image|proprietary|ext4|freedos] [extra 86box args...]
#
# Setup (one-time) and notes are unchanged — see run.sh / the original history.
# Env knobs (BOX86, VM_DIR, FDOS_DIR, HDD_IMG, QT_QPA_PLATFORM, ...) pass through.

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec "$SCRIPT_DIR/run.sh" 86box "$@"
