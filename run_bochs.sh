#!/bin/bash
# Run RetroOS in Bochs.
# COMPAT SHIM: this now forwards to the unified ./run.sh (bochs backend).
# Usage: ./run_bochs.sh [386|686|x64] [-i image|proprietary|ext4|freedos] [extra bochs args...]
#
# All env knobs (BOCHS_CPU_MODEL, BOCHS_IPS, BOCHS_SYNC, BOCHS_VGA_UPDATE_FREQ,
# BOCHS_DEBUG, BOCHS_DISPLAY_LIBRARY, VM_DIR, FDOS_*, APPS_IMG, HDD_IMG, ...)
# are honored by run.sh's bochs backend unchanged.

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="${1:-386}"
shift 2>/dev/null || true

exec "$SCRIPT_DIR/run.sh" bochs --arch "$ARCH" "$@"
