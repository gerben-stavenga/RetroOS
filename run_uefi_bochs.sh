#!/bin/bash
# Run RetroOS in Bochs with UEFI/OVMF (2MB OVMF, GOP, NVMe/ESP-via-GRUB).
# COMPAT SHIM: this now forwards to the unified ./run.sh (bochs --firmware uefi).
# Usage: ./run_uefi_bochs.sh [image] [extra bochs args...]
#
# Env knobs (BOCHS_BIN, BOCHS_VGA_ROM, BOCHS_DEBUG, BOCHS_DISPLAY, VM_DIR) pass
# through; see run.sh's launch_bochs_uefi for the OVMF/ESP details.

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Translate the original's optional leading positional [image] into run.sh's
# uniform `-i <image>` (a leading dash arg is a flag, left as passthrough).
ARGS=()
if [ $# -gt 0 ]; then
    case "$1" in
        -*) : ;;
        *)  ARGS+=(-i "$1"); shift ;;
    esac
fi
ARGS+=("$@")

exec "$SCRIPT_DIR/run.sh" bochs --firmware uefi "${ARGS[@]}"
