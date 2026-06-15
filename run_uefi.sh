#!/bin/bash
# Boot RetroOS on a UEFI-only "modern laptop" mock (QEMU + OVMF, GOP, NVMe).
# COMPAT SHIM: this now forwards to the unified ./run.sh (qemu --firmware uefi).
# Usage: ./run_uefi.sh [image] [--headless] [-- extra qemu args]
#   default image: see run.sh (proprietary when present, else image)
#
# See run.sh's launch_qemu_uefi for the OVMF/ESP/NVMe/xHCI details.

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Translate the original's optional leading positional [image] into run.sh's
# uniform `-i <image>` (a leading dash arg is a flag, left as passthrough), and
# translate the original's -H short form for --headless (run.sh reserves -H for
# the hosted backend's host-dir, so it isn't accepted as a headless flag here).
ARGS=()
first=1
for a in "$@"; do
    if [ "$first" = 1 ]; then
        first=0
        case "$a" in
            -*) : ;;                  # flag: fall through to normal handling
            *)  ARGS+=(-i "$a"); continue ;;
        esac
    fi
    case "$a" in
        -H) ARGS+=(--headless) ;;
        *)  ARGS+=("$a") ;;
    esac
done

exec "$SCRIPT_DIR/run.sh" qemu --firmware uefi "${ARGS[@]}"
