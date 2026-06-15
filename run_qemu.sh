#!/bin/bash
# Run RetroOS in QEMU with debugcon output.
# COMPAT SHIM: this now forwards to the unified ./run.sh (qemu backend).
# Usage: ./run_qemu.sh [386|686|x64] [-i image] [-r binary] [-h hostfs_dir] [extra qemu args...]
#
# Old env knobs are translated: AC97=1 -> --sound ac97, HDA=1 -> --sound hda,
# SOUND=0 -> --sound none. The leading positional arch and all trailing flags
# are forwarded verbatim (run_test.sh relies on this).

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="${1:-386}"
shift 2>/dev/null || true

SOUND_ARGS=()
if [ "${SOUND:-1}" = "0" ]; then
    SOUND_ARGS=(--sound none)
elif [ "${AC97:-0}" = "1" ]; then
    SOUND_ARGS=(--sound ac97)
elif [ "${HDA:-0}" = "1" ]; then
    SOUND_ARGS=(--sound hda)
fi

exec "$SCRIPT_DIR/run.sh" qemu --arch "$ARCH" "${SOUND_ARGS[@]}" "$@"
