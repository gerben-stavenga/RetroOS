#!/bin/bash
# Run RetroOS on the hosted/interp backend (retroos-play window, or -T headless).
# COMPAT SHIM: this now forwards to the unified ./run.sh (hosted backend).
#
# Usage: ./run_interp.sh [-i image|proprietary] [-c DOS_CMD] [-H hostdir]
#                        [-w out.wav] [-T] [-s shot] [-t] [extra args...]
#
# All flags are preserved by run.sh's hosted backend (-i/-c/-H/-w/-T/-s/-t).

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec "$SCRIPT_DIR/run.sh" hosted "$@"
