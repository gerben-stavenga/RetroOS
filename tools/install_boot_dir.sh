#!/bin/bash
# Prepare a direct/hosted C: tree. Physical-machine runtime installation uses
# tools/install_kernel.sh instead; this helper never deletes existing state.
set -euo pipefail
cd "$(dirname "$0")/.."
C_ROOT="${1:-/home/retroos}"
[ -d "$C_ROOT" ] || { echo "C: root does not exist: $C_ROOT" >&2; exit 1; }
bazelisk build //:boot_dir_tar
python3 tools/migrate_dn_state.py "$C_ROOT"
tar xf bazel-bin/boot_dir_tar.tar -C "$C_ROOT"
echo "Runtime refreshed at $C_ROOT/RETROOS; state is in $C_ROOT/CONFIG/DN"
