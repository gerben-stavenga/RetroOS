#!/bin/bash
# Prepare as yourself; install the reviewed, matched release as root.
#   tools/install_kernel.sh --prepare
#   sudo tools/install_kernel.sh
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${1:-}" = --prepare ]; then
    [ "$(id -u)" != 0 ] || { echo 'Prepare as your normal user, not root.' >&2; exit 1; }
    bazelisk build //:machine_boot_tar
fi
exec python3 tools/machine_install.py "$@"
