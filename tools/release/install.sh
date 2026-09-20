#!/bin/bash
# Install a prebuilt release using the same installer as the source checkout.
set -euo pipefail
cd "$(dirname "$0")"
if [ "${1:-}" = --prepare ]; then
    exec python3 tools/machine_install.py "$@" --archive "$PWD/machine_boot.tar"
fi
exec python3 tools/machine_install.py "$@"
