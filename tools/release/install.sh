#!/bin/bash
# Install a prebuilt release using the same installer as the source checkout.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 tools/install_machine.py "$@"
