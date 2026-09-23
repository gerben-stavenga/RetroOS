#!/bin/bash
# Compatibility entry point: verify shared boot/data composition instead of
# the former module-root-wins /disk1 policy.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 test/boot_composition.py
