#!/bin/bash
# Prepare as yourself; install the reviewed, matched release as root.
#   tools/install_kernel.sh --prepare
#   sudo tools/install_kernel.sh
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${1:-}" = --module ]; then
    shift
    if [ "${1:-}" = --prepare ]; then
        [ "$(id -u)" != 0 ] || { echo 'Prepare as your normal user, not root.' >&2; exit 1; }
        supplied_image=0
        for argument in "$@"; do
            case "$argument" in --image|--image=*|--iso|--iso=*) supplied_image=1 ;; esac
        done
        if [ "$supplied_image" = 0 ]; then bazelisk build //:grub_module_usb; fi
    fi
    exec python3 tools/grub_module_install.py "$@"
fi
if [ "${1:-}" = --prepare ]; then
    [ "$(id -u)" != 0 ] || { echo 'Prepare as your normal user, not root.' >&2; exit 1; }
    bazelisk build //:machine_boot_tar
fi
exec python3 tools/machine_install.py "$@"
