#!/bin/bash
# Prepare as yourself; install the reviewed machine plan as root.
set -euo pipefail
cd "$(dirname "$0")/.."
prepare=0
supplied_image=0
copy_showcase=0
supplied_showcase=0
for argument in "$@"; do
    case "$argument" in
        --prepare) prepare=1 ;;
        --image|--image=*|--iso|--iso=*) supplied_image=1 ;;
        --copy-showcase) copy_showcase=1 ;;
        --showcase-archive|--showcase-archive=*) supplied_showcase=1 ;;
    esac
done
if [ "$prepare" = 1 ]; then
    [ "$(id -u)" != 0 ] || { echo 'Prepare as your normal user, not root.' >&2; exit 1; }
    if [ "$supplied_image" = 0 ]; then
        bazelisk build //:machine_boot_tar //:root_module_base_gzip //:showcase_module_tar
    elif [ "$copy_showcase" = 1 ] && [ "$supplied_showcase" = 0 ] && [ ! -f showcase.tar ]; then
        bazelisk build //:showcase_module_tar
    fi
fi
exec python3 tools/install_machine.py "$@"
