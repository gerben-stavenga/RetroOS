#!/bin/bash
# HostFS-specific helpers for QEMU integration tests.

source "$(dirname "${BASH_SOURCE[0]}")/qemu_common.sh"

qemu_hostfs_set_serial_args() {
    case "${1:-com1}" in
        com1) QEMU_HOSTFS_SERIAL_ARGS=(-serial chardev:hostfs) ;;
        com2) QEMU_HOSTFS_SERIAL_ARGS=(-serial null -device isa-serial,chardev=hostfs,index=1) ;;
        *) echo "usage: expected HostFS port com1 or com2" >&2; return 2 ;;
    esac
}
