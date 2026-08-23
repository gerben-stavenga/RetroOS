#!/bin/bash
# QEMU serial logging smoke test.
#
# The serial and debugcon streams are intentionally not compared byte-for-byte:
# the UART presents CRLF and direct guest 0xE9 writers may only appear in
# debugcon. We assert a small set of known kernel messages in both streams.
set -euo pipefail
cd "$(dirname "$0")/.."

stage=$(mktemp -d -t retroos-qemu-serial-log.XXXXXX)
serial_log="$stage/serial.log"
debug_log="$stage/debug.log"
no_serial_log="$stage/no-serial.log"
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "--- serial log ---" >&2
        cat "$serial_log" 2>/dev/null || true
        echo "--- debugcon log ---" >&2
        cat "$debug_log" 2>/dev/null || true
    fi
    rm -rf "$stage"
    return "$status"
}
trap cleanup EXIT

bazelisk build //:image >"$stage/build.log" 2>&1

qemu_run() {
    local serial_target="$1"
    local command_line="$2"
    local debug_target="$3"
    local status

    set +e
    timeout --kill-after=5s 20s qemu-system-i386 \
        -cpu 486 \
        -drive "file=bazel-bin/image.bin,format=raw,snapshot=on" \
        -m 64M -display none -no-reboot \
        -serial "file:$serial_target" \
        -debugcon "file:$debug_target" \
        -fw_cfg "name=opt/cmdline,string=$command_line" \
        >/dev/null 2>&1
    status=$?
    set -e

    # The normal interactive kernel does not exit by itself. A timeout is the
    # expected result. QEMU also returns 1 for the guest's orderly shutdown on
    # the current BIOS path, so accept that status only after log assertions.
    case "$status" in
        0|1|124|137|143) ;;
        *)
            echo "QEMU exited unexpectedly with status $status" >&2
            return "$status"
            ;;
    esac
}

qemu_run "$serial_log" "serial=com1" "$debug_log"

for expected in \
    'serial: Com1 logging enabled' \
    'RetroOS Rust Kernel' \
    'Block devices initialized'; do
    grep -aFq "$expected" "$serial_log"
    grep -aFq "$expected" "$debug_log"
done

# Without serial=, the COM1 chardev is present but the kernel must not write to
# it. Debugcon remains the normal logging path for this boot.
qemu_run "$no_serial_log" "" "$stage/no-serial-debug.log"
test ! -s "$no_serial_log"

echo "PASS: QEMU serial logging"
