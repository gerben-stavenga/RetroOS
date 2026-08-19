#!/bin/bash
# QEMU HostFS reconnect test.
#
# Exercise both endpoint restart directions through the persistent proxy:
# hostfs.py disappears while QEMU remains alive, then QEMU/guest disappears
# while HostFS remains alive. Both replacements must establish a new RHFS
# session over the selected UART. This uses no CTS/DSR assumptions and exercises the same
# protocol used by the physical serial transport.
set -euo pipefail
cd "$(dirname "$0")/.."
source test/lib/qemu_hostfs_common.sh

hostfs_port="${1:-com1}"
qemu_hostfs_set_serial_args "$hostfs_port"

stage=$(mktemp -d -t retroos-qemu-hostfs-lifecycle.XXXXXX)
qemu_sock="$stage/qemu.sock"
hostfs_sock="$stage/hostfs.sock"
root="$stage/root"
log1="$stage/guest1.log"
log2="$stage/guest2.log"
transport_log="$stage/hostfs-transport.log"
proxy_pid=""
server_pid=""
qemu_pid=""
wait_for_qemu() {
    local pid="$1" status
    if wait "$pid"; then
        status=0
    else
        status=$?
    fi
    qemu_pid=""
    if [ "$status" -ne 0 ]; then
        echo "QEMU exited with unexpected status $status" >&2
        return "$status"
    fi
}
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        qemu_dump_log 'guest 1 log' "$log1"
        qemu_dump_log 'guest 2 log' "$log2"
        qemu_dump_log 'HostFS log' "$transport_log"
    fi
    if [ -n "$qemu_pid" ]; then
        qemu_stop_and_reap "$qemu_pid"
    fi
    if [ -n "$server_pid" ]; then
        qemu_stop_and_reap "$server_pid"
    fi
    if [ -n "$proxy_pid" ]; then
        qemu_stop_and_reap "$proxy_pid"
    fi
    rm -rf "$stage"
    return "$status"
}
trap cleanup EXIT

qemu_bazel build //:image >"$stage/build.log" 2>&1

mkdir -p "$root"
printf 'HELLO' > "$root/HELLO.TXT"

# Start the two-ended proxy first. It connects to QEMU when QEMU creates its
# socket and accepts hostfs.py independently.
PYTHONUNBUFFERED=1 python3 test/hostfs_proxy.py "$qemu_sock" "$hostfs_sock" >"$transport_log" 2>&1 &
proxy_pid=$!

PYTHONUNBUFFERED=1 python3 hostfs.py "$root" "$hostfs_sock" >>"$transport_log" 2>&1 &
server_pid=$!

qemu_args=(
    -cpu 486
    -drive "file=bazel-bin/image.bin,format=raw,snapshot=on"
    -m 64M -display none -no-reboot
)
qemu_args+=("${QEMU_HOSTFS_SERIAL_ARGS[@]}")
qemu_args+=(
    -chardev "socket,id=hostfs,path=$qemu_sock,server=on,wait=on"
)

# First guest: keep QEMU alive while HostFS is taken away and restored.
timeout --kill-after=5s 60s qemu-system-i386 "${qemu_args[@]}" \
    -debugcon "file:$log1" \
    -fw_cfg "name=opt/cmdline,string=hostfs=$hostfs_port;TESTS/HFSOPS.COM;TESTS/HFSRECV.COM" \
    >/dev/null 2>&1 &
qemu_pid=$!

qemu_wait_for_log "$log1" 'HFSOPS-OK' 30 "$qemu_pid" "$proxy_pid" "$server_pid"
test -d "$root/HFSOPS"
qemu_wait_for_log "$log1" 'HFS-RECOVER-WAIT' 30 "$qemu_pid" "$proxy_pid" "$server_pid"

# Remove only hostfs.py. The proxy keeps QEMU's socket and drains bytes while
# the guest's current operation times out.
kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
# Require the guest to observe a real bounded failure before restoring the
# server. This prevents a pre-outage success from satisfying the recovery
# assertion.
qemu_wait_for_log "$log1" 'HFS-RECOVER-OUTAGE' 30 "$qemu_pid" "$proxy_pid"

# Restart hostfs.py on the independent HostFS-facing socket. The guest retries
# RHFS and should recover without restarting QEMU.
PYTHONUNBUFFERED=1 python3 hostfs.py "$root" "$hostfs_sock" >>"$transport_log" 2>&1 &
server_pid=$!
qemu_wait_for_log "$log1" 'HFS-RECOVER-OK' 30 "$qemu_pid" "$proxy_pid" "$server_pid"

# The recovered guest exits. Keep hostfs.py and the proxy alive while QEMU's
# side disappears, then boot a replacement guest.
wait_for_qemu "$qemu_pid"
# Second guest: QEMU creates a new socket server and the proxy reconnects.
timeout --kill-after=5s 60s qemu-system-i386 "${qemu_args[@]}" \
    -debugcon "file:$log2" \
    -fw_cfg "name=opt/cmdline,string=hostfs=$hostfs_port;TESTS/HFS_PROBE.COM" \
    >/dev/null 2>&1 &
qemu_pid=$!
wait_for_qemu "$qemu_pid"
grep -q 'HFS-PROBE-OK' "$log2"

echo "PASS: QEMU guest restart and HostFS session recovery ($hostfs_port)"
