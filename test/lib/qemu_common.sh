#!/bin/bash
# Common helpers for bounded QEMU shell tests.

qemu_bazel() {
    if command -v bazelisk >/dev/null 2>&1; then
        bazelisk "$@"
    elif command -v bazel >/dev/null 2>&1; then
        bazel "$@"
    else
        echo 'QEMU test requires bazelisk or bazel' >&2
        return 127
    fi
}

qemu_wait_for_log() {
    local log="$1" needle="$2" timeout_seconds="${3:-30}"
    local deadline=$((SECONDS + timeout_seconds))
    shift 3
    while (( SECONDS < deadline )); do
        if grep -q "$needle" "$log" 2>/dev/null; then
            return 0
        fi
        local pid
        for pid in "$@"; do
            if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
                echo "process $pid exited while waiting for $needle" >&2
                return 1
            fi
        done
        sleep 0.1
    done
    echo "timed out waiting for $needle in $log" >&2
    return 1
}

qemu_stop_and_reap() {
    local pid="${1:-}"
    [[ -n "$pid" ]] || return 0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

qemu_dump_log() {
    local label="$1" path="$2"
    echo "---- $label ----" >&2
    tail -80 "$path" >&2 2>/dev/null || true
}
