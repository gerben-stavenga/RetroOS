#!/bin/bash
# Public guest probes on the metal backend under Bochs. Each boot uses a
# disposable image and SDL's dummy video driver, without a desktop.
set -euo pipefail
cd "$(dirname "$0")/.."
source test/lib/qemu_common.sh
qemu_bazel build //:image

work=$(mktemp -d -t retroos-bochs-test.XXXXXX)
pid=""
stop_probe() {
    local i
    if [ -n "$pid" ]; then
        kill -TERM -- "-$pid" 2>/dev/null || true
        for ((i = 0; i < 20; i++)); do
            kill -0 -- "-$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "-$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        pid=""
    fi
}
cleanup() {
    stop_probe
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_probe() {
    local name="$1" command="$2"
    shift 2
    local log="$work/$name.log"
    local completion='All commands done'
    # SVGAPROBE deliberately waits for a key after its final success marker.
    [ "$name" != vbe ] || completion='VBE-ALL-OK'
    # No sound card on a CI runner: Bochs' own lowlevel sound driver defaults
    # to ALSA, fails to open the default PCM and then dies with "*** buffer
    # overflow detected ***", taking the probe with it. These probes are XMS,
    # DPMI and VBE — sound plays no part — so point every lowlevel driver at
    # 'dummy'. SDL_* keeps SDL itself off the host's devices as well.
    VM_DIR="$work/$name" BOCHS_DISPLAY_LIBRARY=sdl2 SDL_VIDEODRIVER=dummy \
        SDL_AUDIODRIVER=dummy \
        setsid ./run.sh bochs -i image --cmd "$command" \
        'panic: action=fatal' 'speaker: enabled=0' \
        'sound: waveoutdrv=dummy, waveindrv=dummy, midioutdrv=dummy' >"$log" 2>&1 &
    pid=$!
    # Also stop on an early guest exit or panic; marker checks below still
    # require success. DPMI includes benchmarks, so allow slower CI CPUs.
    if ! qemu_wait_for_log "$log" "$completion\|All commands done\|KERNEL PANIC\|panicked\|SEGV" 300 "$pid"; then
        qemu_dump_log "$name" "$log"
        return 1
    fi
    stop_probe
    if grep -qiE 'KERNEL PANIC|panicked|SEGV|Segmentation' "$log"; then
        qemu_dump_log "$name" "$log"
        return 1
    fi
    local marker
    for marker in "$@"; do
        if ! grep -qF "$marker" "$log"; then
            echo "FAIL: Bochs $name missing $marker" >&2
            qemu_dump_log "$name" "$log"
            return 1
        fi
    done
    echo "PASS: Bochs $name"
}

run_probe xms TESTS/XMSPROBE.COM 'XMSPROBE PASS'
run_probe dpmi 'TESTS/DPMI.EXE -r' 'DPMI v0.90 host found' 'raw jump to real-mode' 'GDTR:'
run_probe vbe TESTS/SVGAPROBE.COM 'VBE-ALL-OK'
