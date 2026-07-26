#!/usr/bin/env bash
# 86Box SB configuration sweep — the reference for the REAL card.
#
# 86Box models an SB16/Pro faithfully (the DSP test register, the
# write-status busy flicker, a completion IRQ for a one-transfer block),
# which QEMU's sb16 does not — so the native/passthrough path and the
# physical-configuration sweep belong here, while QEMU stays the sink
# reference (test/audio_matrix.sh).
#
# The invariant is the one the whole SB design rests on: BLASTER declares
# what the GUEST sees, so SBTEST.COM (which pokes exactly that) must print
# its three protocol markers no matter where the real card is strapped.
#
# 86Box is a GUI application with no log to grep, so the probe writes its
# verdict to C:\SBTEST.LOG and this script reads it back out of the disk
# image afterwards — no screen scraping, and the same mechanism works for
# Bochs.
#
# Usage:
#   test/sb_86box.sh --learn          write a config with SB16 selected and
#                                     open 86Box so it records its own
#                                     per-device section (do this ONCE; then
#                                     paste the section into SB_SECTION below)
#   test/sb_86box.sh                  run the sweep
set -u
cd "$(dirname "$0")/.."

: "${BOX86:=}"
if [ -z "$BOX86" ]; then
    for c in "$HOME/bin/86Box.AppImage" /home/gerben/86Box/86Box-Linux-x86_64-b6130.AppImage; do
        [ -x "$c" ] && BOX86="$c" && break
    done
fi
[ -n "$BOX86" ] || { echo "86Box not found; set BOX86=/path/to/86Box.AppImage" >&2; exit 2; }

VM_DIR="${VM_DIR:-$HOME/.local/share/86Box/retroos-sbsweep}"
IMG="${IMG:-bazel-bin/image.bin}"

# Read C:\SBTEST.LOG out of the image the run just used. The DOS C: root is
# an ext4 subtree, so debugfs reads it without mounting (no root needed).
read_verdict() {
    local img="$1" part_off
    part_off=$(partx -g -o START -n 1 "$img" 2>/dev/null | tr -d ' ')
    [ -n "$part_off" ] || return 1
    debugfs -R "cat home/retroos/SBTEST.LOG" \
        <(dd if="$img" bs=512 skip="$part_off" 2>/dev/null) 2>/dev/null
}

if [ "${1:-}" = "--learn" ]; then
    mkdir -p "$VM_DIR"
    echo "Opening 86Box with SB16 selected. In Settings -> Sound -> Sound"
    echo "Blaster 16 -> Configure, set base/IRQ/DMA, then quit. The section"
    echo "86Box writes is what this script needs:"
    echo
    BOX86="$BOX86" ./run.sh 86box -i "$IMG" || true
    echo
    echo "--- per-device sections found in $VM_DIR/86box.cfg ---"
    awk '/^\[/{p=0} /Sound Blaster|SB16|sb16/{p=1} p' "$VM_DIR/86box.cfg" 2>/dev/null
    exit 0
fi

echo "The sweep needs 86Box's per-device config keys, which only 86Box"
echo "itself writes. Run:  test/sb_86box.sh --learn"
echo
echo "Then fill SB_SECTION here with the section it produced, parameterized"
echo "over base/irq/dma, and this script drives:"
echo "    for each (base, irq, dma8, dma16) x SB_AUDIO=native|mixed:"
echo "        write $VM_DIR/86box.cfg with that section"
echo "        run 86Box with --cmd TESTS/SBTEST.COM"
echo "        read_verdict \$IMG  ->  expect BUSY-OK, EDGE-OK, TC-OK"
echo
echo "read_verdict is implemented and testable on its own:"
read_verdict "$IMG" && echo "(verdict above, from $IMG)" || \
    echo "(no verdict in $IMG yet — run the probe once)"
