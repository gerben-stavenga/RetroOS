#!/bin/bash
# Differential engine test: boot the same image to Dos Navigator on BOTH
# hosted engines (TCG and KVM) and require the final VGA text screens to be
# identical, modulo the boot clock (virtual vs real time). Divergence means
# one engine mis-executed something — a far tighter net than "didn't panic",
# which is all the per-engine game cases can assert.
#
# Skips cleanly (exit 0) when /dev/kvm is unavailable, so CI stays green on
# runners without virtualization.
set -uo pipefail
cd "$(dirname "$0")/.."

IMG=bazel-bin/image.bin
TCG=bazel-bin/kernel/retroos-host
KVM=bazel-bin/kernel/retroos-host-kvm

[ -f "$IMG" ] || { echo "no $IMG — run: bazelisk build //:image"; exit 1; }
if ! { : <> /dev/kvm; } 2>/dev/null; then
    echo "SKIP: /dev/kvm unavailable — differential engine test not run"
    exit 0
fi
for bin in "$TCG" "$KVM"; do
    [ -f "$bin" ] || { echo "no $bin — run: bazelisk build //kernel:$(basename "$bin") --platforms=@platforms//host"; exit 1; }
done

shot_tcg=$(mktemp /tmp/retroos-diff-tcg.XXXX.txt)
shot_kvm=$(mktemp /tmp/retroos-diff-kvm.XXXX.txt)
trap 'rm -f "$shot_tcg" "$shot_kvm"' EXIT

boot() { # boot <host-bin> <shot-file>
    python3 test/hosted_test.py --host-bin "$1" --image "$IMG" --keys "" \
        --settle 6 --timeout 20 --screenshot "$2" \
        --expect-screen "free bytes on drive"
}
boot "$TCG" "$shot_tcg" || { echo "FAIL: TCG boot"; exit 1; }
boot "$KVM" "$shot_kvm" || { echo "FAIL: KVM boot"; exit 1; }

# Mask the DN clock (top-right HH:MM:SS): TCG counts virtual time, KVM real.
mask() { sed -E 's/[0-9]{2}:[0-9]{2}:[0-9]{2}/@@:@@:@@/g' "$1"; }

if diff <(mask "$shot_tcg") <(mask "$shot_kvm") > /tmp/retroos-diff-engines.txt; then
    echo "PASS: TCG and KVM screens identical (clock masked)"
else
    echo "FAIL: engine screens diverge (see below)"
    cat /tmp/retroos-diff-engines.txt
    exit 1
fi
