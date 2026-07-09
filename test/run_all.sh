#!/bin/bash
# Single entry point for the RetroOS test suite.
#
# Runs every test, skipping any whose prerequisites are absent on this host, so
# the same script is correct in both places:
#   - CI (GitHub-hosted: no QEMU, no /dev/kvm, no proprietary assets) runs the
#     hosted-TCG subset;
#   - a local run (QEMU + KVM + apps-proprietary present) runs everything.
#
# Adding a test: add one `run` line below — it is then covered in CI and
# locally automatically, gated on its prerequisites.
#
# Exits non-zero iff a test that actually RAN failed. Set RETRO_TEST_ONLY to a
# space-separated name list to run a subset (e.g. RETRO_TEST_ONLY="dpmi_hx").
set -u
cd "$(dirname "$0")/.."

pass=0 fail=0 skip=0
declare -a failed=()

have()      { command -v "$1" >/dev/null 2>&1; }
kvm()       { [ -r /dev/kvm ] && [ -w /dev/kvm ]; }
qemu_prop() { have qemu-system-i386 && [ -e apps-proprietary ]; }

# run <name> <gate-fn|-> <cmd...>
run() {
    local name="$1" gate="$2"; shift 2
    if [ -n "${RETRO_TEST_ONLY:-}" ] && [[ " $RETRO_TEST_ONLY " != *" $name "* ]]; then
        return
    fi
    if [ "$gate" != "-" ] && ! "$gate"; then
        printf 'SKIP  %-14s (prereq: %s)\n' "$name" "$gate"; skip=$((skip + 1)); return
    fi
    printf '\n========== RUN %s ==========\n' "$name"
    if "$@"; then
        printf 'PASS  %s\n' "$name"; pass=$((pass + 1))
    else
        printf 'FAIL  %s\n' "$name"; fail=$((fail + 1)); failed+=("$name")
    fi
}

# --- Hosted TCG: no QEMU / KVM / proprietary needed (CI-safe) ---------------
run hosted_games -         bash test/hosted_games.sh
run dpmi_hx      -         bash test/dpmi_hx.sh
# --- KVM differential: needs /dev/kvm --------------------------------------
run hosted_diff  kvm       bash test/hosted_diff.sh
# --- QEMU + proprietary assets (image_proprietary) -------------------------
run dpmi_smoke   qemu_prop bash test/dpmi_smoke.sh   # qemu + BORLANDC/BCC
run dark_smoke   qemu_prop bash test/dark_smoke.sh   # qemu + DFORCES

printf '\n==== %d passed, %d failed, %d skipped ====\n' "$pass" "$fail" "$skip"
if [ "${#failed[@]}" -ne 0 ]; then
    printf 'FAILED: %s\n' "${failed[*]}"
    exit 1
fi
