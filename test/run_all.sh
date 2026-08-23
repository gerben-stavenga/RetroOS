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
bazel_tool() { have bazelisk || have bazel; }
module_tools() { have bazelisk && have debugfs && have mkfs.ext4; }
module_qemu() { module_tools && have qemu-system-i386; }
python3_test() { have python3; }
qemu_hostfs() { bazel_tool && have qemu-system-i386 && have python3 && have timeout; }
qemu_hostfs_grub() { qemu_hostfs && have grub-mkrescue && have debugfs && have mkfs.ext4; }
qemu_serial() { bazel_tool && have qemu-system-i386 && have timeout; }
# 86Box is a GUI app: it needs the emulator installed AND somewhere to draw.
box86()     { [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && { [ -x "$HOME/bin/86Box.AppImage" ] \
                || have 86box || { have flatpak && flatpak list --app --columns=application \
                2>/dev/null | grep -qi 86box; }; }; }
bz()        { if have bazelisk; then bazelisk "$@"; else bazel "$@"; fi; }

# Rust unit tests, on the host platform. Kept separate from the KVM one below
# so a machine without /dev/kvm still runs the rest.
unit() {
    bz test --platforms=@platforms//host \
        //arch-abi:arch_abi_test //kernel:kernel_unit_test \
        //lib:sound_test //lib:vga_test \
        //arch-interp:arch-interp-test //arch-interp:mmu-test
}
unit_kvm() { bz test --platforms=@platforms//host //arch-interp:arch-interp-kvm-test; }

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

# --- Rust unit tests: pure host builds, no devices at all (CI-safe) --------
run unit         -         unit
run module_games_metadata module_tools bash test/grub_module_games_metadata.sh
run module_disk   module_qemu   bash test/grub_module_physical_fallback.sh
run module_program module_qemu   bash test/grub_module_program.sh
# --- Hosted TCG: no QEMU / KVM / proprietary needed (CI-safe) ---------------
run hosted_games -         bash test/hosted_games.sh
run dpmi_hx      -         bash test/dpmi_hx.sh
# --- KVM differential: needs /dev/kvm --------------------------------------
run hosted_diff  kvm       bash test/hosted_diff.sh
run unit_kvm     kvm       unit_kvm
# --- HostFS launcher and protocol tests -------------------------------------

run hostfs_protocol python3_test python3 test/hostfs_protocol.py
run hostfs_socket python3_test python3 test/hostfs_socket_reconnect.py

# --- QEMU HostFS integration (requires QEMU and Python) ---------------------
run qemu_hostfs_lifecycle_com1 qemu_hostfs bash test/qemu_hostfs_lifecycle.sh com1
run qemu_root_policy qemu_hostfs_grub bash test/qemu_root_failure.sh
run qemu_serial_logging qemu_serial bash test/qemu_serial_logging.sh

run dpmi_smoke   qemu_prop bash test/dpmi_smoke.sh   # qemu + BORLANDC/BCC
run dark_smoke   qemu_prop bash test/dark_smoke.sh   # qemu + DFORCES
# --- Real Sound Blaster 16: 86Box is the only faithful one -----------------
# Never runs in CI (GUI app, no display on a hosted runner), and that is the
# point of listing it: the SB passthrough path has no other oracle, so a local
# run before touching vsb.rs is the only thing that covers it.
run sb_86box     box86     bash test/sb_86box.sh

printf '\n==== %d passed, %d failed, %d skipped ====\n' "$pass" "$fail" "$skip"
if [ "${#failed[@]}" -ne 0 ]; then
    printf 'FAILED: %s\n' "${failed[*]}"
    exit 1
fi
