#!/bin/bash
# Single entry point for the RetroOS test suite.
#
# Runs every test, skipping any whose prerequisites are absent on this host, so
# the same script is correct in both places:
#   - CI installs QEMU/Bochs and requires the KVM suites when the runner has
#     /dev/kvm, but has no proprietary assets;
#   - a local run (QEMU + KVM + apps-proprietary present) runs everything.
#
# Adding a test: add one `run` line below — it is then covered in CI and
# locally automatically, gated on its prerequisites.
#
# Exits non-zero if a test fails or a required prerequisite is missing.
# Set RETRO_TEST_ONLY to a
# space-separated name list to run a subset (e.g. RETRO_TEST_ONLY="dpmi_hx").
# RETRO_REQUIRE_KVM=1 makes missing KVM a failure instead of an optional skip.
# RETRO_REQUIRE_PUBLIC=1 requires every non-proprietary, non-desktop suite; the
# KVM-gated ones stay optional under it unless RETRO_REQUIRE_KVM=1 too, so a
# host without the device is not a failure.
set -u
cd "$(dirname "$0")/.."

pass=0 fail=0 skip=0
declare -a failed=()

have()      { command -v "$1" >/dev/null 2>&1; }
kvm()       { { : <> /dev/kvm; } 2>/dev/null; }
qemu_prop() { have qemu-system-i386 && [ -e apps-proprietary ]; }
bazel_tool() { have bazelisk || have bazel; }
module_tools() { have bazelisk && have debugfs && have mkfs.ext4; }
module_qemu() { module_tools && have qemu-system-i386; }
python3_test() { have python3; }
qemu_hostfs() { bazel_tool && have qemu-system-i386 && have python3 && have timeout; }
qemu_hostfs_grub() { qemu_hostfs && have grub-mkrescue && have debugfs && have mkfs.ext4; }
qemu_serial() { bazel_tool && have qemu-system-i386 && have timeout; }
qemu_audio() { bazel_tool && have qemu-system-x86_64 && have grub-mkstandalone && have mformat && have mmd && have mcopy && have timeout && have python3 && [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] && [ -f /usr/lib/grub/x86_64-efi/modinfo.sh ]; }
# /dev/kvm opening is NOT the same as "qemu can boot THIS guest with -accel
# kvm". Under a GitHub runner's nested virtualization qemu accepts -accel kvm
# and then resets the guest before the BIOS emits a byte; -no-reboot renders
# that as a silent exit 0. An empty qemu (no disk) does NOT show it — SeaBIOS
# idles at "no bootable device" quite happily — so the probe has to boot the
# real image, and it boots it under TCG too:
#
#   boots under kvm            -> yes, run the kvm tests
#   boots under tcg, not kvm   -> this host's kvm cannot run it: skip
#   boots under neither        -> that is our bug, not the host's: run them so
#                                 they fail loudly
#
# Probed once; the image is the one the tests use anyway.
QEMU_KVM_OK=
qemu_kvm_boots() { # <accel> — echoes the guest's first debugcon bytes
    timeout 25 qemu-system-x86_64 -accel "$1" -m 256 -display none -no-reboot \
        -debugcon stdio -serial none \
        -drive file="$QEMU_KVM_IMG",format=raw,if=ide 2>/dev/null | head -c 200
}
qemu_kvm() {
    have qemu-system-x86_64 && kvm || return 1
    if [ -z "$QEMU_KVM_OK" ]; then
        # A probe that cannot run must not quietly disable the tests: every
        # failure here answers "yes, run them" so the tests report it.
        QEMU_KVM_OK=yes
        if ! bz build //:image >/dev/null 2>&1; then
            echo "qemu_kvm: cannot build //:image to probe with; running the" \
                 "kvm tests anyway" >&2
            return 0
        fi
        QEMU_KVM_IMG="$(mktemp -t retroos-kvm-probe.XXXXXX.img)"
        if ! cp "$(bz info bazel-bin 2>/dev/null)/image.bin" "$QEMU_KVM_IMG"; then
            echo "qemu_kvm: cannot copy the image to probe with; running the" \
                 "kvm tests anyway" >&2
            rm -f "$QEMU_KVM_IMG"
            return 0
        fi
        chmod u+w "$QEMU_KVM_IMG"
        if [ -n "$(qemu_kvm_boots kvm)" ]; then
            QEMU_KVM_OK=yes
        elif [ -z "$(qemu_kvm_boots tcg)" ]; then
            echo "qemu_kvm: the image boots under NEITHER kvm nor tcg — running" \
                 "the kvm tests so they report it" >&2
            QEMU_KVM_OK=yes
        else
            echo "qemu_kvm: qemu boots this image under tcg but not kvm;" \
                 "skipping the qemu kvm tests on this host" >&2
            QEMU_KVM_OK=no
        fi
        rm -f "$QEMU_KVM_IMG"
    fi
    [ "$QEMU_KVM_OK" = yes ]
}
qemu_audio_kvm() { qemu_audio && qemu_kvm; }
bochs_tools() { bazel_tool && have bochs && have python3 && have mcopy && have mtype && have setsid; }
grub_fat() { have bazelisk && have qemu-system-i386 && have grub-mkrescue && have xorriso && have gcc && have mkfs.fat && have mmd && have mcopy && have python3; }
machine_layout() { grub_fat && have qemu-system-x86_64 && have mkfs.ext4 && have e2fsck && [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] && [ -f /usr/share/OVMF/OVMF_VARS_4M.fd ]; }
dn_state() { have bazelisk && have qemu-system-i386 && have mkfs.fat && have mmd && have mcopy && have mtype && have mdir && have python3; }
# 86Box is a GUI app: it needs the emulator installed AND somewhere to draw.
box86()     { [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && { [ -x "$HOME/bin/86Box.AppImage" ] \
                || have 86box || { have flatpak && flatpak list --app --columns=application \
                2>/dev/null | grep -qi 86box; }; }; }
freedos_hdd() { have nasm && have mcopy && have mtype && have timeout \
                && { have qemu-system-i386 || have qemu-system-x86_64; } \
                && [ -f freedos/freedos_hdd.img ] && [ -f freedos/.installed ] \
                && [ -f freedos/hx/HDPMI32I.EXE ]; }
bz()        { if have bazelisk; then bazelisk "$@"; else bazel "$@"; fi; }

# Rust unit tests, on the host platform. Kept separate from the KVM one below
# so a machine without /dev/kvm still runs the rest.
unit() {
    bz test --platforms=@platforms//host \
        //arch-abi:arch_abi_test //kernel:kernel_unit_test \
        //lib:sound_test //lib:vga_test //lib:heap_test //lib:compact_fmt_test \
        //ext4:ext4_test //ext4:modern_image_test //third_party/voodoo:voodoo_test \
        //arch-interp:arch-interp-test //arch-interp:mmu-test
}
unit_kvm() { bz test --platforms=@platforms//host --test_env=RETRO_REQUIRE_KVM=1 //arch-interp:arch-interp-kvm-test; }

# run <name> <gate-fn|-> <cmd...>
run() {
    local name="$1" gate="$2"; shift 2
    if [ -n "${RETRO_TEST_ONLY:-}" ] && [[ " $RETRO_TEST_ONLY " != *" $name "* ]]; then
        return
    fi
    if [ "$gate" != "-" ] && ! "$gate"; then
        # RETRO_REQUIRE_KVM guards the HOSTED engine's tests, whose only
        # prerequisite is that /dev/kvm opens: if the device is there and they
        # do not run, coverage was lost silently. qemu_audio_kvm is not in that
        # bucket — it probes whether qemu can actually boot a guest under kvm,
        # which /dev/kvm opening does not imply, and skips honestly when it
        # cannot (a GitHub runner's nested virt).
        local needs_kvm=0
        [ "$gate" = kvm ] && needs_kvm=1
        if { [ "${RETRO_REQUIRE_PUBLIC:-0}" = 1 ] && [ "$needs_kvm" = 0 ] \
                && [[ "$gate" != qemu_prop && "$gate" != box86 \
                      && "$gate" != qemu_audio_kvm && "$gate" != freedos_hdd ]]; } \
            || { [ "${RETRO_REQUIRE_KVM:-0}" = 1 ] && [ "$needs_kvm" = 1 ]; }; then
            printf 'FAIL  %-14s (required prerequisite: %s)\n' "$name" "$gate"
            fail=$((fail + 1)); failed+=("$name"); return
        fi
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
run grub_fat     grub_fat  python3 test/grub_fat.py
run machine_layout machine_layout python3 test/machine_layout.py
run dn_state     dn_state  python3 test/dn_state.py
run module_games_metadata module_tools bash test/grub_module_games_metadata.sh
run module_disk   module_qemu   bash test/grub_module_physical_fallback.sh
run module_program module_qemu   bash test/grub_module_program.sh
# --- Hosted TCG: no QEMU / KVM / proprietary needed (CI-safe) ---------------
run hosted_games -         env ENGINE=tcg bash test/hosted_games.sh
run lfn          -         env ENGINE=tcg python3 test/lfn.py
run dpmi_hx      -         env ENGINE=tcg bash test/dpmi_hx.sh
run xms          -         env ENGINE=tcg bash test/xms.sh
run dpmi_vif     -         env ENGINE=tcg bash test/dpmi_vif.sh
run dpmi_hdpmi_pvi freedos_hdd bash test/dpmi_hdpmi_pvi.sh
run hosted_games_kvm kvm   env ENGINE=kvm bash test/hosted_games.sh
run lfn_kvm      kvm       env ENGINE=kvm python3 test/lfn.py
run dpmi_hx_kvm  kvm       env ENGINE=kvm bash test/dpmi_hx.sh
run xms_kvm      kvm       env ENGINE=kvm bash test/xms.sh
run dpmi_vif_kvm kvm       env ENGINE=kvm bash test/dpmi_vif.sh
# --- KVM differential: needs /dev/kvm --------------------------------------
run hosted_diff  kvm       bash test/hosted_diff.sh
run unit_kvm     kvm       unit_kvm
# --- HostFS launcher and protocol tests -------------------------------------

run shared_disks python3_test python3 test/shared_disks.py
run hostfs_protocol python3_test python3 test/hostfs_protocol.py
run hostfs_socket python3_test python3 test/hostfs_socket_reconnect.py
run audio_pcm_unit python3_test python3 test/audio_steady_unit.py

# --- QEMU HostFS integration (requires QEMU and Python) ---------------------
run qemu_hostfs_lifecycle_com1 qemu_hostfs bash test/qemu_hostfs_lifecycle.sh com1
run qemu_root_policy qemu_hostfs_grub bash test/qemu_root_failure.sh
run qemu_serial_logging qemu_serial bash test/qemu_serial_logging.sh
run audio_matrix qemu_audio bash test/audio_matrix.sh
run audio_matrix_kvm qemu_audio_kvm bash test/audio_matrix.sh --kvm
# Only under KVM: this one measures sustained real-time PCM, and a host that
# cannot run the guest at real time loses PIT ticks, which crawls the music and
# reads as a dropout that is not there. TCG audio coverage is audio_matrix,
# which checks the driver paths rather than wall-clock continuity.
run audio_steady_kvm qemu_audio_kvm bash test/audio_steady.sh --kvm

run dpmi_smoke   qemu_prop bash test/dpmi_smoke.sh   # qemu + BORLANDC/BCC
run dark_smoke   qemu_prop bash test/dark_smoke.sh   # qemu + DFORCES
# --- Bochs metal backend, public probes with a headless SDL driver --------
run bochs_smoke  bochs_tools bash test/bochs_smoke.sh
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
