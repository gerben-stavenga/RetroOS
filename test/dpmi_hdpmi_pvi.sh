#!/bin/bash
# FreeDOS + HDPMI32I + SETPVI: ring-3 IOPL=0 DPMI host with CR4.PVI, then
# VIFIRET.COM /H (hardware VIF must survive a 32-bit CS IRETD).
#
# This is the non-RetroOS host for the 86Box pmodeiret(is32) VIF bug.
# QEMU --kvm (or -cpu pentium) executes IRETD on a real/emulated Pentium+;
# unpatched 86Box fails the same probe at stage 6.
#
# Needs: nasm, mtools, qemu, a FreeDOS HDD (freedos/freedos_hdd.img after
# `./run.sh qemu -i freedos` has been installed). JEMM is not loaded —
# SETPVI's MOV CR4 only works in real mode.
set -euo pipefail
cd "$(dirname "$0")/.."

HDD_SRC="${HDD_IMG:-freedos/freedos_hdd.img}"
HDPMI="${HDPMI:-freedos/hx/HDPMI32I.EXE}"
[ -f "$HDD_SRC" ] || { echo "FAIL: no FreeDOS HDD at $HDD_SRC" >&2; exit 2; }
[ -f "$HDPMI" ] || { echo "FAIL: missing $HDPMI" >&2; exit 2; }
[ -f freedos/.installed ] || { echo "FAIL: FreeDOS not installed (freedos/.installed)" >&2; exit 2; }

nasm -f bin -o /tmp/SETPVI.COM test/dos/setpvi/setpvi.asm
nasm -f bin -o /tmp/VIFIRET.COM test/dos/vifiret/vifiret.asm

WORK=$(mktemp -d -t retroos-hdpmi-pvi.XXXXXX)
cleanup() { rm -rf "$WORK"; }
if [ "${KEEP_WORK:-0}" != 1 ]; then
    trap cleanup EXIT
fi

cp --reflink=auto "$HDD_SRC" "$WORK/hdd.img"
chmod u+w "$WORK/hdd.img"
FAT="$WORK/hdd.img@@32256"

mcopy -D o -i "$FAT" "$HDPMI" ::HDPMI32I.EXE
mcopy -D o -i "$FAT" /tmp/SETPVI.COM ::SETPVI.COM
mcopy -D o -i "$FAT" /tmp/VIFIRET.COM ::VIFIRET.COM

# HIMEMX only: real mode + XMS. Default menu 2 loads JEMMEX, which is VM86
# and makes SETPVI's MOV CR4 #GP. CRLF: FreeDOS CONFIG.SYS ignores Unix LF.
crlf() { sed $'s/$/\r/' "$1" > "$2"; }
cat > "$WORK/FDCONFIG.unix" <<'EOF'
DOS=HIGH
LASTDRIVE=Z
BUFFERS=20
FILES=40
DEVICE=C:\FREEDOS\BIN\HIMEMX.EXE
SHELL=C:\COMMAND.COM C:\ /E:1024 /P=C:\FDAUTO.BAT
EOF
cat > "$WORK/FDAUTO.unix" <<'EOF'
@ECHO OFF
C:
ECHO START>C:\SETUP.LOG
HDPMI32I.EXE -r -b >C:\HDPMI.LOG
ECHO HDPMI>>C:\SETUP.LOG
SETPVI.COM
IF ERRORLEVEL 1 GOTO FAIL
ECHO SETPVI>>C:\SETUP.LOG
ECHO BEFOREVIF>>C:\SETUP.LOG
VIFIRET.COM /H
IF ERRORLEVEL 1 GOTO VF
ECHO EL0>>C:\SETUP.LOG
GOTO CONT
:VF
ECHO EL1>>C:\SETUP.LOG
:CONT
ECHO AFTERVIF>>C:\SETUP.LOG
GOTO OFF
:FAIL
ECHO SETPVI FAIL>C:\VIFIRET.LOG
:OFF
C:\FREEDOS\BIN\FDAPM.COM POWEROFF
EOF
crlf "$WORK/FDCONFIG.unix" "$WORK/FDCONFIG.SYS"
crlf "$WORK/FDAUTO.unix" "$WORK/FDAUTO.BAT"
mcopy -D o -i "$FAT" "$WORK/FDCONFIG.SYS" ::FDCONFIG.SYS
mcopy -D o -i "$FAT" "$WORK/FDAUTO.BAT" ::FDAUTO.BAT
mdir -i "$FAT" :: | grep -iE 'HDPMI|SETPVI|VIFIRET|FDAUTO|FDCONFIG'
GOLD="$WORK/gold.img"
cp --reflink=auto "$WORK/hdd.img" "$GOLD"

verdict_of() {
    mtype -i "$1@@32256" ::VIFIRET.LOG 2>/dev/null || true
}

run_qemu() {
    local img="$1"
    QEMU=qemu-system-i386
    ACCEL=(-cpu pentium)
    if [ -c /dev/kvm ] && command -v qemu-system-x86_64 >/dev/null; then
        QEMU=qemu-system-x86_64
        ACCEL=(-accel kvm -cpu host)
    fi
    command -v "$QEMU" >/dev/null || { echo "SKIP qemu: no $QEMU" >&2; return 2; }
    echo "Using $QEMU ${ACCEL[*]}" >&2
    timeout 120 "$QEMU" "${ACCEL[@]}" -m 64 -display none -no-reboot \
        -drive "file=$img,format=raw" \
        -serial "file:$WORK/serial.log" \
        </dev/null >/dev/null 2>"$WORK/qemu.err" || true
    verdict_of "$img"
}

run_86box() {
    local img="$1" tag="$2" bin="$3"
    local vm="$WORK/vm-$tag"
    mkdir -p "$vm"
    # Keep the HDD *outside* the VM dir. 86Box rewrites in-dir paths to
    # relative names; a working FreeDOS VM uses an absolute path and boots.
    # Relative disk.img here left AMI with no C: (ROM BASIC).
    local disk="$WORK/hdd-$tag.img"
    cp --reflink=auto "$img" "$disk"
    chmod u+w "$disk"
    nvr="$HOME/.var/app/net._86box._86Box/data/86Box/RetroOS-FreeDOS/nvr"
    if [ -d "$nvr" ]; then cp -a "$nvr" "$vm/nvr"; fi
    cat > "$vm/86box.cfg" <<EOF
[General]
vid_renderer = qt_software
window_remember = 0
sound_gain = 0

[Machine]
machine = tx97
cpu_family = pentium_p54c
cpu_speed = 166666666
cpu_multi = 2.5
cpu_use_dynarec = 0
fpu_type = internal
mem_size = 65536
time_sync = local

[Video]
gfxcard = vga

[Input devices]
keyboard_type = keyboard_ps2
mouse_type = ps2

[Sound]
sndcard = none

[Storage controllers]
fdc_type = internal

[Hard disks]
hdd_01_fn = $disk
hdd_01_ide_channel = 0:0
hdd_01_parameters = 63, 16, 520, 0, ide

[Floppy and CD-ROM drives]
fdd_01_type = 35_2hd
fdd_02_type = none
EOF
    export DISPLAY="${DISPLAY:-:1}" QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-xcb}"
    local root fp
    root=$(cd "${RETROOS_86BOX_SOURCE:-$(pwd)/../86Box}" && pwd)
    fp=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
    echo "86box $tag: $bin" >&2
    if [ -n "$fp" ]; then
        setsid flatpak run --devel --env=QT_QPA_PLATFORM="$QT_QPA_PLATFORM" \
            --filesystem="$vm" --filesystem="$WORK" --filesystem="$(dirname "$bin")" --filesystem="$root" \
            --command="$bin" "$fp" --vmpath "$vm" \
            >"$WORK/86box-$tag.log" 2>&1 &
    else
        setsid "$bin" --vmpath "$vm" >"$WORK/86box-$tag.log" 2>&1 &
    fi
    local pid=$! waited=0 v=""
    while [ "$waited" -lt 180 ]; do
        sleep 5
        waited=$((waited + 5))
        v=$(verdict_of "$disk")
        [ -n "$v" ] && break
        setup=$(mtype -i "$disk@@32256" ::SETUP.LOG 2>/dev/null || true)
        if printf '%s' "$setup" | grep -q 'EL0'; then
            v="VIFIRET PASS"
            break
        fi
        if printf '%s' "$setup" | grep -q 'EL1'; then
            v="VIFIRET FAIL stage ?"
            break
        fi
        # flatpak reparents 86Box; the wrapper pid exiting is not the guest.
        echo "86box $tag wait ${waited}s" >&2
    done
    local pgid
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    if [ -n "$pgid" ]; then
        kill -TERM -- -"$pgid" 2>/dev/null || true
        sleep 2
        kill -KILL -- -"$pgid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
    [ -n "$v" ] || v=$(verdict_of "$disk")
    grep -E '86Box v|Configuration file' "$WORK/86box-$tag.log" | head -5 >&2
    grep -E 'hdd_01_fn' "$vm/86box.cfg" >&2 || true
    echo "setup: $(mtype -i "$disk@@32256" ::SETUP.LOG 2>/dev/null || echo missing)" >&2
    printf '%s' "$v"
}

BACKEND="${BACKEND:-qemu}"
BOXSRC="${RETROOS_86BOX_SOURCE:-$(pwd)/../86Box}"
BOXBIN="$BOXSRC/build/regular/src/86Box"
SAVE_UNPATCHED="${SAVE_UNPATCHED:-/tmp/86box-vif-ab/86Box.unpatched}"
SAVE_PATCHED="${SAVE_PATCHED:-/tmp/86box-vif-ab/86Box.patched}"

restore_box() {
    if [ -n "${BOX_SAVED:-}" ] && [ -f "$BOX_SAVED" ]; then
        cp -a "$BOX_SAVED" "$BOXBIN"
        echo "restored $BOXBIN"
    fi
}

run_one_qemu() {
    cp --reflink=auto "$GOLD" "$WORK/hdd.img"
    run_qemu "$WORK/hdd.img"
}

case "$BACKEND" in
    qemu)
        V=$(run_one_qemu)
        echo "VIFIRET.LOG: ${V:-<missing>}"
        echo "SETUP.LOG: $(mtype -i "$WORK/hdd.img@@32256" ::SETUP.LOG 2>/dev/null || echo '<missing>')"
        echo "---- HDPMI.LOG ----"
        mtype -i "$WORK/hdd.img@@32256" ::HDPMI.LOG 2>/dev/null || echo '<missing>'
        if printf '%s' "$V" | grep -q 'VIFIRET PASS'; then
            echo "PASS: HDPMI32I+SETPVI IRETD left hardware VIF set"
            exit 0
        fi
        echo "FAIL: HDPMI32I+SETPVI probe" >&2
        exit 1
        ;;
    compare)
        echo "===== QEMU KVM / native IRETD ====="
        QV=$(run_one_qemu)
        echo "qemu: ${QV:-<missing>}"
        echo
        echo "===== 86Box unpatched (HEAD pmodeiret) ====="
        if [ ! -x "$SAVE_UNPATCHED" ] || [ ! -x "$SAVE_PATCHED" ]; then
            echo "SKIP 86Box: need $SAVE_UNPATCHED and $SAVE_PATCHED" >&2
            echo "qemu=$QV"
            exit 2
        fi
        UV=$(run_86box "$GOLD" unpatched "$SAVE_UNPATCHED")
        echo "86box-old: ${UV:-<missing>}"
        echo
        echo "===== 86Box patched ====="
        PV=$(run_86box "$GOLD" patched "$SAVE_PATCHED")
        echo "86box-fixed: ${PV:-<missing>}"
        echo
        echo "======== HDPMI32I+SETPVI VIFIRET ========"
        echo "qemu kvm:    ${QV:-<missing>}"
        echo "86box old:   ${UV:-<missing>}"
        echo "86box fixed: ${PV:-<missing>}"
        printf '%s' "$QV" | grep -q 'VIFIRET PASS' || { echo "qemu did not PASS" >&2; exit 1; }
        printf '%s' "$UV" | grep -q 'VIFIRET FAIL' || { echo "unpatched 86Box did not FAIL" >&2; exit 1; }
        printf '%s' "$PV" | grep -q 'VIFIRET PASS' || { echo "patched 86Box did not PASS" >&2; exit 1; }
        echo "PASS: old 86Box fails, fixed 86Box and qemu kvm pass"
        exit 0
        ;;
    *)
        echo "BACKEND=qemu|compare" >&2
        exit 2
        ;;
esac
