#!/bin/bash
# Unified RetroOS launcher. Consolidates run_qemu.sh, run_uefi.sh, run_bochs.sh,
# run_uefi_bochs.sh, run_86box.sh and run_interp.sh into ONE parameterized
# entry point. The old per-emulator scripts are now thin shims that forward
# here (so existing invocations and run_test.sh keep working unchanged).
#
# Usage: ./run.sh [BACKEND] [options] [-- passthrough emulator args]
#
#   BACKEND        qemu | bochs | 86box | hosted   (default: qemu)
#   --firmware     bios | uefi                     (default: bios; qemu/bochs only)
#   --sound        sb | ac97 | hda | none          (default: sb; ac97/hda qemu only,
#                                                   incl. qemu --firmware uefi)
#   --arch         386 | 686 | x64                 (default: 386; qemu/bochs only)
#   -i IMG         image|proprietary|ext4|grub|freedos
#                  Uniform across every backend AND firmware. Default: proprietary
#                  when apps-proprietary/ is present, else image. (grub/freedos are
#                  qemu-only; hosted accepts image|proprietary|ext4.)
#
#   qemu extras:   -r BIN            headless fw_cfg cmdline
#                  -h HOSTFS_DIR     host directory served over hostfs.py
#                  --headless        (uefi firmware) -display none
#                  --kvm             run on the host CPU (-accel kvm -cpu host):
#                                    near-metal semantics, no reboot
#   hosted extras: -c DOS_CMD / --cmd, -H hostdir / --host, -w WAV / --wav,
#                  -T (terminal/headless), -s SHOT / --screenshot, -t (trace)
#
#   Everything after `--` (or any unrecognized trailing arg) is passed through
#   to the underlying emulator, matching the original scripts' behavior.
#
# Old -> new mapping:
#   ./run_qemu.sh 386 -i image       ->  ./run.sh qemu --arch 386 -i image
#   AC97=1 ./run_qemu.sh             ->  ./run.sh qemu --sound ac97
#   HDA=1  ./run_qemu.sh             ->  ./run.sh qemu --sound hda
#   SOUND=0 ./run_qemu.sh            ->  ./run.sh qemu --sound none
#   ./run_uefi.sh -i image [--headless] -> ./run.sh qemu --firmware uefi -i image
#   ./run_bochs.sh 386 -i ...        ->  ./run.sh bochs --arch 386 -i ...
#   ./run_uefi_bochs.sh -i image     ->  ./run.sh bochs --firmware uefi -i image
#   ./run_86box.sh -i ...            ->  ./run.sh 86box -i ...
#   ./run_interp.sh ...              ->  ./run.sh hosted ...
#
# What changed vs the originals (now consistent across backends):
#   * -i takes the SAME keywords on every backend and firmware (incl. UEFI and
#     hosted); the old UEFI scripts' positional [img] path is gone.
#   * One default image rule everywhere: proprietary when apps-proprietary/ is
#     present, else image (see below).
#   * --sound is honored under qemu --firmware uefi too (was silently ignored).

set -e
set -o pipefail

usage() {
    sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# 1. Argument parsing
# ---------------------------------------------------------------------------

BACKEND="qemu"
FIRMWARE="bios"
SOUND="sb"
ARCH="386"
IMG=""            # resolved to a per-backend default later if empty
ARCH_SET=0        # whether the user explicitly passed --arch (for warnings)

# qemu-specific
START_BIN=""
HOSTFS_DIR="$HOME"
HOSTFS_DIR_SET=0
QEMU_HEADLESS=0
KVM=0             # --kvm: run on the host CPU via -accel kvm -cpu host (qemu only)

# hosted-specific
HOSTED_CMD=""
HOSTED_HOSTDIR=""
HOSTED_WAV=""
HOSTED_SHOT=""
HOSTED_TRACE=""
HOSTED_TERMINAL=""

# Passthrough args for the underlying emulator.
PASS=()

# Optional leading positional BACKEND.
case "${1:-}" in
    qemu|bochs|86box|hosted) BACKEND="$1"; shift ;;
    -h|--help|help)          usage 0 ;;
esac

while [ $# -gt 0 ]; do
    case "$1" in
        --backend)    BACKEND="$2"; shift 2 ;;
        --firmware)   FIRMWARE="$2"; shift 2 ;;
        --sound)      SOUND="$2"; shift 2 ;;
        --arch)       ARCH="$2"; ARCH_SET=1; shift 2 ;;
        -i|--image)   IMG="$2"; shift 2 ;;

        # qemu passthrough flags
        -r)           START_BIN="$2"; shift 2 ;;
        --headless)   QEMU_HEADLESS=1; shift ;;
        --kvm)        KVM=1; shift ;;

        # hosted flags (long + short forms)
        -c|--cmd)        HOSTED_CMD="$2"; shift 2 ;;
        -w|--wav)        HOSTED_WAV="$2"; shift 2 ;;
        -s|--screenshot) HOSTED_SHOT="$2"; shift 2 ;;
        -T)              HOSTED_TERMINAL=1; shift ;;
        -t|--trace)      HOSTED_TRACE=1; shift ;;

        # -h / --host are overloaded: hosted dir vs qemu hostfs dir.
        # -H is hosted hostdir; --host is hosted hostdir.
        --host)       HOSTED_HOSTDIR="$2"; shift 2 ;;
        -h)
            # In hosted backend, -h has no meaning (use -H/--host); for qemu it
            # is the hostfs dir. Disambiguate by backend.
            if [ "$BACKEND" = "hosted" ]; then
                usage 0
            else
                HOSTFS_DIR="$2"; HOSTFS_DIR_SET=1; shift 2
            fi
            ;;
        -H)
            # Hosted: host directory. (run_uefi.sh's --headless short form was
            # also -H, but for qemu uefi we accept --headless; keep -H = hosted.)
            HOSTED_HOSTDIR="$2"; shift 2
            ;;

        --help)       usage 0 ;;
        --)           shift; PASS+=("$@"); break ;;
        *)            PASS+=("$1"); shift ;;
    esac
done

# ---------------------------------------------------------------------------
# 2. Validate the sparse capability matrix
# ---------------------------------------------------------------------------

case "$BACKEND" in
    qemu|bochs|86box|hosted) ;;
    *) echo "run.sh: unknown backend '$BACKEND' (qemu|bochs|86box|hosted)" >&2; exit 1 ;;
esac

case "$FIRMWARE" in
    bios|uefi) ;;
    *) echo "run.sh: unknown firmware '$FIRMWARE' (bios|uefi)" >&2; exit 1 ;;
esac

case "$SOUND" in
    sb|ac97|hda|none) ;;
    *) echo "run.sh: unknown sound '$SOUND' (sb|ac97|hda|none)" >&2; exit 1 ;;
esac

# firmware=uefi only valid for qemu and bochs.
if [ "$FIRMWARE" = "uefi" ] && [ "$BACKEND" != "qemu" ] && [ "$BACKEND" != "bochs" ]; then
    echo "run.sh: --firmware uefi is only supported for the qemu and bochs backends (got '$BACKEND')." >&2
    exit 1
fi

# sound=ac97|hda only valid for qemu. bochs/86box drive sb via their own
# config; hosted ignores sound (it has a WAV sink instead).
if { [ "$SOUND" = "ac97" ] || [ "$SOUND" = "hda" ]; } && [ "$BACKEND" != "qemu" ]; then
    echo "run.sh: --sound $SOUND is only supported for the qemu backend." >&2
    echo "        bochs/86box only model SB16; hosted has no sound device (use -w to capture WAV)." >&2
    exit 1
fi

# arch is meaningless for 86box (fixed Pentium config) and hosted (host CPU).
if [ "$ARCH_SET" = 1 ] && { [ "$BACKEND" = "86box" ] || [ "$BACKEND" = "hosted" ]; }; then
    echo "run.sh: warning: --arch is ignored for the $BACKEND backend." >&2
fi

if [ "$BACKEND" = "qemu" ] || [ "$BACKEND" = "bochs" ]; then
    case "$ARCH" in
        386|686|x64) ;;
        *) echo "run.sh: unknown arch '$ARCH' (386|686|x64)" >&2; exit 1 ;;
    esac
fi

# --kvm is a QEMU accelerator (run on the host CPU via VT-x/AMD-V).
if [ "$KVM" = 1 ] && [ "$BACKEND" != "qemu" ]; then
    echo "run.sh: --kvm only applies to the qemu backend (got '$BACKEND')." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Shared helpers
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Consistent default across every backend/firmware: the full proprietary image
# when its assets are present, else the open-source image (so fresh checkouts
# without apps-proprietary/ still work). Override with -i.
if [ -z "$IMG" ]; then
    if [ -d "$SCRIPT_DIR/apps-proprietary" ]; then IMG="proprietary"; else IMG="image"; fi
fi

# find_bazel: superset of every original's candidate list.
find_bazel() {
    if command -v bazelisk >/dev/null 2>&1; then
        command -v bazelisk
        return
    fi
    if [ -x "$HOME/bin/bazelisk" ]; then
        printf '%s\n' "$HOME/bin/bazelisk"
        return
    fi
    if [ -x "/home/gerben/bin/bazelisk" ]; then
        printf '%s\n' "/home/gerben/bin/bazelisk"
        return
    fi
    if command -v bazel >/dev/null 2>&1; then
        command -v bazel
        return
    fi
    echo "Could not find bazelisk or bazel" >&2
    exit 1
}

find_bochs() {
    if [ -n "${BOCHS_BIN:-}" ] && [ -x "$BOCHS_BIN" ]; then
        printf '%s\n' "$BOCHS_BIN"
        return
    fi
    for cand in \
        "$HOME/bin/bochs" \
        "$HOME/bin/Bochs" \
        /usr/bin/bochs \
        /usr/local/bin/bochs; do
        if [ -x "$cand" ]; then
            printf '%s\n' "$cand"
            return
        fi
    done
    if command -v bochs >/dev/null 2>&1; then
        command -v bochs
        return
    fi
    echo "Could not find bochs. Set BOCHS_BIN or install bochs." >&2
    exit 1
}

find_bochs_bios() {
    if [ -n "${BOCHS_BIOS:-}" ] && [ -f "$BOCHS_BIOS" ]; then
        printf '%s\n' "$BOCHS_BIOS"
        return
    fi
    if [ -n "${BOCHS_SHARE:-}" ] && [ -f "$BOCHS_SHARE/BIOS-bochs-legacy" ]; then
        printf '%s\n' "$BOCHS_SHARE/BIOS-bochs-legacy"
        return
    fi
    if [ -n "${BXSHARE:-}" ] && [ -f "$BXSHARE/BIOS-bochs-legacy" ]; then
        printf '%s\n' "$BXSHARE/BIOS-bochs-legacy"
        return
    fi
    for cand in \
        /usr/share/bochs/BIOS-bochs-legacy \
        /usr/share/bochs/BIOS-bochs-latest \
        /usr/share/bochs/BIOS-qemu-latest \
        /usr/local/share/bochs/BIOS-bochs-latest \
        /usr/local/share/bochs/BIOS-bochs-legacy; do
        if [ -f "$cand" ]; then
            printf '%s\n' "$cand"
            return
        fi
    done
    echo "Could not find Bochs BIOS image. Install bochsbios or set BOCHS_BIOS." >&2
    exit 1
}

find_bochs_vga_rom() {
    if [ -n "${BOCHS_VGA_ROM:-}" ] && [ -f "$BOCHS_VGA_ROM" ]; then
        printf '%s\n' "$BOCHS_VGA_ROM"
        return
    fi
    if [ -n "${BOCHS_SHARE:-}" ] && [ -f "$BOCHS_SHARE/VGABIOS-lgpl-latest.bin" ]; then
        printf '%s\n' "$BOCHS_SHARE/VGABIOS-lgpl-latest.bin"
        return
    fi
    if [ -n "${BXSHARE:-}" ] && [ -f "$BXSHARE/VGABIOS-lgpl-latest.bin" ]; then
        printf '%s\n' "$BXSHARE/VGABIOS-lgpl-latest.bin"
        return
    fi
    for cand in \
        /usr/share/bochs/VGABIOS-lgpl-latest.bin \
        /usr/share/bochs/VGABIOS-lgpl-latest \
        /usr/share/vgabios/vgabios-stdvga.bin \
        /usr/share/vgabios/vgabios.bin \
        /usr/share/seabios/vgabios-stdvga.bin \
        /usr/share/seabios/vgabios-bochs-display.bin \
        /usr/local/share/bochs/VGABIOS-lgpl-latest.bin \
        /usr/local/share/vgabios/vgabios-stdvga.bin \
        /usr/local/share/vgabios/vgabios.bin; do
        if [ -f "$cand" ]; then
            printf '%s\n' "$cand"
            return
        fi
    done
    echo "Could not find Bochs VGA ROM image. Install vgabios or set BOCHS_VGA_ROM." >&2
    exit 1
}

# choose_audio_backend (qemu). $1 = qemu binary.
choose_audio_backend() {
    if [ -n "${AUDIO_BACKEND:-}" ]; then
        printf '%s\n' "$AUDIO_BACKEND"
        return
    fi
    local help
    help="$("$1" -audiodev help 2>/dev/null || true)"
    # Prefer QEMU's PulseAudio backend. On PipeWire desktops this usually
    # reaches pipewire-pulse and is less brittle than QEMU's native PipeWire
    # backend, which can fail with "Failed to initialize PW context" even when
    # compiled in.
    for backend in pa pipewire alsa sdl; do
        if printf '%s\n' "$help" | grep -q "^$backend"; then
            printf '%s\n' "$backend"
            return
        fi
    done
    printf '%s\n' "pa"
}

# build_qemu_audio_args: set the global AUDIO_ARGS array from $SOUND / $QEMU /
# $IMG. Shared by the qemu BIOS and qemu UEFI paths so --sound behaves the same
# regardless of firmware. $1 = qemu binary.
build_qemu_audio_args() {
    local qemu="$1"
    AUDIO_BACKEND="$(choose_audio_backend "$qemu")"
    SB16_IRQ=5
    if [ "$IMG" = "freedos" ]; then
        SB16_IRQ=7
    fi
    # SOUND axis: --sound none omits devices; ac97/hda swap the codec; sb default.
    if [ "$SOUND" = "none" ]; then
        AUDIO_ARGS=()
    elif [ "$SOUND" = "ac97" ]; then
        # No sb16 (so the kernel SB emulation kicks in); an Intel AC'97 codec is the
        # PCM output the kernel ac97 driver discovers and drives.
        AUDIO_ARGS=(-audiodev "${AUDIO_BACKEND},id=snd0"
                    -device AC97,audiodev=snd0
                    -machine pcspk-audiodev=snd0)
    elif [ "$SOUND" = "hda" ]; then
        # No sb16; an Intel HD Audio controller + duplex codec is the PCM output the
        # kernel hda driver discovers and drives (the in-kernel SB emulation feeds it).
        AUDIO_ARGS=(-audiodev "${AUDIO_BACKEND},id=snd0"
                    -device intel-hda
                    -device hda-duplex,audiodev=snd0
                    -machine pcspk-audiodev=snd0)
    else
        AUDIO_ARGS=(-audiodev "${AUDIO_BACKEND},id=snd0"
                    -device adlib,audiodev=snd0
                    -device sb16,audiodev=snd0,iobase=0x220,irq="$SB16_IRQ",dma=1,dma16=5
                    -machine pcspk-audiodev=snd0)
    fi
}

# Build the standalone-GRUB ESP shared by qemu-uefi and bochs-uefi.
# $1 = destination ESP path, $2 = kernel.elf path, $3 = working dir,
# $4 = "all_video" to additionally `insmod all_video` (bochs path).
build_uefi_esp() {
    local esp="$1" kernel="$2" work="$3" extra_insmod="$4"
    local extra_line=""
    [ "$extra_insmod" = "all_video" ] && extra_line="insmod all_video"
    cat > "$work/grub.cfg" <<EOF
set timeout=0
# The kernel's multiboot header requests a linear framebuffer (GOP); GRUB can
# only satisfy it with its EFI video driver loaded.
$extra_line
insmod efi_gop
set gfxmode=auto
set gfxpayload=keep
menuentry "RetroOS (multiboot)" {
    search --no-floppy --file /kernel.elf --set=root
    multiboot /kernel.elf
    boot
}
EOF
    grub-mkstandalone -O x86_64-efi -o "$work/BOOTX64.EFI" \
        "boot/grub/grub.cfg=$work/grub.cfg" >/dev/null

    truncate -s 64M "$esp"
    mformat -i "$esp" -F ::
    mmd    -i "$esp" ::/EFI ::/EFI/BOOT
    mcopy  -i "$esp" "$work/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
    mcopy  -i "$esp" "$kernel" ::/kernel.elf
}

# ---------------------------------------------------------------------------
# 4. Image -> (bazel target, file) resolution + build
# ---------------------------------------------------------------------------
# Image is chosen uniformly for every backend/firmware: the central default
# rule above (proprietary when apps-proprietary/ is present, else image) unless
# the user overrides with -i. resolve_image maps that keyword to a bazel target
# and on-disk file name.

resolve_image() {
    case "$IMG" in
        image)       BAZEL_TARGET="//:image";             IMAGE_FILE="image.bin" ;;
        proprietary) BAZEL_TARGET="//:image_proprietary";  IMAGE_FILE="image_proprietary.bin" ;;
        ext4)        BAZEL_TARGET="//:image_ext4";          IMAGE_FILE="image_ext4.bin" ;;
        grub)        BAZEL_TARGET="//:grub_iso //:image_ext4"; IMAGE_FILE="" ;;
        freedos)     BAZEL_TARGET="//:freedos_apps";        IMAGE_FILE="freedos_apps.img" ;;
        *)           echo "Unknown image type: $IMG (choose: image, proprietary, ext4, grub, freedos)" >&2; exit 1 ;;
    esac
}

# ===========================================================================
# launch_qemu  (BIOS path from run_qemu.sh; UEFI path from run_uefi.sh)
# ===========================================================================
launch_qemu() {
    case "$ARCH" in
        386)  QEMU=qemu-system-i386;   CPU="-cpu 486" ;;
        686)  QEMU=qemu-system-i386;   CPU="" ;;
        x64)  QEMU=qemu-system-x86_64; CPU="" ;;
    esac

    # --kvm: run on the real host CPU (VT-x/AMD-V) — near-metal semantics for
    # reproducing bugs that TCG's lenient emulation hides. -cpu host wins over
    # the per-arch model above.
    if [ "$KVM" = 1 ]; then
        CPU="-accel kvm -cpu host"
    fi

    if [ "$FIRMWARE" = "uefi" ]; then
        launch_qemu_uefi
        return
    fi

    # ---- BIOS path (verbatim from run_qemu.sh) ----
    build_qemu_audio_args "$QEMU"

    # Display backend. Default to SDL, NOT GTK: QEMU's GTK UI only repaints
    # when the main loop goes idle, and SB16 ISA DMA keeps i8257_dma_run()
    # spinning so it never does — the whole screen freezes while sound plays
    # (QEMU LP#1873769 / GitLab #469; unfixed upstream, SDL/Spice/curses are
    # unaffected). Override with QEMU_DISPLAY=gtk|spice|none|... if needed.
    DISPLAY_ARGS=(-display "${QEMU_DISPLAY:-sdl}")

    resolve_image

    # DOS-era systems treat the RTC as local wall-clock time. QEMU defaults to UTC,
    # which makes DOS file managers display host-local time with the timezone
    # offset applied.
    RTC_ARGS=(-rtc base=localtime)

    # Build selected image(s)
    if [ -n "$BAZEL_TARGET" ]; then
        "$(find_bazel)" build $BAZEL_TARGET 2>&1 | tail -3
    fi

    if [ "$IMG" = "grub" ]; then
        ISO="$SCRIPT_DIR/bazel-bin/retroos_grub.iso"
        DISK="$SCRIPT_DIR/bazel-bin/image_ext4.bin"
        exec env -i \
            PATH="/usr/bin:/bin:/usr/local/bin" \
            HOME="$HOME" \
            DISPLAY="${DISPLAY:-}" \
            XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            $QEMU \
            $CPU \
            -cdrom "$ISO" \
            -drive "file=$DISK,format=raw,snapshot=on" \
            -boot order=d \
            -debugcon stdio \
            "${DISPLAY_ARGS[@]}" \
            "${AUDIO_ARGS[@]}" \
            "${RTC_ARGS[@]}" \
            -no-reboot \
            "${PASS[@]}"
    elif [ "$IMG" = "freedos" ]; then
        # Look for FreeDOS install media + HDD + apps disk in a few candidate
        # locations. Override any of them with FDOS_DIR / FDOS_ISO / FDOS_HDD /
        # APPS_IMG env vars.
        FDOS_DIR="${FDOS_DIR:-$SCRIPT_DIR/freedos}"

        # FreeDOS install ISO/IMG (boot media). Search FDOS_DIR, then project
        # root, then ~/Downloads.
        if [ -z "${FDOS_ISO:-}" ]; then
            for d in "$FDOS_DIR" "$SCRIPT_DIR" "$HOME/Downloads"; do
                for f in "$d"/FD*.iso "$d"/FD*.ISO; do
                    [ -f "$f" ] && FDOS_ISO="$f" && break 2
                done
            done
        fi
        FDOS_HDD="${FDOS_HDD:-}"
        if [ -z "$FDOS_HDD" ]; then
            for d in "$FDOS_DIR" "$SCRIPT_DIR" "$HOME/Downloads"; do
                for f in "$d"/FD*.img "$d"/FD*.IMG; do
                    [ -f "$f" ] && FDOS_HDD="$f" && break 2
                done
            done
        fi
        if [ -z "$FDOS_ISO" ] && [ -z "$FDOS_HDD" ]; then
            echo "No FreeDOS install media found."
            echo "Looked in: $FDOS_DIR/, $SCRIPT_DIR/, $HOME/Downloads/"
            echo "Download from https://www.freedos.org/download/ and place .iso or .img there,"
            echo "or set FDOS_ISO / FDOS_HDD env var to its full path."
            exit 1
        fi

        # Apps disk: bazel-built first, then make_freedos_image.sh output at root.
        if [ -z "${APPS_IMG:-}" ]; then
            for cand in \
                "$SCRIPT_DIR/bazel-bin/freedos_apps.img" \
                "$SCRIPT_DIR/freedos_apps.img" \
                "$SCRIPT_DIR/freedos_proprietary.img"; do
                [ -f "$cand" ] && APPS_IMG="$cand" && break
            done
        fi
        if [ -z "${APPS_IMG:-}" ] || [ ! -f "$APPS_IMG" ]; then
            echo "Apps disk not found. Build with 'bazelisk build //:freedos_apps'"
            echo "or run ./make_freedos_image.sh, or set APPS_IMG=<path>."
            exit 1
        fi
        echo "Using apps disk: $APPS_IMG"

        # Persistent FreeDOS HDD lives next to the install media by default.
        HDD_IMG="${HDD_IMG:-$FDOS_DIR/freedos_hdd.img}"
        FDOS_ARGS=""
        APPS_DRIVE=""
        FDOS_INSTALLED="$FDOS_DIR/.installed"
        if [ ! -f "$HDD_IMG" ]; then
            # First run: create HDD and boot from ISO to install
            echo "Creating 256MB FreeDOS hard disk..."
            qemu-img create -f raw "$HDD_IMG" 256M
            rm -f "$FDOS_INSTALLED"
        elif [ ! -f "$FDOS_INSTALLED" ]; then
            # HDD pre-existed (e.g. you copied in a ready-made install). Trust
            # it and skip the installer.
            touch "$FDOS_INSTALLED"
        fi
        if [ ! -f "$FDOS_INSTALLED" ]; then
            # Not yet installed: boot from ISO
            if [ -n "$FDOS_ISO" ]; then
                FDOS_ARGS="-cdrom $FDOS_ISO -boot order=d"
            elif [ -n "$FDOS_HDD" ]; then
                FDOS_ARGS="-drive file=$FDOS_HDD,format=raw,snapshot=on -boot order=b"
            fi
            echo "Booting FreeDOS installer. After install completes, run:"
            echo "  touch $FDOS_INSTALLED"
            echo "Then run this script again to boot from HDD."
        else
            # Installed: boot from HDD, attach apps as second drive
            APPS_DRIVE="-drive file=$APPS_IMG,format=raw,snapshot=on"
            echo "Booting FreeDOS from HDD. Apps on D:. Delete $HDD_IMG and $FDOS_INSTALLED to reinstall."
        fi
        exec env -i \
            PATH="/usr/bin:/bin:/usr/local/bin" \
            HOME="$HOME" \
            DISPLAY="${DISPLAY:-}" \
            XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            $QEMU \
            $CPU \
            -debugcon stdio \
            -m 32 \
            -k en-us \
            -global i8042.kbd-throttle=on \
            -drive "file=$HDD_IMG,format=raw" \
            $APPS_DRIVE \
            $FDOS_ARGS \
            "${DISPLAY_ARGS[@]}" \
            "${AUDIO_ARGS[@]}" \
            "${RTC_ARGS[@]}" \
            -no-reboot \
            "${PASS[@]}"
    else
        IMAGE="$SCRIPT_DIR/bazel-bin/$IMAGE_FILE"
        FWCFG_ARGS=()
        FWCFG_TMPDIR=""
        if [ -n "$START_BIN" ]; then
            # Write the cmdline to a tempfile and use fw_cfg's file= form. The
            # string= form word-splits on commas, which collide with TLINK's
            # arg separator.
            FWCFG_TMPDIR=$(mktemp -d -t retroos-fwcfg.XXXXXX)
            printf '%s' "$START_BIN" > "$FWCFG_TMPDIR/cmdline"
            FWCFG_ARGS+=(-fw_cfg "name=opt/cmdline,file=$FWCFG_TMPDIR/cmdline")
            # When -h is also given, default cwd to host/ so relative paths in
            # the program's args resolve against the host workspace.
            if [ -n "$HOSTFS_DIR" ]; then
                FWCFG_ARGS+=(-fw_cfg "name=opt/cwd,string=host/")
            fi
        fi
        HOSTFS_ARGS=()
        if [ -n "$HOSTFS_DIR" ]; then
            HOSTFS_SOCK="/tmp/retroos-hostfs.sock"
            HOSTFS_ARGS=(
                -serial chardev:hostfs
                -chardev "socket,id=hostfs,path=$HOSTFS_SOCK,server=on,wait=off"
            )
            # Launch hostfs server in background, kill on exit
            "$SCRIPT_DIR/hostfs.py" "$HOSTFS_DIR" "$HOSTFS_SOCK" &
            HOSTFS_PID=$!
            trap "kill $HOSTFS_PID 2>/dev/null; [ -n \"$FWCFG_TMPDIR\" ] && rm -rf \"$FWCFG_TMPDIR\"" EXIT
        elif [ -n "$FWCFG_TMPDIR" ]; then
            trap "rm -rf $FWCFG_TMPDIR" EXIT
        fi
        exec env -i \
            PATH="/usr/bin:/bin:/usr/local/bin" \
            HOME="$HOME" \
            DISPLAY="${DISPLAY:-}" \
            XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            $QEMU \
            $CPU \
            -drive "file=$IMAGE,format=raw,snapshot=on" \
            -debugcon stdio \
            "${FWCFG_ARGS[@]}" \
            "${HOSTFS_ARGS[@]}" \
            "${DISPLAY_ARGS[@]}" \
            "${AUDIO_ARGS[@]}" \
            "${RTC_ARGS[@]}" \
            -no-reboot \
            "${PASS[@]}"
    fi
}

# ---- QEMU UEFI path (verbatim from run_uefi.sh) ----
launch_qemu_uefi() {
    # Image selection is uniform with the BIOS path: -i picks the keyword, the
    # central default rule supplies it when unset. resolve_image maps it to the
    # on-disk file, then we build it if needed (same as the BIOS path).
    resolve_image
    IMAGE="bazel-bin/$IMAGE_FILE"
    if [ -n "$BAZEL_TARGET" ]; then
        "$(find_bazel)" build $BAZEL_TARGET 2>&1 | tail -3
    fi
    [ -f "$IMAGE" ] || { echo "run.sh (qemu/uefi): no image at $IMAGE (bazelisk build //:image)" >&2; exit 1; }

    # --sound applies under UEFI too (the kernel discovers the same PCI/ISA
    # devices regardless of firmware).
    build_qemu_audio_args qemu-system-x86_64

    KERNEL="bazel-bin/kernel/kernel.elf"
    [ -f "$KERNEL" ] || { echo "run.sh (qemu/uefi): no kernel at $KERNEL (bazelisk build //kernel:kernel_elf)" >&2; exit 1; }

    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
    [ -f "$OVMF_CODE" ] || { echo "run.sh (qemu/uefi): OVMF not found (apt install ovmf)" >&2; exit 1; }

    # Build the ESP fresh each run (cheap: ~1s). Standalone GRUB embeds its own
    # grub.cfg in a memdisk; it then locates kernel.elf on the ESP by search.
    WORK="$(mktemp -d -t retroos-uefi.XXXXXX)"
    trap 'rm -rf "$WORK"' EXIT

    ESP="$WORK/esp.img"
    build_uefi_esp "$ESP" "$KERNEL" "$WORK" ""

    # Private writable VARS copy (OVMF persists boot entries into it).
    cp "$OVMF_VARS" "$WORK/vars.fd"

    DISPLAY_ARGS=()
    if [ "$QEMU_HEADLESS" = 1 ]; then
        DISPLAY_ARGS+=(-display none)
    fi

    # -cpu max: the default qemu64 model lacks VME, forcing the kernel's software
    # VM86 monitor; real hardware (and the BIOS path) has VME. --kvm runs on the
    # host CPU instead (VT-x/AMD-V) for near-metal semantics.
    local ACCEL_CPU="-cpu max"
    [ "$KVM" = 1 ] && ACCEL_CPU="-accel kvm -cpu host"
    exec qemu-system-x86_64 \
        -M q35 -m 512 $ACCEL_CPU \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,file="$WORK/vars.fd" \
        -nodefaults \
        -device bochs-display \
        -drive file="$IMAGE",if=none,id=hd,format=raw,snapshot=on \
        -device nvme,drive=hd,serial=retro1 \
        `# image controller FIRST: the kernel's nvme probe takes the first` \
        `# controller it finds; OVMF locates the ESP by filesystem, not order` \
        -drive file="$ESP",if=none,id=esp,format=raw \
        -device nvme,drive=esp,serial=esp0 \
        `# xHCI controller present (the honest modern-laptop bus, for the future` \
        `# xHCI driver to probe) but NO usb-kbd: QEMU routes keyboard input to a` \
        `# USB keyboard when one exists, and with no xHCI driver those keys` \
        `# vanish — the i8042 bring-up crutch never sees a byte. Keys reach the` \
        `# guest via q35's i8042 until the xHCI/HID driver lands.` \
        -device qemu-xhci \
        -debugcon stdio \
        -no-reboot \
        "${DISPLAY_ARGS[@]}" \
        "${AUDIO_ARGS[@]}" \
        "${PASS[@]}"
}

# ===========================================================================
# launch_bochs  (BIOS from run_bochs.sh; UEFI from run_uefi_bochs.sh)
# ===========================================================================
launch_bochs() {
    if [ "$FIRMWARE" = "uefi" ]; then
        launch_bochs_uefi
        return
    fi

    # ---- BIOS path (verbatim from run_bochs.sh) ----
    # Bochs has no 386/486 CPU model in the Ubuntu 24.04 package. Use a non-PAE
    # Pentium by default so the kernel takes its legacy paging path; Bochs exposes
    # a current PAE setup bug at CR0.PG enable with PAE-capable models.
    BOCHS_CPU_MODEL="${BOCHS_CPU_MODEL:-pentium}"
    BOCHS_IPS="${BOCHS_IPS:-50000000}"
    BOCHS_SYNC="${BOCHS_SYNC:-realtime}"
    BOCHS_VGA_UPDATE_FREQ="${BOCHS_VGA_UPDATE_FREQ:-60}"

    case "$IMG" in
        image)       BAZEL_TARGET="//:image";             IMAGE_FILE="image.bin" ;;
        proprietary) BAZEL_TARGET="//:image_proprietary"; IMAGE_FILE="image_proprietary.bin" ;;
        ext4)        BAZEL_TARGET="//:image_ext4";        IMAGE_FILE="image_ext4.bin" ;;
        freedos)     BAZEL_TARGET="//:freedos_apps" ;;
        *)           echo "Unknown image type: $IMG (choose: image, proprietary, ext4, freedos)" >&2; exit 1 ;;
    esac

    "$(find_bazel)" build "$BAZEL_TARGET" 2>&1 | tail -3

    BOCHS_BIN="$(find_bochs)"
    BOCHS_BIOS="$(find_bochs_bios)"
    BOCHS_VGA_ROM="$(find_bochs_vga_rom)"

    # Persistent VM state.
    if [ -z "${VM_DIR:-}" ]; then
        : "${VM_DIR:=${HOME}/.local/share/Bochs/RetroOS}"
    fi
    mkdir -p "$VM_DIR"
    BOCHSRC="${VM_DIR}/bochsrc.txt"

    bochsrc_preamble() {
        cat <<EOF
megs: 64
cpu: model="$BOCHS_CPU_MODEL", count=1, ips="$BOCHS_IPS", reset_on_triple_fault=1
# RetroOS debug console (dbg_println, the [prof] profiler, the DOS console
# mirror) writes to port 0xE9 - the same debugcon QEMU captures by default.
# Bochs only echoes 0xE9 when this hack is enabled; output goes to Bochs
# stdout (capture by teeing this script). Without it the kernel trace is lost.
port_e9_hack: enabled=1
romimage: file="$BOCHS_BIOS"
vgaromimage: file="$BOCHS_VGA_ROM"
# update_freq = host-window repaints/sec on the emulated clock. Default is a
# few Hz (choppy); 60 Hz gives smooth video. extension=vbe matches the Bochs
# VBE display interface (ports 0x1CE/0x1CF) the kernel programs.
vga: extension=vbe, update_freq=$BOCHS_VGA_UPDATE_FREQ
clock: sync=$BOCHS_SYNC, time0=local
mouse: enabled=1, type=ps2
speaker: enabled=1, mode=sound
sb16: wavemode=1, midimode=0, dmatimer=750000, log="$VM_DIR/sb16.log", loglevel=2
log: "$VM_DIR/bochs.log"
com1: enabled=1, mode=file, dev="$VM_DIR/serial.out"
EOF
    }

    if [ "$IMG" = "freedos" ]; then
        # ---- FreeDOS reference mode (mirrors run_qemu.sh's `-i freedos`) ----
        FDOS_DIR="${FDOS_DIR:-$SCRIPT_DIR/freedos}"

        if [ -z "${FDOS_ISO:-}" ]; then
            for d in "$FDOS_DIR" "$SCRIPT_DIR" "$HOME/Downloads"; do
                for f in "$d"/FD*.iso "$d"/FD*.ISO; do
                    [ -f "$f" ] && FDOS_ISO="$f" && break 2
                done
            done
        fi

        HDD_IMG="${HDD_IMG:-$FDOS_DIR/freedos_hdd.img}"
        FDOS_INSTALLED="$FDOS_DIR/.installed"
        if [ ! -f "$HDD_IMG" ]; then
            echo "Creating 256MB FreeDOS hard disk at $HDD_IMG..."
            if command -v qemu-img >/dev/null 2>&1; then
                qemu-img create -f raw "$HDD_IMG" 256M >/dev/null
            else
                dd if=/dev/zero of="$HDD_IMG" bs=1M count=256 status=none
            fi
            rm -f "$FDOS_INSTALLED"
        elif [ ! -f "$FDOS_INSTALLED" ]; then
            touch "$FDOS_INSTALLED"
        fi

        if [ -z "${APPS_IMG:-}" ]; then
            for cand in \
                "$SCRIPT_DIR/bazel-bin/freedos_apps.img" \
                "$SCRIPT_DIR/freedos_apps.img" \
                "$SCRIPT_DIR/freedos_proprietary.img"; do
                [ -f "$cand" ] && APPS_IMG="$cand" && break
            done
        fi

        # 256MB image -> 520 cyl x 16 heads x 63 spt (partition starts at sector 63).
        FDOS_GEOM='mode=flat, cylinders=520, heads=16, spt=63, translation=lba'

        if [ ! -f "$FDOS_INSTALLED" ]; then
            [ -n "${FDOS_ISO:-}" ] || {
                echo "No FreeDOS ISO found (FD*.iso) in $FDOS_DIR/, $SCRIPT_DIR/, $HOME/Downloads/."
                echo "Download from https://www.freedos.org/download/ or set FDOS_ISO."
                exit 1
            }
            echo "Booting FreeDOS installer from $FDOS_ISO."
            echo "After install completes, run:  touch $FDOS_INSTALLED"
            { bochsrc_preamble
              echo "boot: cdrom"
              echo "ata0-master: type=disk, path=\"$HDD_IMG\", $FDOS_GEOM"
              echo "ata1-master: type=cdrom, path=\"$FDOS_ISO\", status=inserted"
            } > "$BOCHSRC"
        else
            echo "Booting FreeDOS from $HDD_IMG (persistent)."
            APPS_LINE=""
            if [ -n "${APPS_IMG:-}" ] && [ -f "$APPS_IMG" ]; then
                cp --reflink=auto "$APPS_IMG" "$VM_DIR/apps.img"
                chmod u+rw "$VM_DIR/apps.img"
                APPS_LINE="ata0-slave: type=disk, path=\"$VM_DIR/apps.img\", $FDOS_GEOM"
                echo "Apps disk on D: $APPS_IMG"
            else
                echo "(no apps disk found; D: not mounted - build //:freedos_apps or set APPS_IMG)"
            fi
            { bochsrc_preamble
              echo "boot: disk"
              echo "ata0-master: type=disk, path=\"$HDD_IMG\", $FDOS_GEOM"
              [ -n "$APPS_LINE" ] && echo "$APPS_LINE"
            } > "$BOCHSRC"
        fi
    else
        rm -f "${VM_DIR}/disk.img"
        cp --reflink=auto "${SCRIPT_DIR}/bazel-bin/${IMAGE_FILE}" "${VM_DIR}/disk.img"
        chmod u+rw "${VM_DIR}/disk.img"
        # Exact geometry for the RetroOS raw image, rewritten for Bochs' CHS limits:
        # 8448 cylinders * 16 heads * 16 sectors * 512 bytes = 1,107,296,256 bytes.
        { bochsrc_preamble
          echo "boot: disk"
          echo "ata0-master: type=disk, path=\"$VM_DIR/disk.img\", mode=flat, cylinders=8448, heads=16, spt=16, biosdetect=auto, translation=lba"
        } > "$BOCHSRC"
    fi
    echo "Wrote Bochs config to $BOCHSRC"

    BOCHS_ARGS=(-q -f "$BOCHSRC" -unlock)
    if [ "${BOCHS_DEBUG:-0}" != "1" ]; then
        BOCHS_RC="${VM_DIR}/bochs.rc"
        printf 'c\n' > "$BOCHS_RC"
        BOCHS_ARGS=(-q -rc "$BOCHS_RC" -f "$BOCHSRC" -unlock)
    fi

    if [ -n "${BOCHS_DISPLAY_LIBRARY:-}" ]; then
        exec env -i \
            PATH="/usr/bin:/bin:/usr/local/bin" \
            HOME="$HOME" \
            DISPLAY="${DISPLAY:-}" \
            TERM="${TERM:-xterm-256color}" \
            XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            "$BOCHS_BIN" "${BOCHS_ARGS[@]}" "${PASS[@]}" "display_library: ${BOCHS_DISPLAY_LIBRARY}"
    fi

    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        TERM="${TERM:-xterm-256color}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
        DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
        "$BOCHS_BIN" "${BOCHS_ARGS[@]}" "${PASS[@]}"
}

# ---- Bochs UEFI path (verbatim from run_uefi_bochs.sh) ----
launch_bochs_uefi() {
    # Image selection is uniform: -i picks the keyword, central default supplies
    # it when unset; resolve_image maps it to the on-disk file.
    resolve_image
    IMAGE="bazel-bin/$IMAGE_FILE"

    BAZEL="$(find_bazel)"
    "$BAZEL" build //kernel:kernel_elf >/dev/null 2>&1
    if [ -n "$BAZEL_TARGET" ]; then
        "$BAZEL" build $BAZEL_TARGET >/dev/null 2>&1 || true
    fi

    [ -f "$IMAGE" ] || { echo "run.sh (bochs/uefi): no image at $IMAGE" >&2; exit 1; }
    KERNEL="bazel-bin/kernel/kernel.elf"
    [ -f "$KERNEL" ] || { echo "run.sh (bochs/uefi): no kernel at $KERNEL" >&2; exit 1; }

    # Persistent VM state
    VM_DIR="${VM_DIR:-${HOME}/.local/share/Bochs/RetroOS_UEFI}"
    mkdir -p "$VM_DIR"
    BOCHSRC="${VM_DIR}/bochsrc.txt"

    # Bochs 2.7 caps romimage at 2MB (BIOSROMSZ in memory.h), so the 4MB OVMF
    # builds modern distros ship panic with "ROM image too large". The last
    # Ubuntu edk2 that shipped a unified 2MB OVMF.fd is jammy's 2022.02 —
    # fetch that package once and cache the firmware in VM_DIR.
    OVMF_PATH="$VM_DIR/OVMF_2M.fd"
    if [ ! -f "$OVMF_PATH" ]; then
        OVMF_DEB_URL="http://archive.ubuntu.com/ubuntu/pool/main/e/edk2/ovmf_2022.02-3ubuntu0.22.04.6_all.deb"
        echo "Fetching 2MB OVMF (Bochs cannot load the 4MB builds)..."
        OVMF_TMP="$(mktemp -d -t retroos-ovmf.XXXXXX)"
        curl -fsSL -o "$OVMF_TMP/ovmf.deb" "$OVMF_DEB_URL"
        dpkg-deb -x "$OVMF_TMP/ovmf.deb" "$OVMF_TMP/x"
        install -m 644 "$OVMF_TMP/x/usr/share/ovmf/OVMF.fd" "$OVMF_PATH"
        rm -rf "$OVMF_TMP"
    fi

    # Build ESP (identical to qemu uefi path; bochs adds all_video).
    WORK="$(mktemp -d -t retroos-uefi-bochs.XXXXXX)"
    # We don't trap EXIT here because Bochs needs these files while running.
    # Instead we put them in VM_DIR.
    # Note: OVMF exposes no usable GOP on Bochs's VGA (QemuVideoDxe doesn't
    # bind), so GRUB reports "no suitable video mode found" and the kernel
    # boots without a multiboot framebuffer — it falls back to emulated VGA
    # text, which works. Display parity with metal fbcon is not available here.
    BOCHS_VGA_ROM="$(find_bochs_vga_rom)"

    ESP="$VM_DIR/esp.img"
    build_uefi_esp "$ESP" "$KERNEL" "$WORK" "all_video"
    rm -rf "$WORK"

    cp --reflink=auto "$IMAGE" "$VM_DIR/disk.img"
    chmod u+rw "$VM_DIR/disk.img"

    BOCHS_BIN="$(find_bochs)"

    # Bochs config for UEFI.
    # - ROM is top-aligned at 4GB: 2MB OVMF flashes at 0xffe00000.
    # - reset_on_triple_fault=0: this rig exists to debug metal boot faults;
    #   on a triple fault Bochs panics and dumps full CPU state to the log
    #   instead of silently rebooting.
    cat <<EOF > "$BOCHSRC"
megs: 1024
cpu: model=core2_penryn_t9600, count=1, ips=50000000, reset_on_triple_fault=0
pci: enabled=1, chipset=i440fx
port_e9_hack: enabled=1
romimage: file="$OVMF_PATH", address=0xffe00000
vgaromimage: file="$BOCHS_VGA_ROM"
vga: extension=vbe, update_freq=60
clock: sync=realtime, time0=local
mouse: enabled=1, type=ps2
speaker: enabled=1, mode=sound
sb16: wavemode=1, midimode=0, dmatimer=750000, log="$VM_DIR/sb16.log", loglevel=2
log: "$VM_DIR/bochs.log"
com1: enabled=1, mode=file, dev="$VM_DIR/serial.out"
# Boot from the ESP
boot: disk
# ata0-master is our main RetroOS image
ata0-master: type=disk, path="$VM_DIR/disk.img", mode=flat, cylinders=8448, heads=16, spt=16, biosdetect=auto, translation=lba
# ata0-slave is the ESP containing the kernel + GRUB
ata0-slave: type=disk, path="$ESP", mode=flat, cylinders=128, heads=16, spt=63, biosdetect=auto, translation=lba
EOF

    # Headless use: BOCHS_DISPLAY=rfb starts a VNC server on :5900 (a client
    # must connect within 30s or Bochs panics). Default is Bochs's built-in
    # GUI choice (X11 here).
    if [ -n "${BOCHS_DISPLAY:-}" ]; then
        echo "display_library: ${BOCHS_DISPLAY}" >> "$BOCHSRC"
    fi

    echo "Wrote Bochs config to $BOCHSRC"

    BOCHS_ARGS=(-q -f "$BOCHSRC" -unlock)
    if [ "${BOCHS_DEBUG:-0}" != "1" ]; then
        BOCHS_RC="${VM_DIR}/bochs.rc"
        printf 'c\n' > "$BOCHS_RC"
        BOCHS_ARGS=(-q -rc "$BOCHS_RC" -f "$BOCHSRC" -unlock)
    fi

    exec "$BOCHS_BIN" "${BOCHS_ARGS[@]}" "${PASS[@]}"
}

# ===========================================================================
# launch_86box  (verbatim from run_86box.sh)
# ===========================================================================
launch_86box() {
    case "$IMG" in
        image)        BAZEL_TARGET="//:image";              IMAGE_FILE="image.bin" ;;
        proprietary)  BAZEL_TARGET="//:image_proprietary";  IMAGE_FILE="image_proprietary.bin" ;;
        ext4)         BAZEL_TARGET="//:image_ext4";         IMAGE_FILE="image_ext4.bin" ;;
        freedos)      BAZEL_TARGET="//:freedos_apps" ;;
        *)            echo "Unknown image type: $IMG (image | proprietary | ext4 | freedos)" >&2; exit 1 ;;
    esac

    # Emit a BIOS-friendly "spt, heads, cyl" CHS for a raw disk image.
    geom_for() {
        local sectors=$(( $(stat -c%s "$1") / 512 ))
        echo "63, 16, $(( sectors / (63 * 16) ))"
    }

    "$(find_bazel)" build "$BAZEL_TARGET" 2>&1 | tail -3

    VM_NAME="RetroOS"
    [ "$IMG" = "freedos" ] && VM_NAME="RetroOS-FreeDOS"
    if [ -z "${VM_DIR:-}" ]; then
        if command -v flatpak >/dev/null 2>&1; then
            FLATPAK_ID=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
            if [ -n "$FLATPAK_ID" ]; then
                VM_DIR="${HOME}/.var/app/${FLATPAK_ID}/data/86Box/${VM_NAME}"
            fi
        fi
        : "${VM_DIR:=${HOME}/.local/share/86Box/${VM_NAME}}"
    fi

    mkdir -p "$VM_DIR"
    FS_GRANT=""

    if [ "$IMG" = "freedos" ]; then
        # ---- FreeDOS reference mode ----
        FDOS_DIR="${FDOS_DIR:-$SCRIPT_DIR/freedos}"
        HDD_IMG="${HDD_IMG:-$FDOS_DIR/freedos_hdd.img}"
        if [ ! -f "$HDD_IMG" ] || [ ! -f "$FDOS_DIR/.installed" ]; then
            echo "FreeDOS is not installed at $HDD_IMG." >&2
            echo "Install it first:  ./run_qemu.sh -i freedos   (runs the installer)" >&2
            echo "then re-run:       ./run_86box.sh -i freedos" >&2
            exit 1
        fi
        chmod u+rw "$HDD_IMG"
        HDD_GEOM="$(geom_for "$HDD_IMG")"
        FS_GRANT="--filesystem=$FDOS_DIR"

        APPS_LINE=""
        APPS_SRC=""
        for cand in "$SCRIPT_DIR/bazel-bin/freedos_apps.img" \
                    "$SCRIPT_DIR/freedos_apps.img" \
                    "$SCRIPT_DIR/freedos_proprietary.img"; do
            [ -f "$cand" ] && APPS_SRC="$cand" && break
        done
        if [ -n "$APPS_SRC" ]; then
            rm -f "$VM_DIR/apps.img"
            cp --reflink=auto "$APPS_SRC" "$VM_DIR/apps.img"
            chmod u+rw "$VM_DIR/apps.img"
            APPS_LINE="hdd_02_fn = apps.img
hdd_02_ide_channel = 0:1
hdd_02_parameters = $(geom_for "$VM_DIR/apps.img"), 0, ide"
            echo "Apps disk on D: $APPS_SRC"
        else
            echo "(no apps disk found; D: not mounted — build //:freedos_apps)"
        fi

        cat > "$VM_DIR/86box.cfg" <<EOF
[General]
vid_renderer = qt_software
window_remember = 0
sound_gain = 0

[Machine]
machine = tx97
cpu_family = pentium_p54c
cpu_speed = 166666666
cpu_multi = 2.5
cpu_use_dynarec = 1
fpu_type = internal
mem_size = 32768
time_sync = local
pit_mode = -1
fpu_softfloat = 0

[Video]
gfxcard = vga

[Input devices]
keyboard_type = keyboard_ps2
mouse_type = ps2

[Sound]
sndcard = sb16
fm_driver = nuked

[Network]
net_card = none

[Ports (COM & LPT)]
serial1_enabled = 1
serial2_enabled = 0
lpt1_device = none

[Storage controllers]
hdc = internal
fdc_type = internal

[Hard disks]
hdd_01_fn = $HDD_IMG
hdd_01_ide_channel = 0:0
hdd_01_parameters = $HDD_GEOM, 0, ide
$APPS_LINE

[Floppy and CD-ROM drives]
fdd_01_type = 35_2hd
fdd_02_type = none
EOF
        echo "Wrote FreeDOS 86box config to $VM_DIR/86box.cfg"
    else

    rm -f "${VM_DIR}/disk.img"
    cp --reflink=auto "${SCRIPT_DIR}/bazel-bin/${IMAGE_FILE}" "${VM_DIR}/disk.img"
    chmod u+rw "${VM_DIR}/disk.img"

    if [ -f "${VM_DIR}/86box.cfg" ] && ! grep -q '^\[Hard disks\]' "${VM_DIR}/86box.cfg"; then
        cat >> "${VM_DIR}/86box.cfg" <<'EOF'

[Hard disks]
hdd_01_parameters = 63, 16, 2145, 0, ide
hdd_01_fn = disk.img
hdd_01_ide_channel = 0:0
EOF
        echo "Re-added [Hard disks] section to $VM_DIR/86box.cfg"
    fi

    if [ -f "${VM_DIR}/86box.cfg" ] && ! grep -q '^sndcard' "${VM_DIR}/86box.cfg"; then
        cat >> "${VM_DIR}/86box.cfg" <<'EOF'

[Sound]
sndcard = sb16
fm_driver = nuked
EOF
        echo "Re-added [Sound] sndcard=sb16 to $VM_DIR/86box.cfg"
    fi

    if [ -f "${VM_DIR}/86box.cfg" ] && grep -q '^fdd_01_type = none' "${VM_DIR}/86box.cfg"; then
        sed -i 's/^fdd_01_type = none/fdd_01_type = 35_2hd/' "${VM_DIR}/86box.cfg"
        echo "Set floppy A: to 1.44M (was none) in $VM_DIR/86box.cfg"
    fi

    if [ ! -f "${VM_DIR}/86box.cfg" ]; then
        cat > "${VM_DIR}/86box.cfg" <<'EOF'
[General]
vid_renderer = qt_software
window_remember = 0
sound_gain = 0

[Machine]
machine = tx97
cpu_family = pentium_p54c
cpu_speed = 166666666
cpu_multi = 2.5
cpu_use_dynarec = 1
fpu_type = internal
mem_size = 32768
time_sync = local
pit_mode = -1
fpu_softfloat = 0

[Video]
gfxcard = vga

[Input devices]
mouse_type = ps2

[Sound]
sndcard = sb16
fm_driver = nuked

[Network]
net_card = none

[Ports (COM & LPT)]
serial1_enabled = 1
serial1_passthrough_enabled = 0
serial2_enabled = 0
lpt1_device = none

[Storage controllers]
hdc = internal
fdc_type = internal

[Hard disks]
hdd_01_parameters = 63, 16, 2145, 0, ide
hdd_01_fn = disk.img
hdd_01_ide_channel = 0:0

[Floppy and CD-ROM drives]
# A: must be a real (empty) 1.44M drive, not "none": with the FDC enabled
# but no drive, the AMI BIOS POST halts on "Floppy drive A: failure" before
# it reaches the HDD. Empty 1.44M passes the seek test and falls through to C:.
fdd_01_type = 35_2hd
fdd_02_type = none
EOF
        echo "Created default 86box config at $VM_DIR/86box.cfg"
    fi
    fi  # end image-vs-freedos setup

    # 86box is a Qt app. The flatpak only shares the X11 socket (sockets=x11),
    # not Wayland, so on a Wayland desktop Qt's default wayland plugin aborts
    # with "Failed to create wl_display". Force XWayland (xcb).
    : "${QT_QPA_PLATFORM:=xcb}"
    export QT_QPA_PLATFORM

    if [ -n "${BOX86:-}" ]; then
        exec "$BOX86" --vmpath "$VM_DIR" "${PASS[@]}"
    fi
    if [ -x "$HOME/bin/86Box.AppImage" ]; then
        exec "$HOME/bin/86Box.AppImage" --vmpath "$VM_DIR" "${PASS[@]}"
    fi
    if command -v flatpak >/dev/null 2>&1; then
        FLATPAK_ID=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
        if [ -n "$FLATPAK_ID" ]; then
            exec flatpak run --env=QT_QPA_PLATFORM="$QT_QPA_PLATFORM" $FS_GRANT \
                "$FLATPAK_ID" --vmpath "$VM_DIR" "${PASS[@]}"
        fi
    fi
    if command -v 86box >/dev/null 2>&1; then
        exec 86box --vmpath "$VM_DIR" "${PASS[@]}"
    fi

    echo "86box binary not found." >&2
    echo "Tried: \$BOX86, \$HOME/bin/86Box.AppImage, any installed flatpak (containing \"86box\"), 86box in PATH." >&2
    echo "Either install the AppImage from https://github.com/86Box/86Box/releases" >&2
    echo "or install via flatpak (search: flatpak search 86box)." >&2
    exit 1
}

# ===========================================================================
# launch_hosted  (verbatim from run_interp.sh)
# ===========================================================================
launch_hosted() {
    local ARGS=()
    [ -n "$HOSTED_CMD" ] && ARGS+=(--cmd "$HOSTED_CMD")

    # Accept the same -i keywords as the other backends, translating to the
    # on-disk basename hosted loads as "bazel-bin/$IMG.bin".
    case "$IMG" in
        proprietary) IMG="image_proprietary" ;;
        image)       IMG="image" ;;
        ext4)        IMG="image_ext4" ;;
        *)           : ;;  # already a basename / passthrough
    esac

    if [ -n "$HOSTED_HOSTDIR" ]; then
        ARGS+=(--host "$HOSTED_HOSTDIR")
    else
        if [ ! -e "bazel-bin/$IMG.bin" ] && [ "$IMG" = "image_proprietary" ]; then
            echo "bazel-bin/image_proprietary.bin not found, using image.bin" >&2
            IMG="image"
        fi
        if [ ! -e "bazel-bin/$IMG.bin" ]; then
            echo "bazel-bin/$IMG.bin not built; run: bazelisk build //:$IMG" >&2
            exit 1
        fi
        ARGS+=("bazel-bin/$IMG.bin")
    fi

    if [ -n "$HOSTED_TERMINAL" ]; then
        # Headless kernel binary. Hosted build needs the host platform; the repo
        # default pins i686_retro_none.
        bazelisk build //kernel:retroos-host --platforms=@platforms//host
        [ -n "$HOSTED_SHOT" ] && ARGS+=(--screenshot "$HOSTED_SHOT")
        [ -n "$HOSTED_TRACE" ] && export RETRO_TRACE=1
        exec bazel-bin/kernel/retroos-host "${ARGS[@]}" "${PASS[@]}"
    fi

    # Window mode: retroos-play is Bazel-built like everything else, so it links the
    # ONE patched unicorn (//third_party/unicorn). The bootfs is embedded (same as
    # retroos-host), so this is a single host-platform build — no //:bootfs_tar step
    # that would flip --platforms and discard Bazel's analysis cache every run.
    bazelisk build //play:retroos-play --platforms=@platforms//host
    [ -n "$HOSTED_WAV" ] && ARGS+=(--wav "$HOSTED_WAV")
    if [ -n "$HOSTED_CMD" ]; then
        ARGS+=(--cwd "$(dirname "$HOSTED_CMD")/")
    fi
    [ -n "$HOSTED_TRACE" ] && export RETRO_TRACE=1
    exec bazel-bin/play/retroos-play "${ARGS[@]}" "${PASS[@]}"
}

# ---------------------------------------------------------------------------
# 5. Dispatch
# ---------------------------------------------------------------------------
case "$BACKEND" in
    qemu)   launch_qemu ;;
    bochs)  launch_bochs ;;
    86box)  launch_86box ;;
    hosted) launch_hosted ;;
esac
