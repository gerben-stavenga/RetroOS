#!/bin/bash
# Run RetroOS on the hosted/interp backend.
# Default: retroos-play — SDL window with live video/keyboard/mouse.
# -T:      retroos-host — headless/terminal (tests, repro runs, screenshots).
#
# Usage: ./run_interp.sh [-i image|proprietary] [-c DOS_CMD] [-H hostdir]
#                        [-w out.wav] [-T] [-s shot] [-t] [extra args...]
#
#   -i NAME         image basename under bazel-bin (default: image_proprietary,
#                   falls back to image if the proprietary one isn't built)
#   -c GAMES/X.EXE  launch a DOS program directly (cwd derived from its dir)
#   -H DIR          imageless DOSBox-style boot: host dir becomes the root
#   -w FILE         capture audio to WAV (play mode)
#   -T              terminal mode: headless retroos-host instead of the window
#   -s FILE         screenshots (terminal mode; text dump or P6 PPM)
#   -t              RETRO_TRACE=1 slice tracing
#
# Examples:
#   ./run_interp.sh                                  # window, boot to DN
#   ./run_interp.sh -c GAMES/SKYROADS/SKYROADS.EXE   # window, run a game
#   ./run_interp.sh -T -c GAMES/X.EXE -s /tmp/s.ppm  # headless + screenshot

set -e
set -o pipefail
cd "$(dirname "$0")"

IMG="image_proprietary"
CMD=""
HOSTDIR=""
WAV=""
SHOT=""
TRACE=""
TERMINAL=""

while [ $# -gt 0 ]; do
    case "$1" in
        -i) IMG="$2";     shift 2 ;;
        -c) CMD="$2";     shift 2 ;;
        -H) HOSTDIR="$2"; shift 2 ;;
        -w) WAV="$2";     shift 2 ;;
        -s) SHOT="$2";    shift 2 ;;
        -T) TERMINAL=1;   shift ;;
        -t) TRACE=1;      shift ;;
        -*) echo "Usage: $0 [-i image] [-c DOS_CMD] [-H hostdir] [-w wav] [-T] [-s shot] [-t] [extra args...]"; exit 1 ;;
        *)  break ;;
    esac
done

ARGS=()
[ -n "$CMD" ] && ARGS+=(--cmd "$CMD")

if [ -n "$HOSTDIR" ]; then
    ARGS+=(--host "$HOSTDIR")
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

if [ -n "$TERMINAL" ]; then
    # Headless kernel binary. Hosted build needs the host platform; the repo
    # default pins i686_retro_none.
    bazelisk build //kernel:retroos-host --platforms=@platforms//host
    [ -n "$SHOT" ] && ARGS+=(--screenshot "$SHOT")
    [ -n "$TRACE" ] && export RETRO_TRACE=1
    exec bazel-bin/kernel/retroos-host "${ARGS[@]}" "$@"
fi

# Window mode: retroos-play stays cargo-built (it owns the SDL dependency).
# The cargo build has no embedded bootfs; it loads bazel-bin/bootfs_tar.tar
# at startup (and refuses to run without it), so make sure it's built.
bazelisk build //:bootfs_tar
[ -n "$WAV" ] && ARGS+=(--wav "$WAV")
if [ -n "$CMD" ]; then
    ARGS+=(--cwd "$(dirname "$CMD")/")
fi
cargo build --release -p retroos-play
[ -n "$TRACE" ] && export RETRO_TRACE=1
exec target/release/retroos-play "${ARGS[@]}" "$@"
