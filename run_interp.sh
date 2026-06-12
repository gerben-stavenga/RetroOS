#!/bin/bash
# Run RetroOS on the hosted/interp backend (Unicorn-based arch).
# Usage: ./run_interp.sh [-i image|proprietary] [-c DOS_CMD] [-H hostdir] [-s shot] [-t] [extra retroos-host args...]
#
#   -i image        image basename under bazel-bin (default: image_proprietary,
#                   falls back to image if the proprietary one isn't built)
#   -c GAMES/X.EXE  launch a DOS program directly instead of booting to DN
#   -H DIR          imageless DOSBox-style boot: host dir becomes the root
#   -s FILE         write screenshots (text dump, or P6 PPM in graphics mode)
#   -t              RETRO_TRACE=1 slice tracing
#
# Examples:
#   ./run_interp.sh                                  # boot image to DN
#   ./run_interp.sh -c GAMES/PRINCE/PRINCE.EXE       # run a game
#   ./run_interp.sh -H ~/dosroot                     # boot from a folder
#   ./run_interp.sh -c GAMES/SKYROADS/SKYROADS.EXE -s /tmp/shot.ppm

set -e
set -o pipefail
cd "$(dirname "$0")"

IMG="image_proprietary"
CMD=""
HOSTDIR=""
SHOT=""
TRACE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -i) IMG="$2";     shift 2 ;;
        -c) CMD="$2";     shift 2 ;;
        -H) HOSTDIR="$2"; shift 2 ;;
        -s) SHOT="$2";    shift 2 ;;
        -t) TRACE=1;      shift ;;
        -*) echo "Usage: $0 [-i image] [-c DOS_CMD] [-H hostdir] [-s shot] [-t] [extra args...]"; exit 1 ;;
        *)  break ;;
    esac
done

# Hosted build needs the host platform; the repo default pins i686_retro_none.
bazelisk build //kernel:retroos-host --platforms=@platforms//host

ARGS=()
[ -n "$SHOT" ] && ARGS+=(--screenshot "$SHOT")
[ -n "$CMD" ]  && ARGS+=(--cmd "$CMD")

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

RETRO_TRACE=${TRACE:+1} exec bazel-bin/kernel/retroos-host "${ARGS[@]}" "$@"
