#!/usr/bin/env bash
# Install the suite's pinned Rust-DOS as a durable user-local executable.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX="${RUST_DOS_PREFIX:-$HOME/.local}"
SOURCE="${XDG_DATA_HOME:-$HOME/.local/share}/retroos/rust-dos/source"
TARGET="${XDG_CACHE_HOME:-$HOME/.cache}/retroos/rust-dos-build"
UPSTREAM=$(sed -n '1p' "$ROOT/third_party/rustdos_suite/UPSTREAM")
REVISION=$(sed -n '2p' "$ROOT/third_party/rustdos_suite/UPSTREAM")
SHORT=${REVISION:0:7}

if [ "$#" = 2 ] && [ "$1" = --from-build ]; then
    BINARY=$(realpath "$2")
elif [ "$#" = 0 ]; then
    if [ ! -d "$SOURCE/.git" ]; then
        mkdir -p "$SOURCE"
        git init "$SOURCE"
        git -C "$SOURCE" remote add origin "$UPSTREAM"
    fi
    if ! git -C "$SOURCE" diff --quiet || ! git -C "$SOURCE" diff --cached --quiet; then
        echo "Rust-DOS source has local edits: $SOURCE" >&2
        exit 1
    fi
    git -C "$SOURCE" fetch --depth 1 origin "$REVISION"
    git -C "$SOURCE" checkout --detach "$REVISION"
    (cd "$SOURCE" && cargo build --locked --release --no-default-features --features sdl --bin rust-dos --target-dir "$TARGET")
    BINARY="$TARGET/release/rust-dos"
else
    echo "Usage: $0 [--from-build PATH]" >&2
    exit 2
fi

VERSION=$("$BINARY" --version)
[[ "$VERSION" == *"commit $SHORT"* ]] || { echo "Build does not match pinned revision $REVISION: $VERSION" >&2; exit 1; }
mkdir -p "$PREFIX/bin" "$PREFIX/share/retroos/rust-dos"
install -m 644 "$ROOT/third_party/rustdos_suite/COPYING" "$PREFIX/share/retroos/rust-dos/COPYING"
STAGED=$(mktemp "$PREFIX/bin/.rust-dos-install.XXXXXX")
trap 'rm -f "$STAGED"' EXIT
install -m 755 "$BINARY" "$STAGED"
mv -f "$STAGED" "$PREFIX/bin/rust-dos"
{
    printf '%s\n%s\n%s\n' "$UPSTREAM" "$REVISION" "$VERSION"
    printf 'Build features: sdl (dynamic CPU core included)\n'
    sha256sum "$PREFIX/bin/rust-dos"
} > "$PREFIX/share/retroos/rust-dos/SOURCE.TXT"
printf 'Installed %s at %s/bin/rust-dos\n' "$VERSION" "$PREFIX"
