#!/usr/bin/env bash
# Rebuild the shipped upstream app; source/dependencies remain outside the repo.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
revision=90627f7cd70833cbcdaa883ca9506524d9986c24
work=${RAT_BUILD_DIR:-/tmp/retroos-rat-build}
mkdir -p "$work"
if [[ ! -d "$work/source/.git" ]]; then
    git clone https://github.com/dividebysandwich/rat-commander.git "$work/source"
fi
git -C "$work/source" checkout --detach "$revision"
# Add a musl cross compiler's bin directory to PATH before running this script.
# x86_64-linux-musl-gcc is needed by aws-lc, liblzma and zstd.
command -v x86_64-linux-musl-gcc >/dev/null
rustup target add x86_64-unknown-linux-musl
(cd "$work/source" && cargo build --locked --release --no-default-features --target x86_64-unknown-linux-musl)
install -m 755 "$work/source/target/x86_64-unknown-linux-musl/release/rc" "$repo_root/apps-boot/rc/RC.EXE"
install -m 644 "$work/source/LICENSE" "$repo_root/apps-boot/rc/LICENSE"
