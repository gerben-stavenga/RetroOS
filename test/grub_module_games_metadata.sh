#!/bin/bash
# Raw Multiboot module image metadata regression test.
set -euo pipefail
cd "$(dirname "$0")/.."

bazelisk build //:root_module_base_image //:root_module_games_image >/dev/null

base=bazel-bin/retroos-base.img
games=bazel-bin/retroos-games.img
[[ "$(stat -c%s "$base")" -eq $((32 * 1024 * 1024)) ]]
[[ "$(stat -c%s "$games")" -eq $((96 * 1024 * 1024)) ]]

for image in "$base" "$games"; do
    [[ "$(dd if="$image" bs=1 skip=1080 count=2 status=none | od -An -t x1 | tr -d ' ')" == "53ef" ]]
    [[ "$(dd if="$image" bs=1 skip=510 count=2 status=none | od -An -t x1 | tr -d ' ')" != "55aa" ]]
done

stat_field() {
    local path=$1 field=$2
    debugfs -R "stat $path" "$games" 2>/dev/null \
        | awk -v field="$field:" '{ for (i = 1; i <= NF; i++) if ($i == field) { print $(i + 1); exit } }'
}

root_gid=$(stat_field / Group)
game_gid=$(stat_field /DOOMS Group)
game_mode=$(stat_field /DOOMS Mode)
if [[ -z "$root_gid" || "$root_gid" != "$game_gid" ]]; then
    echo "FAIL: games root GID ($root_gid) differs from game directory GID ($game_gid)" >&2
    exit 1
fi
mode_value=$((8#$game_mode))
if (( (mode_value & 16) == 0 )); then
    echo "FAIL: game directory is not group-writable (mode $game_mode)" >&2
    exit 1
fi

echo "PASS: Multiboot fixtures are raw ext4 images with writable ownership"
