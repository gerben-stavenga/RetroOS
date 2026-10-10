#!/bin/bash
# Raw Multiboot module image metadata regression test.
set -euo pipefail
cd "$(dirname "$0")/.."

bazelisk build //:root_module_base_image >/dev/null

base=bazel-bin/retroos-base.img
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/root/DOOMS"
printf '%s\n' 'synthetic game payload' > "$tmp_dir/root/DOOMS/README.TXT"
chmod 444 "$tmp_dir/root/DOOMS/README.TXT"
chmod 555 "$tmp_dir/root/DOOMS"
tar -cf "$tmp_dir/games.tar" -C "$tmp_dir/root" .
chmod u+w "$tmp_dir/root/DOOMS"
python3 tools/build_module_image.py \
    --contents "$tmp_dir/games.tar" \
    --size-mb 1 \
    --writable-root \
    --out "$tmp_dir/games.img"

games="$tmp_dir/games.img"

for image in "$base" "$games"; do
    [[ "$(dd if="$image" bs=1 skip=1080 count=2 status=none | od -An -t x1 | tr -d ' ')" == "53ef" ]]
    [[ "$(dd if="$image" bs=1 skip=510 count=2 status=none | od -An -t x1 | tr -d ' ')" != "55aa" ]]
done

stat_field() {
    local path=$1 field=$2 image=${3:-$games}
    debugfs -R "stat $path" "$image" 2>/dev/null \
        | awk -v field="$field:" '{ for (i = 1; i <= NF; i++) if ($i == field) { print $(i + 1); exit } }'
}

root_uid=$(stat_field / User)
game_uid=$(stat_field /DOOMS User)
game_mode=$(stat_field /DOOMS Mode)
if [[ -z "$root_uid" || "$root_uid" != "$game_uid" ]]; then
    echo "FAIL: games root UID ($root_uid) differs from game directory UID ($game_uid)" >&2
    exit 1
fi
mode_value=$((8#$game_mode))
if (( (mode_value & 128) == 0 )); then
    echo "FAIL: game directory is not owner-writable (mode $game_mode)" >&2
    exit 1
fi

file_mode=$(stat_field /DOOMS/README.TXT Mode)
[[ "$file_mode" == "0644" ]]
[[ "$game_mode" == "0755" ]]
# The flat core module must use the same owner-write policy as the showcase.
base_uid=$(stat_field / User "$base")
core_uid=$(stat_field /RETROOS/COMMAND.COM User "$base")
core_mode=$(stat_field /RETROOS/COMMAND.COM Mode "$base")
[[ -n "$base_uid" && "$base_uid" == "$core_uid" ]]
if (( (8#$core_mode & 128) == 0 )); then
    echo "FAIL: base runtime is not owner-writable (mode $core_mode)" >&2
    exit 1
fi

echo "PASS: Multiboot fixtures are raw ext4 images with writable ownership"
