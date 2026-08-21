#!/bin/sh
set -eu

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    describe="$(git describe --tags --always --long 2>/dev/null || git rev-parse --short=12 HEAD)"

    if test -n "$(git status --porcelain --untracked-files=normal)"; then
        dirty=1
    else
        dirty=0
    fi
else
    describe=unknown
    dirty=0
fi

printf 'STABLE_RETROOS_GIT_DESCRIBE %s\n' "$describe"
printf 'STABLE_RETROOS_GIT_DIRTY %s\n' "$dirty"
