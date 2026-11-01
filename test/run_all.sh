#!/usr/bin/env bash
# Compatibility entry point; Bazel owns test selection and execution.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -n "${RETRO_TEST_ONLY:-}${RETRO_TEST_EXCLUDE:-}${RETRO_TEST_GROUP:-}${RETRO_REQUIRE_KVM:-}${RETRO_REQUIRE_PUBLIC:-}" ]; then
    echo 'Use explicit //tests targets and Bazel tag filters instead of RETRO_TEST_* selection.' >&2
    exit 2
fi
exec bazelisk test //tests:portable "$@"
