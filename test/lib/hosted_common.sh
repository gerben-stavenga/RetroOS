#!/bin/bash
# Shared engine selection for every hosted integration suite. Missing KVM is
# a failure here; run_all.sh owns optional prerequisite skips.
case "${ENGINE:-tcg}" in
    tcg) HOST_TARGET=retroos-host ;;
    kvm)
        if ! { : <> /dev/kvm; } 2>/dev/null; then
            echo "FAIL: ENGINE=kvm requires access to /dev/kvm" >&2
            exit 1
        fi
        HOST_TARGET=retroos-host-kvm
        ;;
    *) echo "Unknown ENGINE: $ENGINE (expected tcg or kvm)" >&2; exit 1 ;;
esac
HOST_BIN="bazel-bin/kernel/$HOST_TARGET"
export RETRO_HOST_BIN="$HOST_BIN"
