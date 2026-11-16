#!/bin/bash
# Hosted end-to-end smoke tests for CI.
#
# Each case boots a program on the hosted backend via test/hosted_test.py,
# optionally drives keyboard input, and asserts the kernel never panicked
# (and, for the text-mode DN shell, that its screen painted). The default TCG
# (software CPU) engine runs on any GitHub-hosted runner; set ENGINE=kvm to
# run the same cases on the KVM engine (requires /dev/kvm).
# Add a case by appending a `run` line.
#
# Exit 0 = all passed.
set -uo pipefail
cd "$(dirname "$0")/.."

ROOT_DIR=$(mktemp -d /tmp/retroos-games-root.XXXXXX)
trap 'rm -rf "$ROOT_DIR"' EXIT
tar -xf bazel-bin/root_module_base_tar.tar -C "$ROOT_DIR"
tar -xf bazel-bin/root_module_showcase_tar.tar -C "$ROOT_DIR"
chmod -R u+w "$ROOT_DIR"
source test/lib/hosted_common.sh

PY="python3 test/hosted_test.py --host-bin $HOST_BIN --directory $ROOT_DIR"
fail=0
run() { local label="$1"; shift; echo "=== $label ==="; $PY "$@" || { fail=1; echo "  ^ FAILED: $label"; }; }

# DN (Dos Navigator) boots into its text-mode file manager: assert the event
# loop ran (no boot panic) and the panel painted. Note: launching a program
# from DN's file panel with Enter is a known DPMI-overlay bug (see the
# dn-enter-launch-bug memory) — not exercised here.
run "DN boots + panel paints" \
    --keys "" --settle 5 --timeout 20 \
    --expect-log "event_loop entered" --expect-screen "free bytes on drive"

# DIGGER: 16-bit real-mode game, launched headless + a few driven keystrokes.
run "DIGGER (real-mode) + keyboard" \
    --cmd "GAMES/DIGGER/DIGGER.EXE" --keys "wait:3,SPACE,wait:1,RIGHT,RIGHT,ENTER" \
    --settle 2 --timeout 25

# DOOM shareware: require progress beyond timer initialization. A lost IRQ0
# EOI used to leave it spinning there indefinitely without a kernel panic.
run "DOOM (shareware, DPMI) boots" \
    --cmd "GAMES/DOOMS/DOOM.EXE" --settle 12 --timeout 35 \
    --expect-log "ST_Init: Init status bar."

# Exercise DN's child-execution path as well as the direct boot path.
run "DN launches DOOM" \
    --settle 6 --timeout 35 \
    --keys 'cd c:\games\dooms,ENTER,wait:2,doom.exe,ENTER,wait:15' \
    --expect-log "ST_Init: Init status bar."

# Substitute-BIOS VBE: controller/mode records, packed + direct-colour mode
# metadata, bank switching with retained VRAM, palette data, and LFB address.
run "VBE/SVGA controller, modes, banks, palette, LFB" \
    --cmd "TESTS/SVGAPROBE.COM" --settle 2 --timeout 25 \
    --expect-log "VBE-INFO-OK" --expect-log "VBE-MODES-OK" \
    --expect-log "VBE-LFB-OK" --expect-log "VBE-BANK-OK" \
    --expect-log "VBE-PAL-OK" --expect-log "VBE-ALL-OK"

# Emulated-SB single-cycle completion protocol (test/dos/sbproto): the DSP
# write-status busy flicker, the 8237 status TC bit, and the post-terminal
# count underflow — each regressed or went missing at least once (PoP's
# end-door hang / level-transition freeze). TC-OK on screen = all three hold.
run "SB DSP completion protocol" \
    --cmd "TESTS/SBTEST.COM" --settle 3 --timeout 30 \
    --expect-log "BUSY-OK" --expect-log "EDGE-OK" --expect-log "TC-OK"

# SB discovery/init conformance (test/dos/sbproto/sbdisc.asm): everything a
# game does BEFORE it plays a sample — version query, mixer, IRQ status and
# acknowledge, the 0xF2 trigger IRQ, the test register, and an auto-init
# block reaching terminal count. The last one caught a real gap: only the
# single-cycle path latched the 8237 TC bit, so an auto-init driver
# identifying its own interrupt by `in al, 0x08` was told "not mine".
# NOT here: sustained completion IRQs (TESTS/SBIRQ.COM). The hosted backend
# has no audio sink (Audio: EmulatedSilent), so nothing paces the guest's DMA
# and no completion interrupt is ever generated — the probe would fail for a
# reason that is not the thing under test. It runs where a card actually
# completes blocks: test/sb_86box.sh (real SB16) and QEMU.

run "SB discovery/init conformance" \
    --cmd "TESTS/SBDISC.COM" --settle 3 --timeout 40 \
    --expect-log "RST-OK" --expect-log "MIXRST-OK" --expect-log "MIXVOL-OK" \
    --expect-log "IRQSTAT-OK" --expect-log "E4E8-OK" --expect-log "TRIG-OK" \
    --expect-log "ACK8-OK" --expect-log "AUTOINIT-OK"

# Emulated-GUS (GF1) probe (test/dos/gusproto): DRAM poke/peek detection
# and register-file readback through the voice/register-select scheme.
# Markers accrete as GF1 phases land (timers, DMA upload, audible voice).
run "GUS (GF1) registers, DRAM, timer IRQ, DMA upload, voice" \
    --cmd "TESTS/GUSTEST.EXE" --settle 3 --timeout 45 \
    --expect-log "GDRAM-OK" --expect-log "GREG-OK" --expect-log "GTIMER-OK" \
    --expect-log "GDMA-OK" --expect-log "GVOICE-OK"

# PC speaker (test/dos/spkproto): PIT channel 2's OUT line at port 61h bit 5 —
# the only part of the speaker path a guest can check by itself, and the part
# programs poll as a PIT presence test and a sub-tick delay source. TONES-DONE
# means the tone sequence also ran to completion; measuring its pitch needs a
# host-side capture (see the .asm header for the recipe).
run "PC speaker OUT line + tone sequence" \
    --cmd "TESTS/SPKTEST.COM" --settle 3 --timeout 30 \
    --expect-log "OUT-OK" --expect-log "TONES-DONE"

exit $fail
