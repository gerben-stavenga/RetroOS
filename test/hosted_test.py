#!/usr/bin/env python3
"""Hosted (interpreter) test driver for RetroOS.

Boots the headless `retroos-host` binary, optionally drives timed keyboard
input on its stdin (the host turns stdin bytes into PC scancodes — see
kernel/src/main.rs spawn_keyboard), then asserts on the kernel debug log
(stderr) and/or the VGA text-screen snapshot (--screenshot).

This is the CI-friendly way to exercise the OS end-to-end with no QEMU/KVM:
the software CPU runs as an ordinary host process, so it works on any runner.

Two shapes:
  * direct launch  — `--cmd GAMES/DOOMS/DOOM.EXE`, drive menu keys, assert the
                     game reached its main loop without a kernel panic.
  * boot to DN     — no --cmd; the OS boots into Dos Navigator. Drive arrows +
                     Enter to launch a highlighted program, assert via the text
                     screenshot. (Also the regression repro for "Enter in DN".)

Keyboard bytes are raw terminal bytes: printable ASCII, '\\r' = Enter,
'\\x1b' = Esc, and ANSI arrow sequences '\\x1b[A/B/C/D' (Up/Down/Right/Left) —
exactly what a real terminal would send, which spawn_keyboard already decodes.

Exit code 0 = PASS, 1 = FAIL.
"""

import argparse
import os
import subprocess
import sys
import time

HOST_BIN = "bazel-bin/kernel/retroos-host"

# Named key tokens for the --keys script (semicolon-separated). Anything not a
# token is sent as its literal bytes.
KEYS = {
    "ENTER": b"\r",
    "ESC": b"\x1b",
    "UP": b"\x1b[A",
    "DOWN": b"\x1b[B",
    "RIGHT": b"\x1b[C",
    "LEFT": b"\x1b[D",
    "TAB": b"\t",
    "SPACE": b" ",
}


def parse_keys(script):
    """A key script is 'tok,tok,...' where a tok is NAME, 'wait:SECS', or text.

    e.g. 'DOWN,DOWN,wait:0.5,ENTER' moves down twice, waits, presses Enter.
    Returns a list of ('key', bytes) / ('wait', secs) actions.
    """
    actions = []
    if not script:
        return actions
    for tok in script.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok.startswith("wait:"):
            actions.append(("wait", float(tok[5:])))
        elif tok in KEYS:
            actions.append(("key", KEYS[tok]))
        else:
            actions.append(("key", tok.encode()))
    return actions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", help="DOS program to launch headless (else boots to DN)")
    ap.add_argument("--cwd", help="working directory on the guest disk")
    ap.add_argument("--image", default="bazel-bin/image.bin",
                    help="disk image (default: the open-source image)")
    ap.add_argument("--keys", default="",
                    help="comma-separated key script, e.g. 'DOWN,wait:1,ENTER'")
    ap.add_argument("--settle", type=float, default=2.0,
                    help="seconds to wait before the first keystroke")
    ap.add_argument("--timeout", type=float, default=30.0,
                    help="hard cap on the run")
    ap.add_argument("--screenshot", help="write the final VGA text screen here")
    ap.add_argument("--expect-screen", action="append", default=[],
                    help="substring that MUST appear in the screenshot (repeatable)")
    ap.add_argument("--expect-log", action="append", default=[],
                    help="substring that MUST appear in the kernel log (repeatable)")
    ap.add_argument("--forbid-log", action="append", default=["KERNEL PANIC"],
                    help="substring that must NOT appear in the log (repeatable)")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    if not os.path.exists(HOST_BIN):
        sys.exit(f"hosted_test: {HOST_BIN} not built — "
                 f"run: bazelisk build //kernel:retroos-host --platforms=@platforms//host")

    # IMPORTANT: retroos-host treats the FIRST positional as the disk image and
    # slurps every following arg into the guest program's argv — so all flags
    # MUST come before the image path.
    shot = args.screenshot or "/tmp/retroos-hosted-shot.txt"
    cmdline = [HOST_BIN, "--screenshot", shot]
    if args.cmd:
        cmdline += ["--cmd", args.cmd]
        cmdline += ["--cwd", args.cwd or (os.path.dirname(args.cmd) + "/")]
    cmdline.append(args.image)

    # Drive keys on stdin; capture the kernel log from stderr (the 0xE9 sink).
    proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    deadline = time.time() + args.timeout
    try:
        time.sleep(min(args.settle, args.timeout))
        for kind, val in parse_keys(args.keys):
            if time.time() > deadline:
                break
            if kind == "wait":
                time.sleep(val)
            else:
                try:
                    proc.stdin.write(val)
                    proc.stdin.flush()
                except BrokenPipeError:
                    break
                time.sleep(0.15)  # let the guest service the keystroke
        # Let the screenshot watcher (1 Hz) capture the settled screen.
        remaining = max(0.0, deadline - time.time())
        time.sleep(min(1.5, remaining))
    finally:
        proc.terminate()
        try:
            log = proc.communicate(timeout=5)[1].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            proc.kill()
            log = proc.communicate()[1].decode("utf-8", "replace")

    screen = ""
    if os.path.exists(shot):
        with open(shot, encoding="utf-8", errors="replace") as f:
            screen = f.read()

    fails = []
    for s in args.forbid_log:
        if s in log:
            fails.append(f"log contained forbidden {s!r}")
    for s in args.expect_log:
        if s not in log:
            fails.append(f"log missing expected {s!r}")
    for s in args.expect_screen:
        if s not in screen:
            fails.append(f"screen missing expected {s!r}")

    if fails:
        print("FAIL:", "; ".join(fails))
        print("--- last 20 log lines ---")
        print("\n".join(log.splitlines()[-20:]))
        if screen:
            print("--- screen ---")
            print(screen)
        sys.exit(1)
    print(f"PASS: {args.cmd or 'DN boot'} "
          f"({len(args.expect_log)} log + {len(args.expect_screen)} screen checks)")


if __name__ == "__main__":
    main()
