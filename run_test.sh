#!/bin/bash
# Run RetroOS in QEMU and type a command into the shell.
# Usage: ./run_test.sh "NC.EXE"        (default arch: 386, wait: 5s)
#        ./run_test.sh "hello" x64 10   (arch x64, wait 10s after typing)

set -e

CMD="${1:?Usage: $0 <command> [arch] [wait_secs]}"
ARCH="${2:-386}"
WAIT="${3:-5}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

exec python3 -u - "$CMD" "$ARCH" "$WAIT" <<'PYEOF'
import socket, subprocess, time, os, signal, sys

cmd, arch, wait = sys.argv[1], sys.argv[2], int(sys.argv[3])
SOCK = "/tmp/retro-qemu-mon.sock"

# Clean up stale socket
try: os.unlink(SOCK)
except: pass

proc = subprocess.Popen(
    ["./run_qemu.sh", arch, "-display", "vnc=:99",
     "-monitor", f"unix:{SOCK},server,nowait"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    preexec_fn=os.setpgrp
)

time.sleep(3)

# Map characters to QEMU sendkey names
KEY_MAP = {
    '.': 'dot', '/': 'slash', '\\': 'backslash', '-': 'minus',
    '=': 'equal', ' ': 'spc', '\n': 'ret', ',': 'comma',
    ';': 'semicolon', "'": 'apostrophe', '[': 'bracket_left',
    ']': 'bracket_right', '`': 'grave_accent', '1': '1', '2': '2',
    '3': '3', '4': '4', '5': '5', '6': '6', '7': '7', '8': '8',
    '9': '9', '0': '0',
}

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(SOCK)
sock.settimeout(1)
try: sock.recv(4096)
except: pass

for ch in cmd + "\n":
    if ch.isupper():
        key = f"shift-{ch.lower()}"
    else:
        key = KEY_MAP.get(ch, ch)
    sock.send(f"sendkey {key}\n".encode())
    time.sleep(0.1)

time.sleep(wait)
# Send F12 for debug dump
sock.send(b"sendkey f12\n")
time.sleep(2)
sock.close()
proc.send_signal(signal.SIGTERM)
out = proc.communicate(timeout=5)[0].decode(errors='replace')
print(out)
PYEOF
