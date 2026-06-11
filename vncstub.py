#!/usr/bin/env python3
"""Minimal VNC client stub: completes the RFB handshake against Bochs's rfb
GUI and holds the connection open so Bochs doesn't panic with 'no client
present'. Discards all framebuffer traffic."""
import socket, struct, sys, time

host, port = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 5900
deadline = time.time() + 30
s = None
while time.time() < deadline:
    try:
        s = socket.create_connection((host, port), timeout=2)
        break
    except OSError:
        time.sleep(0.3)
if s is None:
    sys.exit("vncstub: could not connect")

def readn(n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            sys.exit(0)
        buf += chunk
    return buf

ver = readn(12)                      # b"RFB 003.xxx\n"
s.sendall(ver)                       # echo server version back
if ver >= b"RFB 003.007":
    ntypes = readn(1)[0]
    types = readn(ntypes)
    s.sendall(b"\x01")               # security type 1 = None
    if ver >= b"RFB 003.008":
        readn(4)                     # SecurityResult
else:
    readn(4)                         # 3.3: server picks security type
s.sendall(b"\x01")                   # ClientInit: shared
w, h, = struct.unpack(">HH", readn(4))
readn(16)                            # pixel format
readn(struct.unpack(">I", readn(4))[0])  # server name
print(f"vncstub: connected, {w}x{h}", flush=True)
s.settimeout(None)
while True:                          # drain and discard forever
    if not s.recv(65536):
        break
