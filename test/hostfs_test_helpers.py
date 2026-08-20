"""Independent helpers for HostFS socket/protocol integration tests.

This module intentionally has its own frame codec rather than importing the
production codec, so integration tests can detect production framing mistakes.
"""

from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
HOSTFS = ROOT / "hostfs.py"
FLAG = 0x7e
ESC = 0x7d
MAX_BODY = 4096
TYPE_HELLO = 0xf0
TYPE_HELLO_ACK = 0xf1


def crc16(data):
    crc = 0xffff
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc


def frame(kind, payload=b""):
    body = bytes((kind,)) + payload
    body += struct.pack("<H", crc16(body))
    encoded = bytearray()
    for byte in body:
        if byte == FLAG:
            encoded.extend((ESC, 0x5e))
        elif byte == ESC:
            encoded.extend((ESC, 0x5d))
        else:
            encoded.append(byte)
    return bytes((FLAG,)) + encoded + bytes((FLAG,))


def recvall(conn, size, deadline=None):
    data = bytearray()
    while len(data) < size:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("timed out receiving protocol data")
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise RuntimeError("peer closed while receiving protocol data")
        data.extend(chunk)
    return bytes(data)


def recv_frame(conn):
    while recvall(conn, 1)[0] != FLAG:
        pass
    encoded = bytearray()
    while True:
        byte = recvall(conn, 1)[0]
        if byte == FLAG:
            break
        encoded.append(byte)
    body = bytearray()
    escaped = False
    for byte in encoded:
        if escaped:
            if byte == 0x5d:
                body.append(ESC)
            elif byte == 0x5e:
                body.append(FLAG)
            else:
                raise RuntimeError("malformed response escape")
            escaped = False
        elif byte == ESC:
            escaped = True
        else:
            body.append(byte)
    if escaped or not 3 <= len(body) <= MAX_BODY:
        raise RuntimeError("malformed response frame")
    if crc16(body[:-2]) != struct.unpack("<H", body[-2:])[0]:
        raise RuntimeError("bad response frame CRC")
    return body[0], bytes(body[1:-2])


def start_hostfs(root, sock_path):
    return subprocess.Popen(
        [sys.executable, "-u", str(HOSTFS), str(root), str(sock_path)],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def accept_connection(listener, description, timeout=10.0):
    listener.settimeout(timeout)
    try:
        conn, _ = listener.accept()
    except socket.timeout as exc:
        raise RuntimeError(f"timed out waiting for {description}") from exc
    conn.settimeout(5.0)
    return conn


def stop_process(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
