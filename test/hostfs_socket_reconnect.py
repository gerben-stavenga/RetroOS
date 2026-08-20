#!/usr/bin/env python3
"""Exercise hostfs.py's persistent UNIX-socket connection handling."""

from pathlib import Path
import socket
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CMD_OPEN = 0x01
CMD_READ = 0x02
CMD_MKDIR = 0x08
CMD_STAT = 0x04
from hostfs_test_helpers import (  # noqa: E402
    TYPE_HELLO,
    TYPE_HELLO_ACK,
    accept_connection,
    frame,
    recv_frame,
    start_hostfs,
    stop_process,
)


def check_session(conn, expected, exercise_directory_commands=False):
    token = struct.pack('<I', 0x12345678)
    conn.sendall(frame(TYPE_HELLO, token))
    kind, payload = recv_frame(conn)
    if kind != TYPE_HELLO_ACK or payload != token:
        raise RuntimeError("HELLO_ACK mismatch")

    path = b"HELLO.TXT"
    conn.sendall(frame(CMD_OPEN, struct.pack("<H", len(path)) + path))
    kind, response = recv_frame(conn)
    if kind != 0x81 or len(response) != 12:
        raise RuntimeError(f"unexpected OPEN response type or size: {kind:#x}")
    status, handle, size = struct.unpack("<iII", response)
    if status != 0:
        raise RuntimeError(f"OPEN failed with status {status}")
    if size != len(expected):
        raise RuntimeError(f"OPEN returned size {size}, expected {len(expected)}")

    conn.sendall(frame(CMD_READ, struct.pack("<III", handle, 0, len(expected))))
    kind, response = recv_frame(conn)
    if kind != 0x82 or len(response) < 8:
        raise RuntimeError(f"unexpected READ response type or size: {kind:#x}")
    status, data_size = struct.unpack("<iI", response[:8])
    data = response[8:]
    if status != len(expected) or data_size != len(expected) or len(data) != data_size or data != expected:
        raise RuntimeError(
            f"READ returned status={status}, data_size={data_size}, data={data!r}; expected {expected!r}"
        )

    if exercise_directory_commands:
        conn.sendall(frame(CMD_STAT, struct.pack("<H", 0)))
        kind, response = recv_frame(conn)
        if kind != (0x80 | CMD_STAT) or len(response) != 9:
            raise RuntimeError("unexpected STAT response")
        status, size, is_dir = struct.unpack("<iIB", response)
        if status != 0 or size != 0 or is_dir != 1:
            raise RuntimeError("STAT did not report the session root directory")

        new_dir = b"CREATED"
        conn.sendall(frame(CMD_MKDIR, struct.pack("<H", len(new_dir)) + new_dir))
        kind, response = recv_frame(conn)
        if kind != (0x80 | CMD_MKDIR) or len(response) != 4:
            raise RuntimeError("unexpected MKDIR response")
        if struct.unpack("<i", response)[0] != 0:
            raise RuntimeError("MKDIR failed")

        conn.sendall(frame(CMD_STAT, struct.pack("<H", len(new_dir)) + new_dir))
        kind, response = recv_frame(conn)
        if kind != (0x80 | CMD_STAT) or len(response) != 9:
            raise RuntimeError("unexpected STAT response for created directory")
        status, size, is_dir = struct.unpack("<iIB", response)
        if status != 0 or size != 0 or is_dir != 1:
            raise RuntimeError("STAT did not report the created directory")


def main():
    with tempfile.TemporaryDirectory(prefix="retroos-hostfs-socket-") as stage:
        stage = Path(stage)
        root = stage / "root"
        root.mkdir()
        (root / "HELLO.TXT").write_bytes(b"HELLO")
        sock_path = stage / "hostfs.sock"

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(sock_path))
        listener.listen(1)

        hostfs = None
        peer = None
        replacement = None
        try:
            hostfs = start_hostfs(root, sock_path)
            peer = accept_connection(listener, "initial HostFS connection")
            check_session(peer, b"HELLO", exercise_directory_commands=True)
            # Stop the server while its peer is still connected. This is the
            # failure ordering that must not leave a stale accepted socket.
            stop_process(hostfs)
            hostfs = None
            peer.close()
            peer = None

            hostfs = start_hostfs(root, sock_path)
            replacement = accept_connection(listener, "HostFS replacement connection")
            check_session(replacement, b"HELLO")
            replacement.close()
            replacement = None

            peer = accept_connection(listener, "HostFS reconnect")
            check_session(peer, b"HELLO")

            print("PASS: HostFS socket peer and server restart recovery")
        finally:
            if peer is not None:
                peer.close()
            if replacement is not None:
                replacement.close()
            stop_process(hostfs)
            listener.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise
