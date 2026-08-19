#!/usr/bin/env python3
"""Deterministic two-ended HostFS lifecycle harness for tests.

This test-only proxy keeps QEMU's guest-facing serial socket connected while
allowing the QEMU endpoint and hostfs.py endpoint to be stopped and replaced
independently. It discards bytes whenever either peer is absent and clears both
directional buffers at every lifecycle boundary, so tests never replay stale
partial protocol data.

It is not part of the production HostFS deployment path.
"""

import os
import select
import socket
import sys
import time

RETRY_SECONDS = 0.1
MAX_BUFFER = 64 * 1024
READ_SIZE = 4096


def close_socket(sock):
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def connect_qemu(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(RETRY_SECONDS)
    try:
        sock.connect(path)
    except OSError:
        close_socket(sock)
        return None
    sock.settimeout(None)
    sock.setblocking(False)
    return sock


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <qemu_socket> <hostfs_socket>", file=sys.stderr)
        return 2

    qemu_path, host_path = sys.argv[1:]
    try:
        os.unlink(host_path)
    except FileNotFoundError:
        pass

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(host_path)
    listener.listen(1)
    listener.setblocking(False)

    qemu = None
    host = None
    to_qemu = bytearray()
    to_host = bytearray()
    next_qemu_attempt = 0.0

    def disconnect(endpoint):
        nonlocal qemu, host, to_qemu, to_host
        if endpoint == "qemu":
            close_socket(qemu)
            qemu = None
            print("hostfs-proxy: QEMU disconnected", flush=True)
        else:
            close_socket(host)
            host = None
            print("hostfs-proxy: HostFS disconnected", flush=True)
        # Neither partial requests nor responses survive either endpoint's
        # lifecycle boundary.
        to_qemu.clear()
        to_host.clear()

    def queue_for(source, data):
        nonlocal to_qemu, to_host
        target = host if source is qemu else qemu
        if target is None:
            # Never retain bytes across an absent endpoint.
            return True
        buffer = to_host if source is qemu else to_qemu
        if len(buffer) + len(data) > MAX_BUFFER:
            # The target is connected but not consuming. Disconnect it instead
            # of allowing a slow protocol peer to block the entire relay.
            disconnect("host" if source is qemu else "qemu")
            return False
        buffer.extend(data)
        return True

    def flush(endpoint):
        buffer = to_qemu if endpoint is qemu else to_host
        try:
            sent = endpoint.send(buffer)
        except (BlockingIOError, InterruptedError):
            return
        except (ConnectionError, OSError):
            disconnect("qemu" if endpoint is qemu else "host")
            return
        if sent <= 0:
            disconnect("qemu" if endpoint is qemu else "host")
            return
        del buffer[:sent]

    try:
        while True:
            now = time.monotonic()
            if qemu is None and now >= next_qemu_attempt:
                qemu = connect_qemu(qemu_path)
                next_qemu_attempt = now + RETRY_SECONDS
                if qemu is not None:
                    print("hostfs-proxy: connected to QEMU", flush=True)

            readable = [listener]
            writable = []
            if qemu is not None:
                readable.append(qemu)
                if to_qemu:
                    writable.append(qemu)
            if host is not None:
                readable.append(host)
                if to_host:
                    writable.append(host)

            readable, writable, _ = select.select(
                readable, writable, [], RETRY_SECONDS
            )
            for source in readable:
                if source is listener:
                    try:
                        new_host, _ = listener.accept()
                        new_host.setblocking(False)
                    except OSError:
                        continue
                    disconnect("host") if host is not None else None
                    host = new_host
                    print("hostfs-proxy: connected to HostFS", flush=True)
                    continue

                try:
                    data = source.recv(READ_SIZE)
                except (BlockingIOError, InterruptedError):
                    continue
                except (ConnectionError, OSError):
                    data = b""

                if not data:
                    disconnect("qemu" if source is qemu else "host")
                    continue
                queue_for(source, data)

            for endpoint in writable:
                if endpoint is qemu and qemu is endpoint:
                    flush(endpoint)
                elif endpoint is host and host is endpoint:
                    flush(endpoint)
    except KeyboardInterrupt:
        return 0
    finally:
        close_socket(qemu)
        close_socket(host)
        close_socket(listener)
        try:
            os.unlink(host_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
