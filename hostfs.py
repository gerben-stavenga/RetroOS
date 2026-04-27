#!/usr/bin/env python3
"""Host filesystem server for RetroOS hostfs mount.

Listens on a Unix socket and serves file operations from a host directory.
QEMU connects the guest's COM1 to this socket via:
  -chardev socket,id=hostfs,path=/tmp/retroos-hostfs.sock,server=on,wait=off
  -device isa-serial,chardev=hostfs

Protocol (little-endian):
  Request:  cmd(u8) + payload (cmd-specific)
  Response: status(i32) + payload (cmd-specific)

Commands:
  0x01 OPEN:    path_len(u16) path          → status(i32) handle(u32) size(u32)
  0x02 READ:    handle(u32) offset(u32) len(u32) → status(i32) data_len(u32) data
  0x03 CLOSE:   handle(u32)                 → status(i32)
  0x04 STAT:    path_len(u16) path          → status(i32) size(u32) is_dir(u8)
  0x05 READDIR: path_len(u16) path index(u32) → status(i32) name_len(u8) name size(u32) is_dir(u8)
  0x06 CREATE:  path_len(u16) path          → status(i32) handle(u32)
  0x07 WRITE:   handle(u32) offset(u32) len(u32) data → status(i32) written(u32)
"""

import os
import socket
import struct
import sys

CMD_OPEN = 0x01
CMD_READ = 0x02
CMD_CLOSE = 0x03
CMD_STAT = 0x04
CMD_READDIR = 0x05
CMD_CREATE = 0x06
CMD_WRITE = 0x07

class HostFs:
    def __init__(self, root_dir):
        self.root = os.path.abspath(root_dir)
        self.handles = {}  # handle -> open file object
        self.next_handle = 1

    def _resolve(self, path, allow_missing_last=False):
        """Resolve guest path to host path, case-insensitive, preventing escapes.
        If allow_missing_last is True, the final path component may not yet
        exist (used for CREATE)."""
        p = path.replace(b'\\', b'/').lstrip(b'/').decode('ascii', errors='replace')
        cur = self.root
        if p and p != '.':
            parts = p.split('/')
            for i, component in enumerate(parts):
                if not component:
                    continue
                is_last = i == len(parts) - 1
                exact = os.path.join(cur, component)
                if os.path.exists(exact):
                    cur = exact
                    continue
                found = False
                try:
                    for entry in os.listdir(cur):
                        if entry.lower() == component.lower():
                            cur = os.path.join(cur, entry)
                            found = True
                            break
                except OSError:
                    return None
                if not found:
                    if is_last and allow_missing_last:
                        cur = exact
                        break
                    return None
        full = os.path.normpath(cur)
        if not full.startswith(self.root):
            return None
        return full

    def handle_open(self, conn):
        path_len = struct.unpack('<H', recvall(conn, 2))[0]
        path = recvall(conn, path_len)
        full = self._resolve(path)
        print(f" {path!r} -> {full}", file=sys.stderr)
        if full is None or not os.path.isfile(full):
            conn.sendall(struct.pack('<iII', -2, 0, 0))  # ENOENT
            return
        try:
            f = open(full, 'rb')
            f.seek(0, 2)
            size = f.tell()
            f.seek(0)
        except OSError:
            conn.sendall(struct.pack('<iII', -5, 0, 0))  # EIO
            return
        h = self.next_handle
        self.next_handle += 1
        self.handles[h] = f
        conn.sendall(struct.pack('<iII', 0, h, size))

    def handle_read(self, conn):
        handle, offset, length = struct.unpack('<III', recvall(conn, 12))
        f = self.handles.get(handle)
        if f is None:
            conn.sendall(struct.pack('<iI', -9, 0))
            return
        try:
            f.seek(offset)
            data = f.read(length)
        except OSError:
            conn.sendall(struct.pack('<iI', -5, 0))
            return
        conn.sendall(struct.pack('<iI', len(data), len(data)))
        conn.sendall(data)

    def handle_close(self, conn):
        handle = struct.unpack('<I', recvall(conn, 4))[0]
        f = self.handles.pop(handle, None)
        if f:
            f.close()
            conn.sendall(struct.pack('<i', 0))
        else:
            conn.sendall(struct.pack('<i', -9))

    def handle_stat(self, conn):
        path_len = struct.unpack('<H', recvall(conn, 2))[0]
        path = recvall(conn, path_len)
        full = self._resolve(path)
        print(f" {path!r} -> {full}", file=sys.stderr)
        if full is None or not os.path.exists(full):
            conn.sendall(struct.pack('<iIB', -2, 0, 0))
            return
        st = os.stat(full)
        is_dir = 1 if os.path.isdir(full) else 0
        size = st.st_size if not is_dir else 0
        conn.sendall(struct.pack('<iIB', 0, size & 0xFFFFFFFF, is_dir))

    def handle_readdir(self, conn):
        path_len = struct.unpack('<H', recvall(conn, 2))[0]
        path = recvall(conn, path_len)
        index = struct.unpack('<I', recvall(conn, 4))[0]
        full = self._resolve(path)
        print(f" {path!r}[{index}] -> {full}", file=sys.stderr)
        if full is None or not os.path.isdir(full):
            conn.sendall(struct.pack('<i', -2))
            return
        try:
            entries = sorted(e for e in os.listdir(full) if not e.startswith('.'))
        except OSError:
            conn.sendall(struct.pack('<i', -5))
            return
        if index >= len(entries):
            conn.sendall(struct.pack('<i', -1))  # end of dir
            return
        name = entries[index].encode('ascii', errors='replace')[:100]
        entry_path = os.path.join(full, entries[index])
        is_dir = 1 if os.path.isdir(entry_path) else 0
        size = os.path.getsize(entry_path) if not is_dir else 0
        conn.sendall(struct.pack('<iB', 0, len(name)))
        conn.sendall(name)
        conn.sendall(struct.pack('<IB', size & 0xFFFFFFFF, is_dir))

    def handle_create(self, conn):
        path_len = struct.unpack('<H', recvall(conn, 2))[0]
        path = recvall(conn, path_len)
        full = self._resolve(path, allow_missing_last=True)
        print(f" {path!r} -> {full}", file=sys.stderr)
        if full is None:
            conn.sendall(struct.pack('<iI', -2, 0))
            return
        try:
            f = open(full, 'w+b')
        except OSError:
            conn.sendall(struct.pack('<iI', -5, 0))
            return
        h = self.next_handle
        self.next_handle += 1
        self.handles[h] = f
        conn.sendall(struct.pack('<iI', 0, h))

    def handle_write(self, conn):
        handle, offset, length = struct.unpack('<III', recvall(conn, 12))
        data = recvall(conn, length) if length > 0 else b''
        f = self.handles.get(handle)
        if f is None:
            conn.sendall(struct.pack('<iI', -9, 0))
            return
        try:
            f.seek(offset)
            f.write(data)
            f.flush()
        except OSError:
            conn.sendall(struct.pack('<iI', -5, 0))
            return
        conn.sendall(struct.pack('<iI', 0, len(data)))

    def dispatch(self, conn):
        CMD_NAMES = {1: 'OPEN', 2: 'READ', 3: 'CLOSE', 4: 'STAT',
                     5: 'READDIR', 6: 'CREATE', 7: 'WRITE'}
        while True:
            cmd_byte = conn.recv(1)
            if not cmd_byte:
                break
            cmd = cmd_byte[0]
            print(f"  cmd: {CMD_NAMES.get(cmd, f'0x{cmd:02x}')}", end='', file=sys.stderr)
            if cmd == CMD_OPEN:
                self.handle_open(conn)
            elif cmd == CMD_READ:
                self.handle_read(conn)
            elif cmd == CMD_CLOSE:
                self.handle_close(conn)
            elif cmd == CMD_STAT:
                self.handle_stat(conn)
            elif cmd == CMD_READDIR:
                self.handle_readdir(conn)
            elif cmd == CMD_CREATE:
                self.handle_create(conn)
            elif cmd == CMD_WRITE:
                self.handle_write(conn)
            else:
                print(f"\nUnknown command: 0x{cmd:02x}", file=sys.stderr)
                break


def recvall(conn, n):
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <directory> [socket_path]", file=sys.stderr)
        sys.exit(1)

    root_dir = sys.argv[1]
    sock_path = sys.argv[2] if len(sys.argv) > 2 else '/tmp/retroos-hostfs.sock'

    if not os.path.isdir(root_dir):
        print(f"Error: {root_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    fs = HostFs(root_dir)

    # Connect to QEMU's chardev socket (QEMU is the server)
    print(f"hostfs: connecting to {sock_path} (serving {root_dir})")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        try:
            conn.connect(sock_path)
            break
        except (ConnectionRefusedError, FileNotFoundError):
            import time
            time.sleep(0.5)

    print("hostfs: connected to QEMU")
    try:
        fs.dispatch(conn)
    except (ConnectionError, OSError) as e:
        print(f"hostfs: {e}")
    finally:
        conn.close()
        print("hostfs: disconnected")


if __name__ == '__main__':
    main()
