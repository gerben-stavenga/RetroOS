#!/usr/bin/env python3
# Keep this file a self-contained script with no non-standard Python
# dependencies. It is intentionally easy to copy to a target host and run
# directly without installing a package or synchronizing companion modules.
"""Host filesystem server for RetroOS hostfs mount.

Listens on a Unix socket and serves file operations from a host directory.
QEMU connects the guest's COM1 to this socket via:
  -chardev socket,id=hostfs,path=/tmp/retroos-hostfs.sock,server=on,wait=on
  -device isa-serial,chardev=hostfs

For a physical COM1 connection through a Linux USB serial adapter:
  hostfs.py <directory> --serial /dev/serial/by-path/<device> [--pause-key]

With `--pause-key` on an interactive terminal, press `p` to toggle a
fault-injection mode that drains frames without sending acknowledgements or
filesystem responses. Press `p` again to resume.

The physical serial transport is configured for 115200 baud, 8N1, with
hardware flow control disabled.

Protocol:
  A frame is FLAG (0x7e), escaped body, FLAG (0x7e). The body is
  type(u8) + payload + crc16-ccitt(u16), with the CRC over type + payload.
  0x7e is escaped as 0x7d 0x5e and 0x7d as 0x7d 0x5d.

  HELLO (0xf0) has a u32 session token payload and receives HELLO_ACK
  (0xf1) with the same token. Requests use the command values below;
  responses use 0x80 | command. Response payloads are unchanged. A status of
  -75 (EOVERFLOW) means a host size or requested READ cannot fit the u32/frame
  representation and is an ordinary command error.

Commands:
  0x01 OPEN:    path_len(u16) path          → status(i32) handle(u32) size(u32)
  0x02 READ:    handle(u32) offset(u32) len(u32) → status(i32) data_len(u32) data
  0x03 CLOSE:   handle(u32)                 → (no reply; guest fire-and-forgets)
  0x04 STAT:    path_len(u16) path          → status(i32) size(u32) is_dir(u8)
  0x05 READDIR: path_len(u16) path index(u32) → status(i32) name_len(u8) name size(u32) is_dir(u8) mtime(u32)
  0x06 CREATE:  path_len(u16) path          → status(i32) handle(u32)
  0x07 WRITE:   handle(u32) offset(u32) len(u32) data → status(i32) written(u32)
  0x08 MKDIR:   path_len(u16) path          → status(i32)
"""

import argparse
import os
import select
import socket
import stat
import struct
import sys
import termios
import threading
import time
import tty
from collections import deque

SERIAL_BAUD = 115200
FLAG = 0x7e
ESC = 0x7d
MAX_BODY = 4096
# READ responses contain a frame type, CRC, status, data length, and data.
MAX_READ_DATA = MAX_BODY - 1 - 2 - 8
MAX_U32 = 0xffffffff
ERR_OVERFLOW = -75  # EOVERFLOW: value cannot be represented on the wire
TYPE_HELLO = 0xf0
TYPE_HELLO_ACK = 0xf1


class PauseController:
    """Own the pause-key thread and restoration of the user's terminal."""

    def __init__(self, paused):
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, args=(paused,))
        self.thread.start()

    def _run(self, paused):
        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            print("hostfs: press p to pause/resume responses", file=sys.stderr, flush=True)
            while not self.stop.is_set():
                readable, _, _ = select.select([fd], [], [], 0.2)
                if not readable:
                    continue
                key = os.read(fd, 1).lower()
                if key == b"p":
                    if paused.is_set():
                        paused.clear()
                        print("hostfs: responding", file=sys.stderr, flush=True)
                    else:
                        paused.set()
                        print("hostfs: paused (draining without responding)", file=sys.stderr, flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, saved)

    def close(self):
        self.stop.set()
        self.thread.join()


def start_pause_key(paused):
    """Start pause-key handling, or return None when stdin is not a TTY."""
    if not sys.stdin.isatty():
        print("hostfs: --pause-key requires an interactive stdin TTY", file=sys.stderr)
        return None
    return PauseController(paused)


def crc16_ccitt(data):
    crc = 0xffff
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc


def encode_frame(frame_type, payload=b''):
    body = bytes((frame_type,)) + payload
    body += struct.pack('<H', crc16_ccitt(body))
    escaped = bytearray()
    for byte in body:
        if byte == FLAG:
            escaped.extend((ESC, 0x5e))
        elif byte == ESC:
            escaped.extend((ESC, 0x5d))
        else:
            escaped.append(byte)
    return bytes((FLAG,)) + bytes(escaped) + bytes((FLAG,))


class FrameParser:
    """Incremental parser that resynchronizes at every FLAG."""

    def __init__(self):
        self.body = bytearray()
        self.in_frame = False
        self.escaped = False

    def feed(self, data):
        frames = []
        for byte in data:
            if byte == FLAG:
                if self.in_frame and not self.escaped and self.body:
                    body = bytes(self.body)
                    if len(body) >= 3 and len(body) <= MAX_BODY:
                        received = struct.unpack('<H', body[-2:])[0]
                        content = body[:-2]
                        if crc16_ccitt(content) == received:
                            frames.append((content[0], content[1:]))
                # The flag also starts the next frame. This is what recovers
                # from a truncated or corrupt frame followed by HELLO.
                self.body.clear()
                self.in_frame = True
                self.escaped = False
                continue
            if not self.in_frame:
                continue
            if self.escaped:
                if byte == 0x5e:
                    byte = FLAG
                elif byte == 0x5d:
                    byte = ESC
                else:
                    self.body.clear()
                    self.in_frame = False
                    self.escaped = False
                    continue
                self.escaped = False
            elif byte == ESC:
                self.escaped = True
                continue
            if len(self.body) < MAX_BODY:
                self.body.append(byte)
            else:
                # Keep consuming until FLAG, but never grow without bound.
                self.body.clear()
                self.in_frame = False
                self.escaped = False
        return frames


class FrameStream:
    """Own parser state and frames read ahead of the current protocol phase."""

    def __init__(self):
        self.parser = FrameParser()
        self.pending = deque()

    def recv_frames(self, conn):
        if self.pending:
            frames = list(self.pending)
            self.pending.clear()
            return frames
        data = conn.recv(4096)
        if not data:
            return None
        return self.parser.feed(data)

    def retain(self, frames):
        self.pending.extend(frames)


CMD_OPEN = 0x01
CMD_READ = 0x02
CMD_CLOSE = 0x03
CMD_MKDIR = 0x08
CMD_STAT = 0x04
CMD_READDIR = 0x05
CMD_CREATE = 0x06
CMD_WRITE = 0x07

class HostFs:
    def __init__(self, root_dir):
        # Canonicalize once so containment is component-aware and symlinks
        # cannot redirect a guest path outside the exported tree.
        self.root = os.path.realpath(os.path.abspath(root_dir))
        self.handles = {}  # handle -> open file object
        self.next_handle = 1

    def reset_session(self):
        """Drop file state when the guest starts a new HostFS session."""
        handles = list(self.handles.values())
        self.handles.clear()
        self.next_handle = 1
        for file_obj in handles:
            try:
                file_obj.close()
            except OSError:
                pass

    def _resolve(self, path, allow_missing_last=False):
        """Resolve a guest path beneath the exported tree.

        This rejects pre-existing ``..`` and symlink escapes, including
        similarly prefixed sibling directories. It deliberately does not claim
        race-proof containment: a hostile host process could replace a path
        component after validation and before a later name-based operation.
        The exported tree is therefore expected to be trusted against such
        concurrent mutation. If allow_missing_last is True, the final path
        component may not yet exist (used for CREATE)."""
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
        full = os.path.realpath(os.path.normpath(cur))
        try:
            if os.path.commonpath((self.root, full)) != self.root:
                return None
        except ValueError:
            # Different drives on Windows, or another platform-specific path
            # namespace, cannot be inside the configured export root.
            return None
        return full

    @staticmethod
    def _path_arg(payload):
        if len(payload) < 2:
            raise ValueError
        length = struct.unpack_from('<H', payload)[0]
        if len(payload) != length + 2:
            raise ValueError
        return payload[2:]

    def _open(self, payload):
        path = self._path_arg(payload)
        full = self._resolve(path)
        print(f" {path!r} -> {full}", file=sys.stderr)
        if full is None or not os.path.isfile(full):
            return struct.pack('<iII', -2, 0, 0)
        try:
            file_obj = open(full, 'rb')
            size = os.fstat(file_obj.fileno()).st_size
            if size > MAX_U32:
                file_obj.close()
                return struct.pack('<iII', ERR_OVERFLOW, 0, 0)
        except OSError:
            return struct.pack('<iII', -5, 0, 0)
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = file_obj
        return struct.pack('<iII', 0, handle, size)

    def _read(self, payload):
        if len(payload) != 12:
            raise ValueError
        handle, offset, length = struct.unpack('<III', payload)
        if length > MAX_READ_DATA:
            return struct.pack('<iI', ERR_OVERFLOW, 0)
        file_obj = self.handles.get(handle)
        if file_obj is None:
            return struct.pack('<iI', -9, 0)
        try:
            file_obj.seek(offset)
            data = file_obj.read(length)
        except OSError:
            return struct.pack('<iI', -5, 0)
        return struct.pack('<iI', len(data), len(data)) + data

    def _close(self, payload):
        if len(payload) != 4:
            raise ValueError
        file_obj = self.handles.pop(struct.unpack('<I', payload)[0], None)
        if file_obj is not None:
            try:
                file_obj.close()
            except OSError:
                pass
        return None

    def _stat(self, payload):
        path = self._path_arg(payload)
        full = self._resolve(path)
        print(f" {path!r} -> {full}", file=sys.stderr)
        if full is None:
            return struct.pack('<iIB', -2, 0, 0)
        try:
            metadata = os.stat(full)
        except FileNotFoundError:
            return struct.pack('<iIB', -2, 0, 0)
        except OSError:
            return struct.pack('<iIB', -5, 0, 0)
        is_dir = stat.S_ISDIR(metadata.st_mode)
        size = 0 if is_dir else metadata.st_size
        if size > MAX_U32:
            return struct.pack('<iIB', ERR_OVERFLOW, 0, int(is_dir))
        return struct.pack('<iIB', 0, size, int(is_dir))

    def _readdir(self, payload):
        if len(payload) < 6:
            raise ValueError
        length = struct.unpack_from('<H', payload)[0]
        if len(payload) != length + 6:
            raise ValueError
        path = payload[2:2 + length]
        index = struct.unpack_from('<I', payload, 2 + length)[0]
        full = self._resolve(path)
        print(f" {path!r}[{index}] -> {full}", file=sys.stderr)
        if full is None:
            return struct.pack('<i', -2)
        try:
            entries = sorted(entry for entry in os.listdir(full) if not entry.startswith('.'))
        except (FileNotFoundError, NotADirectoryError):
            return struct.pack('<i', -2)
        except OSError:
            return struct.pack('<i', -5)
        if index >= len(entries):
            return struct.pack('<i', -1)
        name = entries[index].encode('ascii', errors='replace')[:100]
        entry = os.path.join(full, entries[index])
        try:
            metadata = os.stat(entry)
        except FileNotFoundError:
            return struct.pack('<iB', -2, 0)
        except OSError:
            return struct.pack('<iB', -5, 0)
        is_dir = stat.S_ISDIR(metadata.st_mode)
        size = 0 if is_dir else metadata.st_size
        if size > MAX_U32:
            return struct.pack('<iB', ERR_OVERFLOW, 0)
        mtime = int(metadata.st_mtime) & 0xffffffff
        return struct.pack('<iB', 0, len(name)) + name + struct.pack('<IBI', size, int(is_dir), mtime)

    def _create(self, payload):
        path = self._path_arg(payload)
        full = self._resolve(path, allow_missing_last=True)
        print(f" {path!r} -> {full}", file=sys.stderr)
        if full is None:
            return struct.pack('<iI', -2, 0)
        try:
            file_obj = open(full, 'w+b')
        except OSError:
            return struct.pack('<iI', -5, 0)
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = file_obj
        return struct.pack('<iI', 0, handle)

    def _write(self, payload):
        if len(payload) < 12:
            raise ValueError
        handle, offset, length = struct.unpack_from('<III', payload)
        if len(payload) != 12 + length:
            raise ValueError
        file_obj = self.handles.get(handle)
        if file_obj is None:
            return struct.pack('<iI', -9, 0)
        try:
            file_obj.seek(offset)
            file_obj.write(payload[12:])
            file_obj.flush()
        except OSError:
            return struct.pack('<iI', -5, 0)
        return struct.pack('<iI', 0, length)

    def _mkdir(self, payload):
        path = self._path_arg(payload)
        full = self._resolve(path, allow_missing_last=True)
        print(f" {path!r} -> {full}", file=sys.stderr)
        if full is None:
            return struct.pack('<i', -2)
        try:
            os.mkdir(full)
        except FileExistsError:
            return struct.pack('<i', -17)
        except OSError:
            return struct.pack('<i', -13)
        return struct.pack('<i', 0)

    def command(self, cmd, payload):
        handlers = {
            CMD_OPEN: self._open,
            CMD_READ: self._read,
            CMD_CLOSE: self._close,
            CMD_STAT: self._stat,
            CMD_READDIR: self._readdir,
            CMD_CREATE: self._create,
            CMD_WRITE: self._write,
            CMD_MKDIR: self._mkdir,
        }
        handler = handlers.get(cmd)
        if handler is None:
            raise ValueError
        return handler(payload)

    def dispatch(self, conn, paused, stream=None):
        names = {1: 'OPEN', 2: 'READ', 3: 'CLOSE', 4: 'STAT', 5: 'READDIR', 6: 'CREATE', 7: 'WRITE', 8: 'MKDIR'}
        stream = stream or FrameStream()
        while True:
            frames = stream.recv_frames(conn)
            if frames is None:
                return False

            for frame_type, payload in frames:
                if paused.is_set():
                    # Fault injection deliberately drains frames without
                    # changing session state or sending a response.
                    continue

                if frame_type == TYPE_HELLO:
                    if len(payload) != 4:
                        # A malformed handshake is ignored; the next valid
                        # HELLO can still establish a session.
                        continue
                    self.reset_session()
                    conn.sendall(encode_frame(TYPE_HELLO_ACK, payload))
                    continue

                command_name = names.get(frame_type)
                if command_name is None:
                    # Unknown frame types are protocol noise, not a transport
                    # failure. FrameParser has already validated their CRC.
                    continue

                print(f"  cmd: {command_name}", end='', file=sys.stderr)
                try:
                    response = self.command(frame_type, payload)
                except (ValueError, struct.error):
                    # Bad payloads are local protocol errors. Do not tear down
                    # a healthy connection or mistake them for filesystem I/O.
                    continue

                if response is None:
                    # CLOSE is intentionally fire-and-forget.
                    continue
                conn.sendall(encode_frame(0x80 | frame_type, response))


class SerialConnection:
    """Small socket-like wrapper for a Linux UART device.

    The HostFs protocol is a byte stream, so keeping this interface to recv,
    sendall, and close lets the existing dispatcher serve either QEMU's Unix
    socket or a physical COM1 cable.
    """

    def __init__(self, device):
        self.device = device
        self.fd = os.open(device, os.O_RDWR | os.O_NOCTTY)
        self._saved = termios.tcgetattr(self.fd)
        try:
            attrs = termios.tcgetattr(self.fd)
            attrs[0] = 0  # no input translations or software flow control
            attrs[1] = 0  # no output processing
            attrs[2] = termios.CLOCAL | termios.CREAD | termios.CS8
            if hasattr(termios, 'CRTSCTS'):
                attrs[2] &= ~termios.CRTSCTS
            attrs[3] = 0  # raw mode; the protocol is binary
            attrs[4] = termios.B115200
            attrs[5] = termios.B115200
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)

        except Exception:
            termios.tcsetattr(self.fd, termios.TCSANOW, self._saved)
            os.close(self.fd)
            raise


    def recv(self, count):
        return os.read(self.fd, count)

    def sendall(self, data):
        view = memoryview(data)
        while view:
            try:
                written = os.write(self.fd, view)
            except InterruptedError:
                continue
            if written <= 0:
                raise ConnectionError("serial write made no progress")
            view = view[written:]

    def close(self):
        try:
            termios.tcsetattr(self.fd, termios.TCSANOW, self._saved)
        finally:
            os.close(self.fd)



def wait_for_handshake(conn, paused=None, stream=None):
    """Discard frames until HELLO, retaining frames read after it."""
    # Keep the small test-facing helper compatible with its original two-
    # argument form while production callers pass the pause controller.
    if isinstance(paused, FrameStream) and stream is None:
        stream = paused
        paused = threading.Event()
    paused = paused or threading.Event()
    stream = stream or FrameStream()
    while True:
        frames = stream.recv_frames(conn)
        if frames is None:
            raise ConnectionError("EOF before guest handshake")
        for index, (frame_type, payload) in enumerate(frames):
            if paused.is_set():
                continue
            if frame_type == TYPE_HELLO and len(payload) == 4:
                stream.retain(frames[index + 1:])
                return payload


def serve_connection(fs, conn, description, paused):
    print(f"hostfs: connected to {description}")
    try:
        stream = FrameStream()
        token = wait_for_handshake(conn, paused, stream)
        print("hostfs: HELLO received")
        fs.reset_session()
        conn.sendall(encode_frame(TYPE_HELLO_ACK, token))
        fs.dispatch(conn, paused, stream)
    except (ConnectionError, OSError) as e:
        print(f"hostfs: {e}")
    finally:
        conn.close()
        print("hostfs: disconnected")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Serve a directory to RetroOS HostFS")
    parser.add_argument("directory", help="directory exported to the guest")
    parser.add_argument("socket_path", nargs="?", help="QEMU Unix socket path")
    parser.add_argument("--serial", dest="serial_device", help="physical serial device")
    parser.add_argument("--pause-key", action="store_true", help="toggle response suppression with p")
    args = parser.parse_args(argv)
    if args.serial_device is not None and args.socket_path is not None:
        parser.error("socket_path cannot be combined with --serial")
    if args.socket_path is None and args.serial_device is None:
        args.socket_path = '/tmp/retroos-hostfs.sock'
    return args


def main():
    args = parse_args(sys.argv[1:])
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a directory", file=sys.stderr)
        sys.exit(1)

    paused = threading.Event()
    pause_controller = start_pause_key(paused) if args.pause_key else None
    try:
        fs = HostFs(args.directory)
        if args.serial_device is not None:
            print(f"hostfs: opening {args.serial_device} at {SERIAL_BAUD} 8N1 (serving {args.directory})")
            conn = SerialConnection(args.serial_device)
            serve_connection(fs, conn, args.serial_device, paused)
            return

        # Connect to QEMU's chardev socket (QEMU is the server). Keep retrying
        # after a guest shutdown so one persistent hostfs.py can serve reboots.
        while True:
            print(f"hostfs: connecting to {args.socket_path} (serving {args.directory})")
            while True:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    conn.connect(args.socket_path)
                    break
                except OSError:
                    conn.close()
                    time.sleep(0.5)
            serve_connection(fs, conn, 'QEMU', paused)
            time.sleep(0.1)
    finally:
        if pause_controller is not None:
            pause_controller.close()


if __name__ == '__main__':
    main()
