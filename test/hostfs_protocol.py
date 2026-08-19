#!/usr/bin/env python3
"""Focused tests for the framed hostfs wire protocol."""

from pathlib import Path
import os
import pty
import struct
import sys
import tempfile
import termios
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hostfs import (  # noqa: E402
    ESC,
    FLAG,
    MAX_BODY,
    MAX_READ_DATA,
    ERR_OVERFLOW,
    FrameParser,
    FrameStream,
    TYPE_HELLO,
    encode_frame,
    wait_for_handshake,
    HostFs,
    PauseController,
)


class HostFsProtocolTest(unittest.TestCase):
    def test_pause_key_restores_terminal_after_shutdown(self):
        master, slave = pty.openpty()
        stream = os.fdopen(slave, 'r', closefd=False)
        saved = termios.tcgetattr(slave)
        paused = threading.Event()
        try:
            with mock.patch.object(sys, 'stdin', stream):
                controller = PauseController(paused)
                deadline = time.monotonic() + 1.0
                while termios.tcgetattr(slave) == saved and time.monotonic() < deadline:
                    time.sleep(0.01)
                controller.close()
            self.assertEqual(termios.tcgetattr(slave), saved)
        finally:
            stream.close()
            os.close(master)

    def test_escaping_round_trip(self):
        payload = bytes((0x00, FLAG, ESC, 0xff))
        parser = FrameParser()
        self.assertEqual(parser.feed(encode_frame(0x47, payload)), [(0x47, payload)])

    def test_bad_crc_and_partial_frame_recover_at_hello(self):
        bad = bytearray(encode_frame(0x47, b"interrupted"))
        bad[-3] ^= 1
        hello = encode_frame(TYPE_HELLO, struct.pack('<I', 0x12345678))
        parser = FrameParser()
        # The second frame's opening flag closes/discards the interrupted one.
        self.assertEqual(parser.feed(bytes(bad[:-2]) + hello[:1]), [])
        self.assertEqual(
            parser.feed(hello[1:]),
            [(TYPE_HELLO, struct.pack('<I', 0x12345678))],
        )

    def test_oversized_body_is_bounded_and_next_frame_survives(self):
        parser = FrameParser()
        oversized = bytes((FLAG,)) + b'x' * (MAX_BODY + 100) + bytes((FLAG,))
        result = parser.feed(oversized + encode_frame(0x44, b'ok'))
        self.assertEqual(result, [(0x44, b'ok')])
        self.assertLessEqual(len(parser.body), MAX_BODY)

    def test_path_containment_rejects_parent_and_sibling_prefixes(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "export"
            sibling = Path(parent) / "export-other"
            root.mkdir()
            sibling.mkdir()
            fs = HostFs(root)
            self.assertIsNone(fs._resolve(b"../export-other/file"))
            self.assertIsNone(fs._resolve(b"../export-other"))

    def test_path_containment_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "export"
            outside = Path(parent) / "outside"
            root.mkdir()
            outside.mkdir()
            link = root / "link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            fs = HostFs(root)
            self.assertIsNone(fs._resolve(b"link/secret.txt", allow_missing_last=True))

    def test_read_response_boundary_is_enforced(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            data = b'x' * MAX_READ_DATA
            (root / 'data').write_bytes(data)
            fs = HostFs(root)
            path = b'data'
            opened = fs._open(struct.pack('<H', len(path)) + path)
            status, handle, size = struct.unpack('<iII', opened)
            self.assertEqual((status, size), (0, MAX_READ_DATA))

            response = fs._read(struct.pack('<III', handle, 0, MAX_READ_DATA))
            self.assertEqual(struct.unpack('<iI', response[:8]), (MAX_READ_DATA, MAX_READ_DATA))
            self.assertEqual(response[8:], data)

            oversized = fs._read(struct.pack('<III', handle, 0, MAX_READ_DATA + 1))
            self.assertEqual(struct.unpack('<iI', oversized), (ERR_OVERFLOW, 0))
            huge = fs._read(struct.pack('<III', handle, 0, 0xffffffff))
            self.assertEqual(struct.unpack('<iI', huge), (ERR_OVERFLOW, 0))
            follow_up = fs._read(struct.pack('<III', handle, 0, 1))
            self.assertEqual(struct.unpack('<iI', follow_up[:8]), (1, 1))
            self.assertEqual(follow_up[8:], b'x')
            fs.reset_session()

    def test_oversized_metadata_returns_protocol_error(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            huge = root / 'huge'
            try:
                with huge.open('wb') as file_obj:
                    file_obj.truncate(0xffffffff)
            except (OSError, ValueError) as error:
                self.skipTest(f'sparse files around u32 are unavailable: {error}')
            fs = HostFs(root)
            path = b'huge'
            encoded_path = struct.pack('<H', len(path)) + path
            exact = fs._open(encoded_path)
            self.assertEqual(struct.unpack('<iII', exact)[:1], (0,))
            self.assertEqual(struct.unpack('<iII', exact)[2], 0xffffffff)
            fs.reset_session()
            try:
                with huge.open('r+b') as file_obj:
                    file_obj.truncate(0xffffffff + 1)
            except (OSError, ValueError) as error:
                self.skipTest(f'sparse files above u32 are unavailable: {error}')
            fs = HostFs(root)

            class NoRead:
                def seek(self, _offset):
                    raise AssertionError('oversized READ attempted a file operation')

                def read(self, _length):
                    raise AssertionError('oversized READ attempted a file operation')

            fs.handles[1] = NoRead()
            oversized = fs._read(struct.pack('<III', 1, 0, 0xffffffff))
            self.assertEqual(struct.unpack('<iI', oversized), (ERR_OVERFLOW, 0))

            opened = fs._open(encoded_path)
            self.assertEqual(struct.unpack('<iII', opened), (ERR_OVERFLOW, 0, 0))
            stat_reply = fs._stat(encoded_path)
            self.assertEqual(struct.unpack('<iIB', stat_reply), (ERR_OVERFLOW, 0, 0))
            readdir_reply = fs._readdir(struct.pack('<H', 0) + struct.pack('<I', 0))
            self.assertEqual(struct.unpack('<iB', readdir_reply), (ERR_OVERFLOW, 0))

    def test_missing_stat_and_readdir_return_errors(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            (root / "gone").mkdir()
            fs = HostFs(root)
            (root / "gone").rmdir()
            path = b"gone"
            stat_reply = fs._stat(struct.pack("<H", len(path)) + path)
            self.assertEqual(struct.unpack("<iIB", stat_reply), (-2, 0, 0))
            readdir_reply = fs._readdir(struct.pack("<H", len(path)) + path + struct.pack("<I", 0))
            self.assertEqual(struct.unpack("<i", readdir_reply[:4])[0], -2)

    def test_handshake_preserves_request_in_same_socket_chunk(self):
        token = struct.pack('<I', 0x12345678)
        request = encode_frame(0x01, b'open-payload')

        class OneChunk:
            def __init__(self, data):
                self.data = data

            def recv(self, _size):
                data, self.data = self.data, b''
                return data

        stream = FrameStream()
        conn = OneChunk(encode_frame(TYPE_HELLO, token) + request)
        self.assertEqual(wait_for_handshake(conn, stream), token)
        self.assertEqual(stream.recv_frames(conn), [(0x01, b'open-payload')])


if __name__ == '__main__':
    unittest.main()
