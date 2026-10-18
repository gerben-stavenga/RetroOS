#!/usr/bin/env python3
"""Offline bounds/format regression checks for native Wi-Fi crash capture."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location(
    'inspect_wifi_dump', Path(__file__).resolve().parents[1] / 'tools/inspect_wifi_dump.py')
dump = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dump)


def init(tail=18 << 16):
    payload = struct.pack('<II', 1, (74 << 16) | 28) + bytes(28)
    payload += struct.pack('<I', (75 << 16) | 288) + bytes(288)
    payload += struct.pack('<I', tail)
    return struct.pack('<II', (len(payload) << 16) | 0x102, 0) + payload


class InspectWifiDumpTest(unittest.TestCase):
    def test_init_distinguishes_valid_host_frame_and_modified_firmware_copy(self):
        packet = init()
        values = list(dump.init_candidates(b'prefix!!' + packet))
        self.assertEqual(values, [(8, 332, 2, [(74, 28), (75, 288), (18, 0)], None)])
        changed = list(dump.init_candidates(init(0)))[0]
        self.assertEqual(changed[3][-1], (0, 0))
        self.assertEqual(changed[4], 'unexpected INIT TLV sequence')

    def test_init_scan_bounds_corrupt_payloads_and_false_markers(self):
        packet = init()
        self.assertEqual(list(dump.init_candidates(packet[:-1]))[0][4], 'truncated HTC payload')
        self.assertEqual(list(dump.init_candidates(init((18 << 16) | 4)))[0][4],
                         'TLV exceeds HTC payload')
        self.assertEqual(list(dump.init_candidates(packet[8:])), [])
        for header in [0, (332 << 16), (332 << 16) | 16, (65535 << 16) | 2]:
            malformed = struct.pack('<I', header) + packet[4:]
            self.assertEqual(list(dump.init_candidates(malformed)), [])

    def test_paging_and_ce_trailer_preserves_bytes_and_validates_region_lengths(self):
        raw = struct.pack('<II', 1, 8)
        packet = init()
        table = b'RTWFPAGE' + struct.pack('<II', 1, 2)
        table += struct.pack('<IIQ', 1, 3, 0x5800000)
        table += struct.pack('<IIQ', 0x100, len(packet), 0x6a00000)
        blob = raw + table + b'abc' + packet + b'RTWFEND1' + struct.pack('<Q', len(raw))
        values = dump.sections(blob)
        self.assertEqual(values[0][0:3], ('HOST-1-0', 0, 0x5800000))
        self.assertEqual(values[0][4], b'abc')
        self.assertEqual(values[1][0:3], ('CE-DMA-1', 0, 0x6a00000))
        self.assertEqual(values[1][4], packet)
        for length in [0, len(packet) - 1, len(packet) + 1, 0xffffffff]:
            corrupt = bytearray(blob)
            struct.pack_into('<I', corrupt, 44, length)
            with self.assertRaises(ValueError):
                dump.sections(corrupt)


if __name__ == '__main__':
    unittest.main()
