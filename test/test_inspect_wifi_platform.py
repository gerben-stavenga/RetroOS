#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location(
    'inspect_wifi_platform', Path(__file__).resolve().parents[1] / 'tools/inspect_wifi_platform.py')
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


def record(kind=248, enabled=1, name=b'BDF_QC_5mm', handle=1):
    return struct.pack('<BBHBBHB', kind, 9, handle, 0, 0, 0, enabled) + name + b'\0\0'


class InspectWifiPlatformTest(unittest.TestCase):
    def test_selects_first_valid_variant_and_skips_unrelated_strings(self):
        data = record(kind=1, name=b'private system serial')
        data += record(enabled=0) + record(name=b'other') + record()
        data += record(name=b'BDF_later') + record(kind=127)
        rows, selected = platform.inspect(data)
        self.assertEqual(selected, 'QC_5mm')
        self.assertEqual(len(rows), 4)
        self.assertNotIn('private system serial', str(rows))
        self.assertEqual(rows[0]['status'], 'ignored: BDF extension disabled')

    def test_rejects_invalid_lengths_magic_and_nonprintable_variants(self):
        for name in [b'BDF_', b'BDF_' + b'x' * 32, b'BDF_\xff', b'BDF_\x1btest', b'wrong']:
            self.assertIsNone(platform.inspect(record(name=name))[1])
        short = struct.pack('<BBH', 248, 4, 1) + b'BDF_QC_5mm\0\0'
        self.assertIsNone(platform.inspect(short)[1])
        self.assertEqual(platform.inspect(record(name=b'BDF_' + b'x' * 31))[1], 'x' * 31)

    def test_bounds_malformed_tables_and_honors_end_marker(self):
        for data in [b'\0', b'\0\x03\0\0\0\0', b'\xf8\x09\0\0', record()[:-1]]:
            with self.assertRaises(ValueError):
                platform.inspect(data)
        with self.assertRaises(ValueError):
            platform.inspect(bytes(1024 * 1024 + 1))
        self.assertEqual(platform.inspect(record(kind=127) + b'invalid tail'), ([], None))
        self.assertEqual(platform.inspect(b''), ([], None))


if __name__ == '__main__':
    unittest.main()
