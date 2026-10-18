import importlib.util
from pathlib import Path
import struct
import unittest


spec = importlib.util.spec_from_file_location(
    'inspect_wifi_event', Path(__file__).resolve().parents[1] / 'tools/inspect_wifi_event.py')
event = importlib.util.module_from_spec(spec)
spec.loader.exec_module(event)


def log(packet):
    rows = [f'WiFi: rejected WMI bytes={len(packet)} captured={len(packet)}']
    for offset in range(0, len(packet), 16):
        words = struct.unpack('<4I', packet[offset:offset+16].ljust(16, b'\0'))
        rows.append(f'WiFi: rejected WMI +{offset:04x}: ' + ' '.join(f'{word:08x}' for word in words))
    return '\n'.join(rows)


class EventTests(unittest.TestCase):
    def test_exact_packet_recovery_including_partial_last_word_and_multiple_events(self):
        first = struct.pack('<I', 0x3a003) + b'odd sized data'
        second = struct.pack('<I', 2) + bytes(range(40))
        self.assertEqual(list(event.events_from_log(log(first)+'\nordinary log\n'+log(second))), [first, second])

    def test_truncated_reordered_and_bounded_captures_are_rejected(self):
        good = log(bytes(range(37)))
        for bad in [good.rsplit('\n',1)[0], good.replace('+0010:', '+0020:'),
                    good.replace('captured=37','captured=20'),
                    'WiFi: rejected WMI bytes=4096 captured=2048',
                    good + '\n' + good.splitlines()[-1],
                    good.rsplit('\n',1)[0] + '\n' + good]:
            with self.assertRaises(ValueError):
                list(event.events_from_log(bad))

    def test_report_locates_invalid_nested_arrays_without_discarding_packet(self):
        fixed = bytearray(312)
        struct.pack_into('<4I', fixed, 0, 0, 0, 0x3030, 2)
        packet = struct.pack('<II', 0x3a003, (938<<16)|312) + fixed
        packet += struct.pack('<I', (18<<16)|3) + b'abc'
        report = event.describe(packet)
        self.assertIn("country=b'00'",report)
        self.assertIn('array #1 raw=616263',report)
        self.assertIn('nested TLV parse failed',report)


if __name__ == '__main__':
    unittest.main()
