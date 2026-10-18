import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    'inspect_linux_wifi_trace', Path(__file__).resolve().parents[1] / 'tools/inspect_linux_wifi_trace.py')
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


def qmi(message, body=b''):
    return struct.pack('<BHHH', 0, 12, message, len(body)) + body


def event(kind, data, message=0x23):
    fields = f'length={len(data)}'
    if kind == 'qmi_wire':
        fields += f' message={message} iov_length={len(data)}'
    return f'task-1 [000] 1.0: {kind}: (function) {fields} packet={data.hex()}\n'


class PacketTests(unittest.TestCase):
    def test_qmi_config_decodes_table_and_rejects_truncation(self):
        table = b'\x01' + struct.pack('<5I', 3, 2, 32, 2048, 0)
        body = struct.pack('<BH', 0x11, len(table)) + table
        message, txn, fields = decoder.qmi_packet(qmi(0x23, body))
        self.assertEqual((message, txn), (0x23, 12))
        self.assertIn('0x3,0x2,0x20,0x800,0x0', '\n'.join(decoder.qmi_details(message, fields)))
        with self.assertRaises(ValueError):
            decoder.qmi_packet(qmi(0x23, body)[:-1])
        with self.assertRaises(ValueError):
            decoder.qmi_packet(qmi(0x23, b'\x11\xff\x00'))

    def test_fixed_fetch_padding_is_removed_before_persistence(self):
        packet = qmi(0x24)
        # Padding resembles unrelated adjacent memory, not packet bytes.
        raw = packet + b'private-padding' + bytes(1024 - len(packet) - 15)
        words = struct.unpack('<128Q', raw)
        arrays = ' '.join(f'data{i}={{' + ','.join(hex(w) for w in words[i*64:(i+1)*64]) + '}' for i in range(2))
        line = f'qmi_wire: length=7 iov_length=7 message=36 {arrays}\n'
        sanitized = decoder.sanitize_line(line)
        self.assertEqual(decoder.packet_bytes(sanitized), packet)
        self.assertNotIn('data0=', sanitized)
        self.assertNotIn(b'private-padding'.hex(), sanitized)

    def test_incomplete_fetch_and_wrong_iovec_are_explicit(self):
        bad = 'qmi_wire: length=20 iov_length=20 message=35 data0={0x0}\n'
        self.assertIn('packet_error=incomplete packet', decoder.sanitize_line(bad))
        with self.assertRaises(ValueError):
            decoder.packet_bytes(event('qmi_wire', qmi(0x24)).replace('iov_length=7', 'iov_length=8'))

    def test_htc_receive_removes_header_and_credit_trailer(self):
        payload = struct.pack('<3I', 0x1000003, (2048 << 16) | (2 << 8), 0)
        trailer = b'\x01\x04\x00\x00\x02\x01\x00\x00'
        packet = struct.pack('<II', ((len(payload)+len(trailer)) << 16) | 0x200, len(trailer)) + payload + trailer
        decoded = decoder.htc_payload(packet, True)
        self.assertEqual(decoded, payload)
        kind, details = decoder.htc_details(decoded)
        self.assertEqual(kind, 3)
        self.assertIn('endpoint=2 max_message=2048', details)

    def test_decode_reports_missing_packets_in_old_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trace = root / 'trace.txt'
            trace.write_text(event('qmi_wire', qmi(0x23, b'\x10\x03\x00WIN')))
            with contextlib.redirect_stdout(io.StringIO()):
                decoder.decode(trace, root / 'packets')
            report = (root / 'packets/decoded.txt').read_text()
            self.assertIn('compatibility=', report)
            self.assertIn('INCOMPLETE: missing htc_tx message 2', report)
            self.assertEqual((root / 'packets/001-qmi-0023.bin').read_bytes(), qmi(0x23, b'\x10\x03\x00WIN'))

    def test_complete_startup_exports_packets_and_passes_completeness_checks(self):
        rows = [event('qmi_wire', qmi(message), message)
                for message in (0x20, 0x34, 0x36, 0x24, 0x23, 0x22, 0x3c)]
        rows += [event('htc_tx', struct.pack('<2I', 0x1000002, 0x200)),
                 event('htc_tx', struct.pack('<3I', 5, 0, 0))]
        for payload in (struct.pack('<2I', 1 | (10 << 16), 2176 | (9 << 16)),
                        struct.pack('<3I', 0x1000003, (2048 << 16) | (2 << 8), 0)):
            rows.append(event('htc_rx', struct.pack('<II', len(payload) << 16, 0) + payload))
        words = [0x4a001c] + [0]*7 + [0x4b0120] + [0]*72 + [0x120000]
        rows += ['wmi_init: length=328 words0={' + ','.join(hex(v) for v in words[:64])
                 + '} words1={' + ','.join(hex(v) for v in words[64:]) + '}\n',
                 'ready: result=0\n']
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trace = root / 'trace.txt'
            trace.write_text(''.join(rows))
            with contextlib.redirect_stdout(io.StringIO()):
                decoder.decode(trace, root / 'packets')
            report = (root / 'packets/decoded.txt').read_text()
            self.assertNotIn('INCOMPLETE', report)
            self.assertIn('Decoded packets: 11', report)
            self.assertEqual((root / 'packets/wmi-init.bin').stat().st_size, 328)


if __name__ == '__main__':
    unittest.main()
