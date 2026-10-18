#!/usr/bin/env python3
"""Recover rejected WMI packets from a RetroOS boot log for offline diagnosis."""
import argparse
from pathlib import Path
import re
import struct


def events_from_log(text):
    pending = None
    for line in text.splitlines():
        header = re.search(r'WiFi: rejected WMI bytes=(\d+) captured=(\d+)', line)
        if header:
            if pending is not None:
                raise ValueError('incomplete WMI packet before next header')
            length, captured = map(int, header.groups())
            if not 4 <= captured <= 2048 or captured != length:
                raise ValueError(f'incomplete or invalid capture: {captured} of {length} bytes')
            pending = (length, bytearray())
            continue
        row = re.search(r'WiFi: rejected WMI \+([0-9a-fA-F]+):\s*' + r'\s+'.join([r'([0-9a-fA-F]{8})'] * 4), line)
        if row:
            if pending is None:
                raise ValueError('packet data without a capture header')
            length, data = pending
            if int(row[1], 16) != len(data):
                raise ValueError('missing or out-of-order WMI packet words')
            data.extend(struct.pack('<4I', *(int(value, 16) for value in row.groups()[1:])))
            if len(data) >= length:
                yield bytes(data[:length])
                pending = None
    if pending is not None:
        raise ValueError('truncated WMI packet in log')


def tlvs(data):
    result = []
    while data:
        if len(data) < 4:
            raise ValueError('truncated TLV header')
        header, = struct.unpack_from('<I', data)
        size, tag = header & 65535, header >> 16
        if size > len(data) - 4:
            raise ValueError(f'tag {tag}: truncated TLV body')
        result.append((tag, data[4:4 + size]))
        data = data[4 + size:]
    return result


def describe(packet):
    event, = struct.unpack_from('<I', packet)
    rows = [f'WMI event={event & 0xffffff:#x} bytes={len(packet)}']
    arrays = 0
    for tag, body in tlvs(packet[4:]):
        rows.append(f'TLV tag={tag} bytes={len(body)}')
        if tag == 938 and len(body) >= 312:
            words = struct.unpack_from('<78I', body)
            rows.append(f'  status={words[0]} PHY={words[1]} PHYs={words[3]} country={body[8:10]!r}')
            fields = [12, 13, 64, 63, 65, 70, 71, 66, 67, 74, 75]
            rows.append('  rule counts (2G,5G,LPI/SP/VLP AP,then clients): ' + ','.join(str(words[i]) for i in fields))
            rows.append('  fixed DWORDs: ' + ','.join(f'{value:#x}' for value in words))
        if tag == 18:
            arrays += 1
            rows.append(f'  array #{arrays} raw={body.hex()}')
            try:
                for child, value in tlvs(body):
                    rows.append(f'    child tag={child} bytes={len(value)} data={value.hex()}')
                    if child in (608, 937) and len(value) >= 16:
                        freq, bw, flags, psd = struct.unpack_from('<4I', value)
                        rows.append(f'      freq={freq & 65535}..{freq >> 16} bw={bw & 65535} flags={flags:#x} psd={psd:#x}')
            except ValueError as error:
                rows.append(f'    nested TLV parse failed: {error}')
    return '\n'.join(rows) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        packets = list(events_from_log(args.log.read_text(errors='replace')))
        if not packets:
            raise ValueError('no rejected WMI packet capture in this log')
        reports = [describe(packet) for packet in packets]
        args.output.mkdir(parents=True, exist_ok=False)
        for index, (packet, report) in enumerate(zip(packets, reports), 1):
            (args.output / f'event-{index:03d}.bin').write_bytes(packet)
            (args.output / f'event-{index:03d}.txt').write_text(report)
            print(report, end='')
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
