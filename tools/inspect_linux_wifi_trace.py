#!/usr/bin/env python3
"""Decode bounded Linux startup packets; no root or hardware access required."""
import argparse
from pathlib import Path
import re
import struct


QMI_NAMES = {0x20: 'indication-register', 0x22: 'wlan-mode', 0x23: 'wlan-config',
             0x24: 'target-capabilities', 0x2f: 'wlan-ini', 0x34: 'host-capabilities',
             0x36: 'memory-response', 0x3c: 'm3-info', 0x57: 'phy-capabilities'}


def number(line, field):
    match = re.search(rf'\b{field}=(0x[0-9a-fA-F]+|[0-9]+)\b', line)
    if not match:
        raise ValueError(f'missing {field}')
    return int(match[1], 0)


def array_bytes(line, prefix, width):
    parts = re.findall(rf'\b{prefix}(\d+)=\{{([^}}]*)\}}', line)
    if not parts or [int(index) for index, _ in parts] != list(range(len(parts))):
        raise ValueError(f'missing or out-of-order {prefix} arrays')
    data = bytearray()
    for _, body in parts:
        for value in body.split(','):
            data.extend(int(value.strip(), 0).to_bytes(width, 'little'))
    return bytes(data)


def packet_bytes(line):
    length = number(line, 'length')
    limit = 1024 if 'qmi_wire:' in line else 64
    if not 0 < length <= limit:
        raise ValueError(f'invalid packet length {length}')
    if 'qmi_wire:' in line and number(line, 'iov_length') != length:
        raise ValueError('QMI iovec length differs from send length')
    match = re.search(r'\bpacket=([0-9a-f]+)\b', line)
    data = bytes.fromhex(match[1]) if match else array_bytes(line, 'data', 8)
    if len(data) < length:
        raise ValueError(f'incomplete packet: {len(data)} of {length} bytes')
    return data[:length]


def sanitize_line(line):
    """Discard fixed-fetch padding before saving: it is not packet content."""
    if not any(event + ':' in line for event in ('qmi_wire', 'htc_tx', 'htc_rx')):
        return line
    prefix = re.split(r'\s+(?:data0|packet|packet_error)=', line, maxsplit=1)[0]
    try:
        return prefix + ' packet=' + packet_bytes(line).hex() + '\n'
    except (ValueError, OverflowError) as error:
        return prefix + ' packet_error=' + str(error) + '\n'


def qmi_packet(data):
    if len(data) < 7:
        raise ValueError('truncated QMI header')
    kind, transaction, message, length = struct.unpack_from('<BHHH', data)
    if kind != 0 or length != len(data) - 7:
        raise ValueError('QMI request header/encoded length mismatch')
    fields = []
    at = 7
    while at < len(data):
        if at + 3 > len(data):
            raise ValueError('truncated QMI TLV header')
        tag, size = struct.unpack_from('<BH', data, at)
        at += 3
        if size > len(data) - at:
            raise ValueError('truncated QMI TLV body')
        fields.append((tag, data[at:at + size]))
        at += size
    return message, transaction, fields


def qmi_details(message, fields):
    rows = []
    for tag, value in fields:
        rows.append(f'  TLV {tag:#04x}, {len(value)} bytes: {value.hex()}')
        if message != 0x23:
            continue
        if tag == 0x10:
            rows.append('    compatibility=' + repr(value.decode('ascii', errors='replace')))
        elif tag in (0x11, 0x12):
            words = 5 if tag == 0x11 else 3
            if not value or len(value) != 1 + value[0] * words * 4:
                raise ValueError('invalid WLAN config table length')
            label = 'CE pipe (id,direction,entries,bytes,flags)' if tag == 0x11 else 'service (id,direction,pipe)'
            for at in range(1, len(value), words * 4):
                entry = struct.unpack_from('<' + 'I' * words, value, at)
                rows.append(f'    {label}: ' + ','.join(hex(word) for word in entry))
    return rows


def htc_payload(data, receive):
    if not receive:
        return data
    if len(data) < 8:
        raise ValueError('truncated HTC header')
    first, second = struct.unpack_from('<II', data)
    size = first >> 16
    if first & 255 or size > len(data) - 8:
        raise ValueError('invalid HTC control frame')
    # The HTC header length includes any trailer. Remove it for message decode.
    trailer = second & 255 if first & 0x200 else 0
    if trailer > size:
        raise ValueError('HTC trailer exceeds payload')
    return data[8:8 + size - trailer]


def htc_details(payload):
    if len(payload) < 8 or len(payload) % 4:
        raise ValueError('invalid HTC message size')
    words = struct.unpack('<' + 'I' * (len(payload) // 4), payload)
    kind, service = words[0] & 65535, words[0] >> 16
    text = f'HTC message={kind} service={service:#x} words=' + ','.join(hex(word) for word in words)
    if kind == 1:
        text += f' credits={service} credit_size={words[1] & 65535} endpoints={(words[1] >> 16) & 255}'
    elif kind == 2:
        text += f' connection_flags={words[1] & 65535:#x}'
    elif kind == 3:
        text += f' status={words[1] & 255} endpoint={(words[1] >> 8) & 255} max_message={words[1] >> 16}'
    return kind, text


def decode(trace, output):
    output.mkdir(parents=True, exist_ok=False)
    rows, problems, messages, htc = [], [], set(), set()
    count = 0
    ready = False
    init = False
    for line_number, line in enumerate(trace.read_text().splitlines(), 1):
        if 'ready:' in line and 'result=0' in line:
            ready = True
        if 'wmi_init:' in line:
            try:
                packet = array_bytes(line, 'words', 4)
                if len(packet) != 328 or number(line, 'length') != 328:
                    raise ValueError('invalid WMI INIT length')
                (output / 'wmi-init.bin').write_bytes(packet)
                init = True
            except (ValueError, OverflowError) as error:
                problems.append(f'line {line_number}: {error}')
        event = next((name for name in ('qmi_wire', 'htc_tx', 'htc_rx') if name + ':' in line), None)
        if event is None:
            continue
        try:
            packet = packet_bytes(line)
            if event == 'qmi_wire':
                message, transaction, fields = qmi_packet(packet)
                if message != number(line, 'message'):
                    raise ValueError('QMI event message ID differs from packet header')
                messages.add(message)
                name = f'{count + 1:03d}-qmi-{message:04x}.bin'
                rows.append(f'{name}: {QMI_NAMES.get(message, "unknown")} transaction={transaction} wire_bytes={len(packet)}')
                rows.extend(qmi_details(message, fields))
            else:
                payload = htc_payload(packet, event == 'htc_rx')
                kind, text = htc_details(payload)
                htc.add((event, kind))
                name = f'{count + 1:03d}-{event}-{kind}.bin'
                rows.append(f'{name}: {text}')
                (output / name.replace('.bin', '-payload.bin')).write_bytes(payload)
            (output / name).write_bytes(packet)
            count += 1
        except (ValueError, OverflowError) as error:
            problems.append(f'line {line_number}: {error}')
    missing = {0x20, 0x34, 0x36, 0x24, 0x23, 0x22, 0x3c} - messages
    if missing:
        problems.append('missing QMI requests: ' + ', '.join(hex(value) for value in sorted(missing)))
    for expected in [('htc_tx', 2), ('htc_tx', 5), ('htc_rx', 1), ('htc_rx', 3)]:
        if expected not in htc:
            problems.append(f'missing {expected[0]} message {expected[1]}')
    if not ready:
        problems.append('missing successful firmware ready result')
    if not init:
        problems.append('missing complete WMI INIT')
    summary = [f'Decoded packets: {count}', f'Firmware ready: {ready}', f'WMI INIT: {init}']
    summary.extend('INCOMPLETE: ' + problem for problem in problems)
    if not problems:
        summary.append('Required startup packets present; also check buffer-stats.txt for dropped events.')
    (output / 'decoded.txt').write_text('\n'.join([*summary, '', *rows]) + '\n')
    print('\n'.join(summary))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        decode(args.trace, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
