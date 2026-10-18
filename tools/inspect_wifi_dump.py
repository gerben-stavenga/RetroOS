#!/usr/bin/env python3
"""Inspect raw Qualcomm RDDM sections and RetroOS host-paging trailers offline."""
import argparse
from pathlib import Path
import re
import struct


def sections(data):
    if len(data) < 8:
        raise ValueError('truncated RDDM header')
    version, header_bytes = struct.unpack_from('<II', data)
    if version != 1 or not 8 <= header_bytes <= len(data) or (header_bytes - 8) % 64:
        raise ValueError('invalid RDDM section table')
    paging = None
    rddm_end = len(data)
    if data[-16:-8] == b'RTWFEND1':
        paging, = struct.unpack_from('<Q', data, len(data) - 8)
        if not header_bytes <= paging <= len(data) - 32:
            raise ValueError('invalid paging footer offset')
        rddm_end = paging
    cursor = header_bytes
    result = []
    for offset in range(8, header_bytes, 64):
        address, physical, length, name, _ = struct.unpack_from('<QQQ20s20s', data, offset)
        if length > rddm_end - cursor:
            raise ValueError('truncated RDDM section')
        name = name.split(b'\0', 1)[0].decode('ascii', errors='replace')
        result.append((name, address, physical, cursor, data[cursor:cursor + length]))
        cursor += length
    if paging is not None:
        magic, version, count = struct.unpack_from('<8sII', data, paging)
        if magic != b'RTWFPAGE' or version != 1 or count > 64:
            raise ValueError('invalid host paging table')
        table = paging + 16
        cursor = table + count * 16
        end = len(data) - 16
        if cursor > end:
            raise ValueError('truncated host paging table')
        for index in range(count):
            kind, length, physical = struct.unpack_from('<IIQ', data, table + index * 16)
            if length == 0 or length > end - cursor:
                raise ValueError('truncated host paging region')
            name = f'CE-DMA-{index}' if kind == 0x100 else f'HOST-{kind}-{index}'
            result.append((name, 0, physical, cursor, data[cursor:cursor + length]))
            cursor += length
        if cursor != end:
            raise ValueError('unexpected bytes after host paging regions')
    return result


def init_candidates(data):
    """Find bounded HTC/WMI INIT copies, not necessarily unmodified packets.

    Firmware SRAM may contain translated/partially consumed copies. A host
    CE buffer provides stronger evidence of what was supplied to DMA.
    """
    marker = struct.pack('<II', 1, (74 << 16) | 28)
    cursor = 0
    while True:
        at = data.find(marker, cursor)
        if at < 0:
            return
        cursor = at + len(marker)
        if at < 8:
            continue
        header, _ = struct.unpack_from('<II', data, at - 8)
        size = header >> 16
        endpoint = header & 255
        if not 1 <= endpoint < 16 or header & 0xf000 or not 36 <= size <= 2040:
            continue
        end = at + size
        tags, error = [], None
        if end > len(data):
            error = 'truncated HTC payload'
        else:
            pos = at + 4  # WMI command header
            while pos < end:
                if end - pos < 4:
                    error = 'truncated TLV header'
                    break
                field, = struct.unpack_from('<I', data, pos)
                tag, length = field >> 16, field & 65535
                tags.append((tag, length))
                pos += 4
                if length > end - pos:
                    error = 'TLV exceeds HTC payload'
                    break
                pos += length
        if error is None and (len(tags) != 3 or tags[0] != (74, 28)
                              or tags[1][0] != 75 or tags[2] != (18, 0)):
            error = 'unexpected INIT TLV sequence'
        yield at - 8, size, endpoint, tags, error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dump', type=Path)
    parser.add_argument('--find', help='show printable strings containing this text')
    parser.add_argument('--limit', type=int, default=30)
    parser.add_argument('--wmi-init', action='store_true',
                        help='inspect candidate HTC/WMI INIT copies; firmware may modify SRAM copies')
    args = parser.parse_args()
    try:
        entries = sections(args.dump.read_bytes())
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'{error}\n')
    for name, address, physical, offset, contents in entries:
        print(f'{name}: file=0x{offset:x} bytes=0x{len(contents):x} '
              f'address=0x{address:x} physical=0x{physical:x}')
        if name == 'Q6-SFR':
            print('  Failure:', contents.split(b'\0', 1)[0].decode('ascii', errors='replace'))
        if args.wmi_init:
            for index, (at, size, endpoint, tags, error) in enumerate(init_candidates(contents)):
                if index >= args.limit:
                    break
                fields = ', '.join(f'{tag}:{length}' for tag, length in tags)
                print(f'  INIT copy +0x{at:x}: endpoint={endpoint} payload={size} '
                      f'TLVs=[{fields}] {error or "expected INIT TLV sequence"}')
        if args.find:
            count = 0
            for match in re.finditer(rb'[\x20-\x7e]{6,}', contents):
                text = match.group().decode('ascii')
                if args.find.lower() in text.lower():
                    print(f'  +0x{match.start():x}: {text[:300]}')
                    count += 1
                    if count >= args.limit:
                        break


if __name__ == '__main__':
    main()
