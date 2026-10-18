#!/usr/bin/env python3
"""Read Qualcomm Wi-Fi calibration metadata from Linux's SMBIOS table.

Only type 248 metadata is printed; other SMBIOS records are skipped.
This does not change the Wi-Fi device or platform configuration.
Field layout follows Linux v7.0 ath12k core.h/core.c (type 0xf8, length 9).
"""
import argparse
from pathlib import Path
import struct


def records(data):
    if len(data) > 1024 * 1024:
        raise ValueError('SMBIOS table exceeds 1 MiB limit')
    at = 0
    count = 0
    while at < len(data):
        if len(data) - at < 4:
            raise ValueError('truncated SMBIOS header')
        kind, length, handle = struct.unpack_from('<BBH', data, at)
        if length < 4 or length > len(data) - at:
            raise ValueError('invalid SMBIOS formatted length')
        end = data.find(b'\0\0', at + length)
        if end < 0:
            raise ValueError('unterminated SMBIOS string set')
        yield kind, handle, data[at:at + length], data[at + length:end]
        at = end + 2
        count += 1
        if kind == 127:
            return
        if count >= 4096:
            raise ValueError('too many SMBIOS records')


def inspect(data):
    result = []
    selected = None
    for kind, handle, fixed, strings in records(data):
        if kind != 248:
            continue
        row = {'handle': handle, 'length': len(fixed)}
        if len(fixed) != 9:
            row['status'] = 'ignored: formatted length must be 9'
        elif not fixed[8]:
            row['status'] = 'ignored: BDF extension disabled'
        else:
            # ath12k uses the first string, immediately after the fixed part.
            name = strings.split(b'\0', 1)[0]
            if not name.startswith(b'BDF_'):
                row['status'] = 'ignored: missing BDF_ prefix'
            elif not name[4:] or len(name[4:]) >= 32:
                row['status'] = 'ignored: variant length must be 1..31'
            elif any(value < 32 or value > 126 for value in name):
                row['status'] = 'ignored: non-printable variant'
            else:
                row['variant'] = name[4:].decode('ascii')
                row['status'] = 'valid'
                if selected is None:
                    selected = row['variant']
        result.append(row)
    return result, selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--table', type=Path, default=Path('/sys/firmware/dmi/tables/DMI'))
    args = parser.parse_args()
    try:
        with args.table.open('rb') as stream:
            data = stream.read(1024 * 1024 + 1)
        rows, selected = inspect(data)
    except PermissionError:
        parser.exit(1, 'Linux restricts the SMBIOS table to root; run this read-only tool with sudo.\n')
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')
    for row in rows:
        print(f'SMBIOS type=248 handle=0x{row["handle"]:04x} length={row["length"]} '
              f'{row["status"]}' + (f' variant={row["variant"]}' if 'variant' in row else ''))
    if not rows:
        print('No Qualcomm SMBIOS type 248 record found.')
    print(f'Calibration variant: {selected if selected is not None else "none (default board lookup)"}')


if __name__ == '__main__':
    main()
