#!/usr/bin/env python3
"""Print every syscall's handler time from a `profile syscalls` JSON reply.

Also accepts a collected report containing a `profile syscalls` reply.
Blocked waiting, deferred lifecycle work, architecture transitions and the
outer event loop are outside the measured handler interval.
"""
import argparse
import csv
import json
from pathlib import Path
import re
import sys


def syscall_names(abi):
    for directory in ('/usr/include/x86_64-linux-gnu/asm', '/usr/include/asm'):
        header = Path(directory) / f'unistd_{abi}.h'
        if header.exists():
            return {int(number): name for name, number in re.findall(
                r'^#define __NR_(\w+)\s+(\d+)\s*$', header.read_text(), re.MULTILINE)}
    return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', type=Path)
    parser.add_argument('--csv', type=Path, help='Also save all rows as CSV')
    args = parser.parse_args()
    report = json.loads(args.profile.read_text())
    profile = report.get('profile syscalls', report)
    if not profile.get('ok'):
        parser.error('profile syscalls did not return a successful reply')
    names = {abi: syscall_names(abi) for abi in (32, 64)}
    rows = []
    for counter in profile['syscalls']:
        abi, nr, calls, ns, maximum = (counter[key] for key in ('abi', 'nr', 'calls', 'ns', 'max_ns'))
        if not calls or not 0 <= maximum <= ns:
            parser.error(f'invalid counter for ABI {abi} syscall {nr}')
        rows.append((abi, nr, names.get(abi, {}).get(nr, f'syscall_{nr}'), calls,
                     ns / 1e6, ns / calls / 1e3, maximum / 1e6))
    rows.sort(key=lambda row: row[4], reverse=True)
    columns = ('abi', 'nr', 'syscall', 'calls', 'total_ms', 'average_us', 'max_ms')
    if args.csv:
        with args.csv.open('w', newline='') as output:
            writer = csv.writer(output)
            writer.writerow(columns)
            writer.writerows(rows)
    print(f'{"ABI":>3} {"NR":>4} {"SYSCALL":<28} {"CALLS":>10} {"TOTAL ms":>12} {"AVG us":>10} {"MAX ms":>10}')
    for abi, nr, name, calls, total, average, maximum in rows:
        print(f'{abi:>3} {nr:>4} {name:<28} {calls:>10} {total:>12.3f} {average:>10.3f} {maximum:>10.3f}')
    print(f'{len(rows)} syscall types; {sum(row[3] for row in rows)} calls; '
          f'{sum(row[4] for row in rows) / 1000:.6f} seconds in handlers', file=sys.stderr)


if __name__ == '__main__':
    main()
