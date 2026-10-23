#!/usr/bin/env python3
"""Shared native Intel Ethernet rings on QEMU 82540EM and 82574L devices."""
from pathlib import Path
import tempfile
from virtio_net import run, session


def main():
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-intel-net-'))
    print('Artifacts:', work, flush=True)
    for device, controller in [('e1000', '82540EM'), ('e1000e', '82574L')]:
        for uefi in (False, True):
            firmware = 'uefi' if uefi else 'bios'
            session(work / f'{device}-{firmware}',
                    f'{firmware.upper()} Intel {controller}: DHCP, TCP ring wrap, UDP, incoming TCP, wget',
                    device, uefi, 64 if uefi else 32,
                    driver_ready=f'intel-net: {controller} ready')


if __name__ == '__main__':
    main()
