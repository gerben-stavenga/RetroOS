#!/usr/bin/env python3
"""Check POSIX namespace permissions on native ext4."""
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot
from pathlib import Path


def main():
    artifacts = ROOT/'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-namespace_permissions-') as directory:
        work = Path(directory)
        tree = work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-static', str(ROOT/'test/linux_namespace_permissions_probe.c'), '-o', str(tree/'probe')], check=True)
        subprocess.run([str(tree/'probe'), str(work)], check=True, timeout=15)
        image = work/'data.ext4'
        with image.open('wb') as stream: stream.truncate(32*1024*1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(image)], check=True)
        # Foreign ownership cannot be constructed by an unprivileged host
        # process; set it only in the disposable ext4 fixture.
        for command in (
            'mkdir /home/retroos/sticky',
            'set_inode_field /home/retroos/sticky mode 041777',
            'set_inode_field /home/retroos/sticky uid 2000',
            f'write {tree / "probe"} /home/retroos/sticky/foreign',
            'set_inode_field /home/retroos/sticky/foreign uid 2001',
            'set_inode_field /home/retroos/sticky/foreign mode 0100444',
            f'write {tree / "probe"} /home/retroos/sticky/owned',
            f'set_inode_field /home/retroos/sticky/owned uid {(tree / "home/retroos").stat().st_uid}',
            'set_inode_field /home/retroos/sticky/owned mode 0100444',
        ):
            subprocess.run(['debugfs', '-w', '-R', command, str(image)], check=True, capture_output=True)
        boot = prepare_boot(work, image, '[environment]\nTEST=/probe\n')
        log = artifacts/'linux-namespace_permissions.log'
        with log.open('w') as output:
            result = subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '512',
                '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={image},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT, timeout=40)
        text = log.read_text()
        assert result.returncode == 0 and 'NAMESPACE_PASS:' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
    print('PASS: POSIX namespace permissions')


if __name__ == '__main__': main()
