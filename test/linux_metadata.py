#!/usr/bin/env python3
"""Measure stat walks and their interaction with unrelated file writes."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', default='current')
    parser.add_argument('--filled', action='store_true', help='Use a valid mostly allocated filesystem with hundreds of full block groups')
    parser.add_argument('--boot-image', type=Path)
    args = parser.parse_args()
    artifacts = ROOT / 'build/ci/metadata'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-metadata-') as directory:
        work = Path(directory)
        tree = work / 'root'
        home = tree / 'home/retroos'
        (home / 'RETROOS').mkdir(parents=True)
        (home / 'flat').mkdir()
        for i in range(50):
            (home / 'tree' / f'd{i:02}').mkdir(parents=True)
        for i in range(2000):
            (home / 'flat' / f'f{i:04}').write_bytes(b'x')
            (home / 'tree' / f'd{i % 50:02}' / f'f{i:04}').write_bytes(b'x')
        (home / 'activity').write_bytes(b'')
        (home / 'growing').write_bytes(b'')
        (tree / 'filler').write_bytes(b'')
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_metadata_probe.c'),
                        '-o', str(tree / 'probe')], check=True)
        host = subprocess.run([str(tree / 'probe'), str(home)], capture_output=True, text=True, check=True)
        (artifacts / (args.label + '-linux.txt')).write_text(host.stderr)
        (home / 'activity').write_bytes(b'')
        (home / 'growing').write_bytes(b'')
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate((16384 if args.filled else 128) * 1024 * 1024)
        layout = ['-b', '4096', '-g', '1024', '-N', '16384', '-O', '^meta_bg,^resize_inode'] if args.filled else []
        subprocess.run(['mkfs.ext4', '-q', '-F', *layout, '-d', str(tree), str(data)], check=True)
        if args.filled:
            subprocess.run(['debugfs', '-w', '-R', 'fallocate /filler 0 3145727', str(data)],
                           check=True, capture_output=True)
            subprocess.run(['e2fsck', '-f', '-n', str(data)], check=True, capture_output=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n', boot_image=args.boot_image)
        log = artifacts / (args.label + '.log')
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                '-m', '1024', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw,if=none,id=fsdata',
                '-device', 'nvme,drive=fsdata,serial=RETROOS-METADATA'],
                stdout=output, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=240)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        text = log.read_text()
        assert process.returncode == 0 and '[mem] exit tid=1 code=0' in text and 'METADATA_PASS' in text, text[-3000:]
        subprocess.run(['e2fsck', '-f', '-n', str(data)], check=True, capture_output=True)
        result = {name: int(ns) for name, ns in re.findall(r'METADATA_NS (\w+) (\d+)', text)}
        (artifacts / (args.label + '.json')).write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
