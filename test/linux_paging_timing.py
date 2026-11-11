#!/usr/bin/env python3
"""Time anonymous mapping and first writes, without screen polling."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path)
    parser.add_argument('--label', default='current')
    args = parser.parse_args()
    artifacts = ROOT / 'build/ci/resume-investigation'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-paging-timing-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_paging_timing_probe.c'),
                        '-o', str(tree / 'probe')], check=True)
        host = subprocess.run([str(tree / 'probe')], capture_output=True, text=True, check=True)
        (artifacts / (args.label + '-paging-linux.txt')).write_text(host.stderr)
        image = work / 'root.ext4'
        with image.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(image)], check=True)
        boot = prepare_boot(work, image, '[environment]\nTEST=/probe\n')
        if args.kernel:
            subprocess.run(['mcopy', '-o', '-i', str(boot) + '@@1048576', str(args.kernel.resolve(strict=True)), '::kernel.elf'], check=True)
        log = artifacts / (args.label + '-paging.log')
        with log.open('w') as output:
            result = subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                '-m', '1024', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={image},format=raw,snapshot=on'],
                stdout=output, stderr=subprocess.STDOUT, timeout=45)
        text = log.read_text()
        assert result.returncode == 0 and 'PAGING_TIMING_PASS' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
        values = re.search(r'PAGING_NS (.*)', text).group(1)
        result = {name: int(value) for name, value in re.findall(r'(\w+)=(\d+)', values)}
        (artifacts / (args.label + '-paging.json')).write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
