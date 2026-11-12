#!/usr/bin/env python3
"""QEMU/KVM: physical file pages share storage beyond kernel address-space size."""
import argparse
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--large', action='store_true', help='Cache 1152 MiB with 3 GiB RAM')
    parser.add_argument('--size-mb', type=int, help='Override the file size for profiling')
    parser.add_argument('--kernel', type=Path, help='Test a prepared kernel in the private boot copy')
    parser.add_argument('--label', help='Separate diagnostic log name')
    args = parser.parse_args()
    if args.size_mb is not None and args.size_mb <= 0: parser.error('--size-mb must be positive')
    size = (args.size_mb or (1152 if args.large else 16)) * 1024 * 1024
    label = args.label or ('large' if args.large else 'small')
    log = ROOT / f'build/ci/frame-cache-{label}.log'
    log.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-frame-cache-') as directory:
        work = Path(directory); root = work / 'root'
        (root / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-static', str(ROOT / 'test/linux_frame_cache_probe.c'), '-o', str(root / 'probe')], check=True)
        with (root / 'data').open('wb') as output:
            output.write(b'A'); output.seek(size - 1); output.write(b'Z')
        image = work / 'data.ext4'
        with image.open('wb') as output: output.truncate(size + 64 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(root), str(image)], check=True)
        boot = prepare_boot(work, image, f'[environment]\nTEST=/probe {size}\n')
        if args.kernel:
            subprocess.run(['mcopy', '-o', '-i', str(boot)+'@@1048576', str(args.kernel.resolve(strict=True)), '::kernel.elf'], check=True)
        with log.open('w') as output:
            result = subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '3072' if args.large else '256', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none', '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on', '-drive', f'file={image},format=raw,if=none,id=data', '-device', 'nvme,drive=data,serial=FRAMECACHE'], stdout=output, stderr=subprocess.STDOUT, timeout=300)
        text = log.read_text()
        assert result.returncode == 0 and 'FRAME_CACHE_PASS' in text and '[mem] exit tid=1 code=0' in text, text[-4000:]
        print(next(line for line in text.splitlines() if 'FRAME_CACHE_PASS' in line))
if __name__ == '__main__': main()
