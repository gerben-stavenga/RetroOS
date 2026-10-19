#!/usr/bin/env python3
"""Exercise real blocking POSIX locks in 32/64-bit native RetroOS guests."""
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-record-lock-') as directory:
        for bits, legacy in [(32, False), (64, False), (32, True)]:
            label = 'legacy-486' if legacy else str(bits)
            work = Path(directory) / label
            tree = work / 'root'
            (tree / "home/retroos/RETROOS").mkdir(parents=True)
            (tree / 'lockfile').write_bytes(b'lock test')
            subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie',
                '-fno-pie', '-fno-stack-protector', '-fno-builtin',
                *(['-march=i486'] if legacy else []),
                str(ROOT / 'test/linux_record_lock_probe.c'), '-o', str(tree / 'probe')], check=True)
            data = work / 'data.img'
            with data.open('wb') as stream:
                stream.truncate(32 * 1024 * 1024)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
            boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
            log = ROOT / f'build/ci/record-lock-{label}.log'
            with log.open('w') as output:
                process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'tcg' if legacy else 'kvm',
                    '-cpu', '486' if legacy else 'host', '-m', '256', '-display', 'none', '-serial', 'none',
                    '-nic', 'none', '-debugcon', 'stdio', '-no-reboot',
                    '-drive', f'file={boot},format=raw,snapshot=on',
                    '-drive', f'file={data},format=raw'], stdout=output, stderr=subprocess.STDOUT)
                try:
                    process.wait(timeout=40)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
            text = log.read_text()
            assert process.returncode == 0 and 'RECORD LOCK PASS' in text and '[mem] exit tid=1 code=0' in text, text[-2500:]
            print(f'PASS: {label}: POSIX record locks, conflict queries, blocking waits, pwrite64 and directory fsync', flush=True)


if __name__ == '__main__':
    main()
