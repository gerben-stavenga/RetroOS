#!/usr/bin/env python3
"""Executable reuse, writes, shared mappings, rename and pathname replacement."""
import subprocess
import tempfile
from pathlib import Path
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]

def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    for bits in (64, 32):
        with tempfile.TemporaryDirectory(prefix='retroos-exec-cache-') as directory:
            work = Path(directory)
            tree = work / 'root'
            (tree / 'home/retroos/RETROOS').mkdir(parents=True)
            subprocess.run(['gcc', f'-m{bits}', '-static', '-O2', str(ROOT / 'test/linux_exec_cache_probe.c'), '-o', str(tree / 'probe')], check=True)
            child = tree / 'home/retroos/child'
            source = 'volatile const unsigned char marker[]="EXEC_CACHE_BYTE_\\013"; int main(void){return marker[16];}'
            subprocess.run(['gcc', f'-m{bits}', '-static', '-O2', '-x', 'c', '-', '-o', str(child)], input=source, text=True, check=True)
            marker = b'EXEC_CACHE_BYTE_' + bytes([11])
            content = child.read_bytes()
            assert content.count(marker) == 1
            offset = content.index(marker) + len(marker) - 1
            data = work / 'data.img'
            with data.open('wb') as output:
                output.truncate(32 * 1024 * 1024)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
            boot = prepare_boot(work, data, f'[environment]\nTEST=/probe {offset}\n')
            log = artifacts / f'linux-exec-cache-{bits}.log'
            with log.open('w') as output:
                process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                    '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                    '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                    '-drive', f'file={data},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT)
                try:
                    process.wait(timeout=45)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
            text = log.read_text()
            assert process.returncode == 0 and 'EXEC_CACHE_PASS' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
            print(f'PASS: exec-cache {bits}-bit', flush=True)

if __name__ == '__main__':
    main()
