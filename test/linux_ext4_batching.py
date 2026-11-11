#!/usr/bin/env python3
"""Bound physical write amplification while observing sequential ext4 writes."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from boot_fixture import ROOT, prepare_boot


def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-batching-') as directory:
        work = Path(directory)
        tree = work / 'root'
        home = tree / 'home/retroos'
        (home / 'RETROOS').mkdir(parents=True)
        (home / 'other').write_text('unrelated file\n')
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_ext4_batching_probe.c'), '-o', str(tree / 'probe')], check=True)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        qmp_path = work / 'qmp'
        log = artifacts / 'linux-ext4-batching.log'
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot', '-no-shutdown', '-nic', 'none',
                '-qmp', f'unix:{qmp_path},server=on,wait=off', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw,if=none,id=fsdata',
                '-device', 'nvme,drive=fsdata,serial=RETROOS-BATCH,write-cache=on'], stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                while not qmp_path.exists() and time.monotonic() < deadline:
                    assert process.poll() is None, log.read_text()[-2000:]
                    time.sleep(.05)
                with socket.socket(socket.AF_UNIX) as qmp:
                    qmp.settimeout(60)
                    qmp.connect(str(qmp_path))
                    stream = qmp.makefile('rb')
                    stream.readline()

                    def request(command):
                        qmp.sendall(json.dumps({'execute': command}).encode() + b'\n')
                        while True:
                            result = json.loads(stream.readline())
                            if 'return' in result:
                                return result['return']
                            assert 'error' not in result, result

                    request('qmp_capabilities')
                    while True:
                        event = json.loads(stream.readline())
                        if event.get('event') == 'SHUTDOWN':
                            break
                    stats = request('query-blockstats')
                    disk_stats = next(item['stats'] for item in stats if item.get('device') == 'fsdata')
                    writes = disk_stats['wr_operations']
                    written_bytes = disk_stats['wr_bytes']
                    request('quit')
                process.wait(timeout=5)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        text = log.read_text()
        assert 'BATCH_PASS:' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
        print(f'NVMe physical writes: {writes}; bytes: {written_bytes}', flush=True)
        # Preserve the working kernel's conservative commit behavior. The
        # lower-I/O experiment was withdrawn after a metal launch regression.
        assert writes < 600, f'Write amplification exceeded the working baseline: {writes} physical writes'
        recovered = work / 'recovered'
        subprocess.run(['debugfs', '-R', f'dump /home/retroos/batch {recovered}', str(data)], check=True, capture_output=True)
        assert recovered.read_bytes() == b'b' * 65536
        print('PASS: metadata preserves batching; fsync persists the complete file')


if __name__ == '__main__':
    main()
