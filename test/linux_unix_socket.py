#!/usr/bin/env python3
"""Native Unix-domain streams across processes, without a NIC."""
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-unix-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_unix_socket_probe.c'), '-o', str(tree / 'probe')], check=True)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        for field, value in [('uid', 1001), ('gid', 1002)]:
            subprocess.run(['debugfs', '-w', '-R', f'set_inode_field /home/retroos {field} {value}', str(data)],
                           check=True, stdout=subprocess.DEVNULL)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        log = artifacts / 'linux-unix-socket.log'
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                '-m', '256', '-smp', '6', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=45)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        text = log.read_text()
        assert process.returncode == 0 and '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text[-3000:]
        assert '6 CPUs initialized' in text, text[-3000:]
        assert 'UNIX_PASS:' in text, text[-3000:]
        print('PASS: Unix streams, credentials, polling, large writes and namespace lifetimes', flush=True)


if __name__ == '__main__':
    main()
