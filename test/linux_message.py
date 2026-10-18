#!/usr/bin/env python3
"""Native IPv4 recvmsg: 32/64-bit vectors, peeking and UDP truncation."""
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-message-') as directory:
        for bits in (32, 64):
            work = Path(directory) / str(bits)
            tree = work / 'root'
            (tree / "home/retroos/RETROOS").mkdir(parents=True)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.bind(('127.0.0.1', 0))
                server.settimeout(45)
                port = server.getsockname()[1]
                errors = []

                def echo():
                    try:
                        data, peer = server.recvfrom(1024)
                        assert data == b'hello'
                        server.sendto(b'abcdef', peer)
                        server.sendto(b'ghijkl', peer)
                    except Exception as error:
                        errors.append(error)

                thread = threading.Thread(target=echo, daemon=True)
                thread.start()
                subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-fno-pie', '-no-pie',
                                '-fno-stack-protector', f'-DPORT={port}',
                                str(ROOT / 'test/linux_message_probe.c'), '-o', str(tree / 'probe')], check=True)
                data = work / 'data.img'
                with data.open('wb') as output:
                    output.truncate(32 * 1024 * 1024)
                subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
                boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
                log = artifacts / f'recvmsg-{bits}.log'
                with log.open('w') as output:
                    process = subprocess.Popen(
                        ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '256',
                         '-display', 'none', '-serial', 'none', '-no-reboot',
                         '-drive', f'file={boot},format=raw,snapshot=on',
                         '-drive', f'file={data},format=raw', '-debugcon', 'stdio',
                         '-nic', 'none', '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0'],
                        stdout=output, stderr=subprocess.STDOUT)
                    try:
                        process.wait(timeout=45)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=5)
                thread.join(timeout=1)
                assert not errors and not thread.is_alive(), errors
                assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), str(log)
    print('PASS: native 32/64-bit recvmsg scatter, source address, peek and datagram truncation')


if __name__ == '__main__':
    main()
