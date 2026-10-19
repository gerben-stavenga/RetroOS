#!/usr/bin/env python3
"""Native UDP readiness drops and rises between edge-triggered epoll waits."""
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-epoll-net-') as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        server.bind(('127.0.0.1', 0))
        server.settimeout(40)
        tcp.bind(('127.0.0.1', 0))
        tcp.listen(1)
        tcp.settimeout(40)
        errors = []

        def exchange():
            try:
                for expected, response in [(b'start', b'A'), (b'next', b'B')]:
                    data, peer = server.recvfrom(100)
                    assert data == expected, data
                    server.sendto(response, peer)
                connection, _ = tcp.accept()
                with connection:
                    connection.settimeout(10)
                    connection.sendall(b'HELLO')
                    received = b''
                    while len(received) < 4:
                        data = connection.recv(4 - len(received))
                        assert data, 'TCP client closed before acknowledging the data'
                        received += data
                    assert received == b'done'
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=exchange, daemon=True)
        worker.start()
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-m64', '-nostdlib', '-static', '-no-pie', '-fno-pie',
            '-fno-stack-protector', f'-DPORT={server.getsockname()[1]}', f'-DTCP_PORT={tcp.getsockname()[1]}',
            str(ROOT / 'test/linux_epoll_network_probe.c'), '-o', str(tree / 'probe')], check=True)
        data = work / 'data.img'
        with data.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        log = ROOT / 'build/ci/epoll-network.log'
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot',
                '-nic', 'none', '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0',
                '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw'], stdout=output, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=40)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        text = log.read_text()
        worker.join(timeout=1)
        assert not errors, errors
        assert process.returncode == 0 and 'EPOLL SOCKET PASS' in text and '[mem] exit tid=1 code=0' in text, text[-2500:]
        print('PASS: native edge-triggered epoll sees data arriving after EAGAIN and before the next wait')


if __name__ == '__main__':
    main()
