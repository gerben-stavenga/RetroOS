#!/usr/bin/env python3
"""Real VirtIO PCI DMA, DHCP, TCP and UDP through QEMU's user network."""
from pathlib import Path
import http.server
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]
HTTP_BODY = bytes((i * 19 + 7) & 255 for i in range(32768))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(HTTP_BODY)))
        self.end_headers()
        self.wfile.write(HTTP_BODY)

    def log_message(self, *_):
        pass


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def session(work, name, device, uefi=False, bits=32, driver_ready="virtio-net: ready"):
    work.mkdir()
    tcp = socket.socket()
    tcp.bind(('127.0.0.1', 0))
    tcp.listen()
    tcp.settimeout(60)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    udp.settimeout(60)
    refused = socket.socket()
    refused.bind(('127.0.0.1', 0))  # Bound, deliberately not listening.
    failures = []
    forwarding = socket.socket()
    forwarding.bind(('127.0.0.1', 0))
    forward_port = forwarding.getsockname()[1]
    forwarding.close()
    outgoing_done = threading.Event()
    incoming_done = threading.Event()
    http_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=http_server.serve_forever, daemon=True).start()

    def tcp_server():
        try:
            connection, _ = tcp.accept()
            with connection:
                connection.settimeout(30)
                data = bytearray()
                while len(data) < 128 * 1024:
                    chunk = connection.recv(16384)
                    assert chunk, 'TCP request ended early'
                    data.extend(chunk)
                assert data == bytes((i * 37 + (i >> 8)) & 255 for i in range(128 * 1024))
                connection.sendall(bytes(v ^ 0x5a for v in data))
            connection, _ = tcp.accept()
            connection.close()
            outgoing_done.set()
        except Exception as error:
            failures.append(error)

    def incoming_client():
        try:
            assert outgoing_done.wait(45), 'outgoing TCP did not complete'
            for _ in range(2):
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', forward_port), timeout=2) as connection:
                            connection.sendall(b'PING')
                            data = b''
                            while len(data) < 4:
                                chunk = connection.recv(4 - len(data))
                                if not chunk:
                                    raise ConnectionResetError('listener not ready')
                                data += chunk
                            assert data == b'PONG', data
                            break
                    except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.1)
            incoming_done.set()
        except Exception as error:
            failures.append(error)

    def udp_server():
        try:
            for length in (257, 31, 9, 5, 9):
                data, peer = udp.recvfrom(2048)
                assert len(data) == length
                udp.sendto(data, peer)
        except Exception as error:
            failures.append(error)

    if device:
        for target in (tcp_server, udp_server, incoming_client):
            threading.Thread(target=target, daemon=True).start()
    data = work / 'data.img'
    with data.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', data)
    run('mmd', '-i', data, '::RETROOS')
    flags = [f'-DTCP_PORT={tcp.getsockname()[1]}', f'-DUDP_PORT={udp.getsockname()[1]}',
             f'-DREFUSED_PORT={refused.getsockname()[1]}']
    if device is None:
        flags.append('-DNO_NIC')
    run('gcc', f'-m{bits}', '-static', '-nostdlib', '-no-pie', '-fno-pic', '-fno-stack-protector',
        '-O2', '-e', '_start', *flags, ROOT / 'test/virtio_net_probe.c', '-o', work / 'NET.ELF')
    run('mcopy', '-i', data, work / 'NET.ELF', '::NET.ELF')
    commands = '/home/retroos/NET.ELF'
    if device:
        commands += f';/bin/busybox wget -q -O /home/retroos/NETWORK.TXT http://10.0.2.2:{http_server.server_port}/probe'
    boot = prepare_boot(work, data, '[environment]\nTEST=' + commands + '\n')
    log = work / 'klog'
    args = ['qemu-system-x86_64', '-m', '256', '-display', 'none', '-serial', 'none',
            '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={data},format=raw',
            '-debugcon', f'file:{log}', '-no-reboot', '-nic', 'none']
    if device:
        args += ['-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{forward_port}-:23456', '-device', device + ',netdev=net0',
                 '-object', f'filter-dump,id=capture,netdev=net0,file={work / "network.pcap"}']
    if uefi:
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work / 'vars.fd')
        args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive', f'if=pflash,format=raw,file={work / "vars.fd"}']
    with (work / 'stderr').open('w') as errors:
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace') if log.exists() else ''
                exits = re.findall(r'\[mem\] exit tid=\d+ code=(-?\d+) ', text)
                if len(exits) >= (2 if device else 1) or any(s in text for s in ('PANIC', 'FATAL')):
                    break
                assert process.poll() is None, (text, (work / 'stderr').read_text())
                time.sleep(.1)
            assert exits == (['0', '0'] if device else ['0']), text[-10000:]
            assert not any(s in text for s in ('PANIC', 'FATAL')), text
            if device:
                assert driver_ready in text and 'Network: DHCP IPv4 10.0.2.15/24' in text, text
                assert incoming_done.wait(2), failures
                assert not failures, failures
                saved = subprocess.check_output(['mtype', '-i', str(data), '::NETWORK.TXT'])
                assert saved == HTTP_BODY, 'BusyBox wget download differs from server response'
            print('PASS:', name, flush=True)
        finally:
            process.terminate()
            process.wait(timeout=5)
            tcp.close()
            udp.close()
            refused.close()
            http_server.shutdown()
            http_server.server_close()


def main():
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-virtio-net-'))
    print('Artifacts:', work, flush=True)
    session(work / 'transitional', 'BIOS transitional VirtIO', 'virtio-net-pci')
    session(work / 'modern', 'UEFI modern VirtIO, 64-bit sockets', 'virtio-net-pci,disable-legacy=on', True, 64)
    session(work / 'absent', 'no NIC returns ENOSYS', None)


if __name__ == '__main__':
    main()
