#!/usr/bin/env python3
"""GNU wget/OpenSSL over native VirtIO: TLS downloads and certificate rejection."""
from pathlib import Path
import http.server
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]
BODY = bytes((i * 29 + 17) & 255 for i in range(32768))


def run(*args):
    return subprocess.run(list(map(str, args)), cwd=ROOT, check=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_):
        pass


def session(work, ca, certificate, key, name, version, trusted=True, hostname=True):
    work.mkdir()
    tree = work / 'root'
    for path in ('etc/ssl/certs', 'usr/bin', 'home/retroos/RETROOS'):
        (tree / path).mkdir(parents=True)
    shutil.copyfile('/usr/bin/wget', tree / 'usr/bin/wget')
    # The guest uses real Linux userspace libraries; the kernel supplies only
    # socket/random/time syscalls, not TLS or a hosted networking workaround.
    libraries = subprocess.check_output(['ldd', '/usr/bin/wget'], text=True)
    for name_of_library in re.findall(r'(/[^\s()]+)', libraries):
        source = Path(name_of_library)
        if source.is_file():
            target = tree / name_of_library.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    shutil.copyfile(ca if trusted else '/etc/ssl/certs/ca-certificates.crt',
                    tree / 'etc/ssl/certs/ca-certificates.crt')
    (tree / 'etc/hosts').write_text('10.0.2.2 wrong.example\n')
    (tree / 'etc/nsswitch.conf').write_text('hosts: files dns\n')
    data = work / 'data.img'
    with data.open('wb') as output:
        output.truncate(64 * 1024 * 1024)
    run('mkfs.ext4', '-q', '-F', '-d', tree, data)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = '10.0.2.2' if hostname else 'wrong.example'
    command = ('/usr/bin/wget -t 1 --ca-certificate=/etc/ssl/certs/ca-certificates.crt '
               f'-O /home/retroos/RESULT.BIN https://{host}:{server.server_port}/')
    boot = prepare_boot(work, data, f'[environment]\nTEST={command}\n')
    log = work / 'klog'
    args = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '256',
            '-display', 'none', '-serial', 'none', '-no-reboot',
            '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={data},format=raw', '-debugcon', f'file:{log}',
            '-nic', 'none', '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0']
    with (work / 'stderr').open('wb') as errors:
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace') if log.exists() else ''
                assert 'PANIC' not in text and 'FATAL' not in text, text[-5000:]
                if '[mem] exit tid=1 code=' in text:
                    break
                assert process.poll() is None, text[-5000:]
                time.sleep(.1)
            else:
                raise AssertionError(text[-5000:])
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            server.shutdown()
            server.server_close()
    expected = 0 if trusted and hostname else 5  # wget SSL verification failure
    assert f'[mem] exit tid=1 code={expected} ' in text, text[-5000:]
    result = subprocess.check_output(['debugfs', '-R', 'cat /home/retroos/RESULT.BIN', str(data)],
                                     stderr=subprocess.DEVNULL)
    if expected == 0:
        assert result == BODY, f'{name}: TLS download differs ({len(result)} bytes)'
        assert '200 OK' in text, text[-5000:]
    else:
        assert not result, f'{name}: downloaded data despite invalid certificate'
        assert 'ERROR:' in text and 'certificate' in text, text[-5000:]
    print(f'PASS: {name}', flush=True)


def main():
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-https-'))
    print('Artifacts:', work, flush=True)
    ca, ca_key = work / 'ca.pem', work / 'ca.key'
    cert, key, csr = work / 'server.pem', work / 'server.key', work / 'server.csr'
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
        '-subj', '/CN=RetroOS HTTPS test CA', '-keyout', ca_key, '-out', ca)
    run('openssl', 'req', '-newkey', 'rsa:2048', '-noenc', '-subj', '/CN=10.0.2.2',
        '-keyout', key, '-out', csr)
    extensions = work / 'extensions'
    extensions.write_text('subjectAltName=IP:10.0.2.2\nbasicConstraints=critical,CA:FALSE\n'
                          'keyUsage=critical,digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\n')
    run('openssl', 'x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key,
        '-CAcreateserial', '-days', '1', '-extfile', extensions, '-out', cert)
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        session(work / version.name, ca, cert, key, version.name + ' verified 32KiB download', version)
    session(work / 'untrusted', ca, cert, key, 'untrusted issuer rejected', ssl.TLSVersion.TLSv1_3, trusted=False)
    session(work / 'hostname', ca, cert, key, 'wrong hostname rejected', ssl.TLSVersion.TLSv1_3, hostname=False)


if __name__ == '__main__':
    main()
