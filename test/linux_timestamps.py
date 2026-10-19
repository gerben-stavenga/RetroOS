#!/usr/bin/env python3
"""Check Linux stat timestamp ABIs over native ext4 and live SMB in QEMU/KVM."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'build/ci'


def run(work, bits, smb=False):
    tree = work / 'root'
    home = tree / 'home/retroos'
    (home / 'RETROOS').mkdir(parents=True)
    stamps = home / 'stamps'
    stamps.mkdir()
    (stamps / 'file').write_text('timestamp fixture\n')
    (stamps / 'link').symlink_to('file')
    long = home / ('long-' + 'a' * 90) / ('long-' + 'b' * 90) / ('long-' + 'c' * 90)
    long.mkdir(parents=True)
    (long / 'file').write_text('long path fixture\n')
    os.utime(long / 'file', (1700000008, 1700000008))
    for name, seconds in [('file', 1700000002), ('link', 1700000006), ('', 1700000004)]:
        os.utime(stamps / name, (seconds, seconds), follow_symlinks=False)
    subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie', '-fno-pie',
        '-fno-stack-protector', *(['-DSMB'] if smb else []),
        str(ROOT / 'test/linux_timestamp_probe.c'), '-o', str(home / 'probe')], check=True)
    label = f'timestamps-{bits}-' + ('smb' if smb else 'ext4')
    env = os.environ.copy()
    env.pop('RETROOS_DATA_IMAGE', None)
    if smb:
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        profile = work / 'profile.json'
        profile.write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
        command = [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless', '--sound',
                   'none', '--cmd', '/home/retroos/probe']
    else:
        data = work / 'data.img'
        with data.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/home/retroos/probe\n')
        command = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '256',
            '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
            '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={data},format=raw']
    log = ARTIFACTS / (label + '.log')
    with log.open('w') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=90)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
    assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), str(log)
    if smb:
        metadata = (stamps / 'file').stat()
        assert int(metadata.st_mtime) == 1700000010, metadata
        assert int(metadata.st_atime) == 1700000011, metadata
        assert int(stamps.stat().st_mtime) == 1700000012
    print('PASS: ' + label, flush=True)


def main():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-timestamps-') as directory:
        for bits, smb in [(32, False), (64, False), (64, True)]:
            run(Path(directory) / f'{bits}-{smb}', bits, smb)


if __name__ == '__main__':
    main()
