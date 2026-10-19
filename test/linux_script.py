#!/usr/bin/env python3
"""Linux script interpreters, argv/env and errors on ext4 and SMB."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
from boot_fixture import prepare_boot
from linux_smb_symlink import launch, ROOT


def run_case(work, bits, smb):
    tree = work / 'root'
    home = tree / 'home/retroos'
    (home / 'RETROOS').mkdir(parents=True)
    (home / 'bad').write_text('#!/home/retroos/absent-interpreter\n')
    (home / 'loop').write_text('#!/home/retroos/loop\n')
    (home / 'malformed').write_text('#! \t\n')
    (home / 'second').write_text('#!/home/retroos/interpreter single\n')
    (home / 'script with spaces').write_text('#! /home/retroos/second \toptional value \t\n')
    subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie', '-fno-pie',
        str(ROOT / 'test/linux_script_probe.c'), '-o', str(home / 'probe')], check=True)
    shutil.copyfile(home / 'probe', home / 'interpreter')
    if smb:
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        launch(work, 'probe', f'linux-script-{bits}-smb')
        return
    data = work / 'data.img'
    with data.open('wb') as output:
        output.truncate(32 * 1024 * 1024)
    subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
    boot = prepare_boot(work, data, '[environment]\nTEST=/home/retroos/probe\n')
    log = ROOT / 'build/ci' / f'linux-script-{bits}-ext4.log'
    with log.open('w') as output:
        process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
            '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
            '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={data},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=40)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    text = log.read_text()
    assert process.returncode == 0 and '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text[-2500:]
    print(f'PASS: linux-script-{bits}-ext4', flush=True)


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-linux-script-') as directory:
        for bits, smb in [(64, True), (32, True), (64, False), (32, False)]:
            run_case(Path(directory) / f'{bits}-{smb}', bits, smb)


if __name__ == '__main__':
    main()
