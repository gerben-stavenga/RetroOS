#!/usr/bin/env python3
"""Native glibc worker-thread spawn/fork/exec with concurrent malloc arenas."""
from pathlib import Path
import subprocess
import json
import shutil
from linux_smb_symlink import launch
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def native():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-glibc-fork-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-pthread', '-static', '-no-pie', '-fno-pie',
            str(ROOT / 'test/linux_glibc_fork_probe.c'), '-o', str(tree / 'probe')], check=True)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        log = ROOT / 'build/ci/glibc-fork.log'
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
        assert process.returncode == 0 and '[mem] exit tid=1 code=0' in text, text[-2500:]
        print('PASS: glibc worker-thread spawn/fork/exec preserves shared spawn errors, COW and malloc arenas', flush=True)


def main():
    native()
    with tempfile.TemporaryDirectory(prefix='retroos-glibc-smb-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        subprocess.run(['gcc', '-pthread', '-static', '-no-pie', '-fno-pie',
            str(ROOT / 'test/linux_glibc_fork_probe.c'), '-o', str(home / 'probe')], check=True)
        launch(work, 'probe', 'glibc-fork-smb')


if __name__ == '__main__':
    main()
