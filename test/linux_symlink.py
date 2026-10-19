#!/usr/bin/env python3
"""Native ext4 links, dup/renameat ABIs, executable paths and Codex aliases."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]
CODEX = Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/'
             'codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
LONG_DIR = 'directory-with-a-name-long-enough-to-require-a-block-backed-symbolic-link'


def run(work, bits, codex=False):
    tree = work / 'root'
    home = tree / 'home/retroos'
    (home / 'RETROOS').mkdir(parents=True)
    (home / LONG_DIR).mkdir()
    (home / 'target').write_bytes(b'LINKOK')
    (home / LONG_DIR / 'target').write_bytes(b'LINKOK')
    if codex:
        (home / 'bin').mkdir()
        shutil.copyfile(CODEX, home / 'bin/codex')
    subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie', '-fno-pie',
                    '-fno-stack-protector', *(['-DCODEX'] if codex else []),
                    str(ROOT / 'test/linux_symlink_probe.c'), '-o', str(tree / 'probe')], check=True)
    (tree / 'probe-link').symlink_to('/probe')
    data = work / 'data.img'
    with data.open('wb') as output:
        output.truncate((768 if codex else 32) * 1024 * 1024)
    subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
    boot = prepare_boot(work, data, '[environment]\nTEST=/probe-link\n')
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    label = 'codex-aliases' if codex else f'symlink-{bits}'
    log = artifacts / (label + '.log')
    with log.open('w') as output:
        process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
            '-m', '2048' if codex else '256', '-display', 'none', '-serial', 'none',
            '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
            '-drive', f'file={boot},format=raw,snapshot=on', '-drive', f'file={data},format=raw'],
            stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=150)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), str(log)
    if codex:
        output = subprocess.check_output(['debugfs', '-R', 'cat /home/retroos/codex.out', str(data)],
                                        stderr=subprocess.DEVNULL, text=True)
        (artifacts / 'codex-aliases-output.txt').write_text(output)
        assert output.startswith('codex-cli ') and 'WARNING' not in output, output
    else:
        for link, target in [('relative', 'target'), ('dangling', 'missing'),
                             ('long', LONG_DIR + '/target'), ('boundary59', 'x' * 59),
                             ('boundary60', 'x' * 60)]:
            metadata = subprocess.check_output(['debugfs', '-R', f'stat /home/retroos/{link}', str(data)],
                                              stderr=subprocess.DEVNULL, text=True)
            if 'Fast link dest:' in metadata:
                assert f'Fast link dest: "{target}"' in metadata, metadata
            else:
                output = subprocess.check_output(['debugfs', '-R', f'cat /home/retroos/{link}', str(data)],
                                                stderr=subprocess.DEVNULL)
                assert output == target.encode(), (link, output, metadata)
    check = subprocess.run(['e2fsck', '-fn', str(data)], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    print(f'PASS: {label}: native ext4 links persist and Linux fsck is clean', flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-symlink-') as directory:
        for bits in (32, 64):
            work = Path(directory) / str(bits)
            run(work, bits)
        if CODEX.is_file():
            run(Path(directory) / 'codex', 64, codex=True)


if __name__ == '__main__':
    main()
