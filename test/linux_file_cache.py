#!/usr/bin/env python3
"""Exercise the common file cache through local FAT/ext4 and signed live SMB."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import threading
from linux_smb_symlink import launch, ROOT
from boot_fixture import prepare_boot


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-file-cache-') as directory:
        work = Path(directory)
        home = work / 'root/home/retroos'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_file_cache_probe.c'),
                        '-o', str(home / 'probe')], check=True)
        for kind in ('ext4', 'fat'):
            volume = work / kind
            volume.mkdir()
            data = volume / 'data.img'
            with data.open('wb') as output:
                output.truncate(32 * 1024 * 1024)
            if kind == 'ext4':
                subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(work / 'root'), str(data)], check=True)
            else:
                subprocess.run(['mkfs.fat', '-F', '16', str(data)], check=True)
                subprocess.run(['mcopy', '-i', str(data), '-s', str(work / 'root/home'), '::/'], check=True)
            boot = prepare_boot(volume, data, '[environment]\nTEST=/home/retroos/probe\n')
            log = ROOT / f'build/ci/file-cache-{kind}.log'
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open('w') as output:
                process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                    '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                    '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                    '-drive', f'file={data},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT)
                try:
                    process.wait(timeout=90)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
            assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), log.read_text()[-4000:]
            print(f'PASS: {kind} file cache and shared mappings', flush=True)
        (home / 'cache-external').write_bytes(b'original')
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        stop = threading.Event()
        changed = threading.Event()
        def writer():
            while not stop.wait(.02):
                if (home / 'cache-ready').exists():
                    (home / 'cache-external').write_bytes(b'new')
                    changed.set()
                    return
        thread = threading.Thread(target=writer)
        thread.start()
        try:
            launch(work, 'probe external', 'file-cache-smb', timeout=180)
            assert changed.is_set(), 'external writer did not run'
        finally:
            stop.set()
            thread.join(timeout=5)

        # The interpreter's shared frames are distinct from ordinary heap
        # allocations, so exercise promotion and release there as well.
        subprocess.run(['bazelisk', 'build', '//kernel:retroos-host-kvm',
                        '--platforms=@platforms//host'], cwd=ROOT, check=True)
        log = ROOT / 'build/ci/file-cache-hosted.log'
        with log.open('w') as output:
            result = subprocess.run(['python3', str(Path(__file__).resolve().parent / 'disk_fixture.py'), '--root', str(work / 'root'), '--', str(ROOT / 'bazel-bin/kernel/retroos-host-kvm'), '--cmd', '/home/retroos/probe', '--cwd', '/home/retroos'], stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, timeout=90)
        assert result.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), log.read_text()[-4000:]
        print('PASS: hosted file cache and architecture frame promotion', flush=True)


if __name__ == '__main__':
    main()
