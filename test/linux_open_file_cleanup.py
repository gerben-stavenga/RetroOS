#!/usr/bin/env python3
"""Remove a locked open file and its parent while retaining descriptor I/O."""
import json
import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path
from linux_smb_symlink import ROOT, launch
from boot_fixture import prepare_boot

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=('smb', 'ext4', 'both'), default='both')
    args = parser.parse_args()
    backends = ('smb', 'ext4') if args.backend == 'both' else (args.backend,)
    for backend in backends:
        run(backend)

def run(backend):
    for bits in (64, 32):
        with tempfile.TemporaryDirectory(prefix='retroos-open-clean-') as directory:
            work = Path(directory)
            home = work / 'c'
            (home / 'RETROOS').mkdir(parents=True)
            shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
            (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
            subprocess.run(['gcc', f'-m{bits}', '-static', '-O2', str(ROOT / 'test/linux_open_file_cleanup_probe.c'), '-o', str(home / 'probe')], check=True)
            label = f'open-file-cleanup-{backend}-{bits}'
            if backend == 'smb':
                launch(work, 'probe', label, memory=2048)
                assert not (home / 'cleanup').exists()
                assert not list(home.glob('.retroos-unlinked-*'))
            else:
                tree = work / 'root'
                (tree / 'home').mkdir(parents=True)
                shutil.copytree(home, tree / 'home/retroos')
                data = work / 'data.img'
                with data.open('wb') as output:
                    output.truncate(32 * 1024 * 1024)
                subprocess.run(['mkfs.ext4','-q','-F','-d',str(tree),str(data)],check=True)
                boot = prepare_boot(work, data, '[environment]\nTEST=/home/retroos/probe\n')
                log = ROOT / 'build/ci' / f'{label}.log'
                with log.open('w') as output:
                    process = subprocess.Popen(['qemu-system-x86_64','-accel','kvm','-cpu','host',
                        '-m','256','-display','none','-serial','none','-no-reboot','-nic','none',
                        '-debugcon','stdio','-drive',f'file={boot},format=raw,snapshot=on',
                        '-drive',f'file={data},format=raw'],stdout=output,stderr=subprocess.STDOUT)
                    try:
                        process.wait(timeout=45)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=5)
                assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), log.read_text()[-2000:]
                check = subprocess.run(['e2fsck','-fn',str(data)],capture_output=True,text=True)
                assert check.returncode == 0, check.stdout + check.stderr
                print(f'PASS: {label} and e2fsck',flush=True)
            assert 'OPEN_CLEAN_PASS' in (ROOT / 'build/ci' / f'{label}.log').read_text()

if __name__ == '__main__':
    main()
