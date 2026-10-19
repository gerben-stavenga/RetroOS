#!/usr/bin/env python3
"""Large SMB read/pread/write/writev and persisted bytes through both Linux ABIs."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
from linux_smb_symlink import launch, ROOT


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-smb-read-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        expected = bytes(((i * 17 + 3) ^ (i >> 8)) & 255 for i in range(8*1024*1024+37))
        (home / 'payload').write_bytes(expected[:95013])
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        for bits in (64, 32):
            subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie',
                '-fno-pie', '-fno-stack-protector', str(ROOT / 'test/linux_smb_read_probe.c'),
                '-o', str(home / 'probe')], check=True)
            launch(work, 'probe', f'smb-read-{bits}')
            assert (home / 'written').read_bytes() == expected + expected[:70001] + expected[:90003]


if __name__ == '__main__':
    main()
