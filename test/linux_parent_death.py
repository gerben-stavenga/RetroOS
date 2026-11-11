#!/usr/bin/env python3
"""Native parent identities and parent-death signal lifecycle through real fork/exec."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from linux_smb_symlink import ROOT, launch


def main():
    (ROOT / 'build/ci').mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-parent-death-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        subprocess.run(['gcc', '-O2', '-pthread', str(ROOT / 'test/linux_parent_death_probe.c'),
                        '-o', str(home / 'probe')], check=True)
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        launch(work, 'probe', 'linux-parent-death', timeout=180)
        assert 'PARENT DEATH PASS:' in (ROOT / 'build/ci/linux-parent-death.log').read_text()
    print('PASS: parent identities and parent-death signal lifecycle')


if __name__ == '__main__':
    main()
