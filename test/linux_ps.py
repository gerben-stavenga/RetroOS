#!/usr/bin/env python3
"""Run Codex's process-identity command with the installed GNU procps."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from linux_smb_symlink import ROOT, launch


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-ps-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_ps_probe.c'),
                        '-o', str(home / 'ps-probe')], check=True)
        (home / 'run.sh').write_text('''
/bin/cat /proc/stat > /home/retroos/proc-stat 2> /home/retroos/cat-errors
/bin/ps -p $$ -o stat= -o lstart= > /home/retroos/first 2> /home/retroos/errors || exit 1
/home/retroos/ps-probe > /home/retroos/child 2>> /home/retroos/errors || exit 4
/bin/sleep 2
/bin/ps -p $$ -o stat= -o lstart= > /home/retroos/second 2>> /home/retroos/errors || exit 2
/bin/ps -p 987654 -o stat= -o lstart= > /home/retroos/missing 2>> /home/retroos/errors
test $? -eq 1 || exit 3
exit 0
''')
        try:
            launch(work, 'RETROOS/SHELL.ELF /home/retroos/run.sh', 'linux-ps')
        except AssertionError:
            for name in ('first', 'second', 'missing', 'errors', 'proc-stat', 'cat-errors'):
                if (home / name).exists():
                    print(name + ': ' + (home / name).read_text(), flush=True)
            print((ROOT / 'build/ci/linux-ps.log').read_text()[-2500:], flush=True)
            raise
        first, second = [(home / name).read_text().strip().split(maxsplit=1) for name in ('first', 'second')]
        assert len(first) == len(second) == 2, (first, second)
        assert len((home / 'child').read_text().strip().split(maxsplit=1)) == 2
        assert first[1] == second[1], (first, second)
        assert re.fullmatch(r'\w{3} \w{3}\s+\d{1,2} \d\d:\d\d:\d\d \d{4}', first[1]), first
        assert not (home / 'missing').read_text()
        assert not (home / 'errors').read_text(), (home / 'errors').read_text()
    print('PASS: ps reports stable start times, finds newly created children, and rejects absent PIDs')


if __name__ == '__main__':
    main()
