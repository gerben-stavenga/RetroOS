#!/usr/bin/env python3
"""Compare direct shells and exec-server command RPC on Linux and native ext4."""
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess
import native_program_profile
from linux_smb_symlink import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path.home()/'.codex/packages/app-server-daemon/current/bin/codex-exec-server')
    parser.add_argument('--label', default='exec-server-native')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    label = args.label
    work = ROOT/'build/ci'/label
    home = work/'c'
    for child in ('RETROOS', 'TEMP'):
        (home/child).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT/'etc/RETROOS.INI', home/'RETROOS/RETROOS.INI')
    shutil.copyfile(ROOT/'test/linux_exec_server_probe.py', home/'probe.py')
    with (work/'linux.jsonl').open('w') as output:
        subprocess.run(['python3', str(home/'probe.py'), str(binary)], stdout=output, check=True, timeout=90)
    (home/'run.sh').write_text('/usr/bin/python3 /home/retroos/probe.py '+shlex.quote(str(binary))+
                              ' > /home/retroos/output-probe 2> /home/retroos/errors-probe\nexit $?\n')
    image = native_program_profile.prepare(work, home, False, [str(binary), '/bin/bash', '/bin/cat', '/bin/sleep'])
    try:
        native_program_profile.launch(work, home, image, label, ['probe'])
    except AssertionError:
        for name in ('errors-probe', 'output-probe'):
            path = home/name
            if path.exists():
                print(name+':\n'+path.read_text(errors='replace')[-2500:], flush=True)
        raise
    assert '"event": "PASS"' in (home/'output-probe').read_text(), (home/'errors-probe').read_text()
    print('PASS: command completion through installed exec-server; timings in '+str(work))


if __name__ == '__main__':
    main()
