#!/usr/bin/env python3
"""Run the installed CLI's code-mode helper repeatedly on native ext4."""
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import native_program_profile
from linux_smb_symlink import ROOT
sys.path.insert(0, str(ROOT/'tools'))
from setup_codex import DEFAULT_BINARY


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=DEFAULT_BINARY.with_name('codex-code-mode-host'))
    parser.add_argument('--sessions', type=int, default=24)
    parser.add_argument('--label', default='code-mode-stress')
    parser.add_argument('--start-delay', type=float, default=0)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    work = ROOT/'build/ci'/args.label
    home = work/'c'
    for child in ('RETROOS', 'TEMP'):(home/child).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT/'etc/RETROOS.INI', home/'RETROOS/RETROOS.INI')
    shutil.copyfile(ROOT/'test/linux_code_mode_stress_probe.py', home/'probe.py')
    (home/'run.sh').write_text('/usr/bin/python3 /home/retroos/probe.py '+shlex.quote(str(binary))+
        ' --sessions '+str(args.sessions)+' --start-delay '+str(args.start_delay)+
        ' > /home/retroos/output-probe 2> /home/retroos/errors-probe\nexit $?\n')
    image = native_program_profile.prepare(work, home, False, [str(binary)])
    try:
        native_program_profile.launch(work, home, image, args.label, ['probe', 'host'])
    except AssertionError:
        for name in ('errors-probe', 'output-host', 'output-probe'):
            path=home/name
            if path.exists():print(name+':\n'+path.read_text(errors='replace')[-2000:], flush=True)
        raise
    assert 'CODE_MODE_STRESS_PASS' in (home/'output-probe').read_text()
    print('PASS: repeated code-mode sessions')


if __name__ == '__main__': main()
