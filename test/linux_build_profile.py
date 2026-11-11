#!/usr/bin/env python3
"""Profile Python startup and a real C compile/link/run in a private guest home."""
import importlib.util
import argparse
import json
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import threading
import time
from linux_smb_symlink import ROOT, launch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex-startup', action='store_true', help='Time two native --version invocations without login or session state')
    parser.add_argument('--native-ext4', action='store_true', help='Place tools, libraries and outputs on native ext4/NVMe with no network')
    options = parser.parse_args()
    label = 'program-profile-codex' if options.codex_startup else 'program-profile'
    if options.native_ext4:
        label += '-ext4'
    work = ROOT / 'build/ci' / label
    home = work / 'c'
    (home / 'RETROOS').mkdir(parents=True, exist_ok=True)
    (home / 'TEMP').mkdir(exist_ok=True)
    shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
    (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
    (home / 'hello.c').write_text('#include <stdio.h>\nint main(void) { puts("BUILD_PROFILE_PASS"); return 0; }\n')
    subprocess.run(['gcc', '-m64', '-nostdlib', '-static', '-no-pie', '-fno-pie', '-fno-stack-protector',
                    '-fno-builtin', '-O2', str(ROOT / 'test/linux_program_timer.c'), '-o', str(home / 'timer')], check=True)
    for name in ('timings', 'errors', 'output', 'stage', 'hello', 'hello.o'):
        (home / name).unlink(missing_ok=True)
    commands = [
        ('true', '/bin/true'),
        ('python-minimal', '/usr/bin/python3 -S -c "pass"'),
        ('python-imports', '/usr/bin/python3 -c "import pathlib, sqlite3, subprocess"'),
        ('compile', '/usr/bin/gcc -O2 -c /home/retroos/hello.c -o /home/retroos/hello.o'),
        ('link', '/usr/bin/gcc /home/retroos/hello.o -o /home/retroos/hello'),
        ('execute', '/home/retroos/hello'),
    ]
    if options.codex_startup:
        import sys
        sys.path.insert(0, str(ROOT / 'tools'))
        from setup_codex import DEFAULT_BINARY
        binary = shlex.quote(str(DEFAULT_BINARY.resolve(strict=True)))
        commands = [('codex-cold', binary + ' --version'), ('codex-repeat', binary + ' --version')]
    script = ['export HOME=/home/retroos TMPDIR=/home/retroos/TEMP MALLOC_ARENA_MAX=2\n']
    for name, command in commands:
        script += [f'printf "{name}\\n" > /home/retroos/stage\n',
                   f'/home/retroos/timer {name} {command}'
                   f' > /home/retroos/output-{name} 2> /home/retroos/errors-{name} || exit $?\n']
    script += ['printf "done\\n" > /home/retroos/stage\nexit 0\n']
    (home / 'run.sh').write_text(''.join(script))
    native_image = None
    if options.native_ext4:
        import native_program_profile
        native_image = native_program_profile.prepare(work, home, options.codex_startup)
    log = ROOT / 'build/ci' / (label + '.log')
    log.unlink(missing_ok=True)
    stop = threading.Event()

    def profile():
        spec = importlib.util.spec_from_file_location('serial_bridge', ROOT / 'tools/86box_mcp.py')
        bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bridge)
        control = None
        started = time.monotonic()
        with (work / 'samples.jsonl').open('w') as output:
            try:
                while not stop.wait(.25):
                    text = log.read_text(errors='replace') if log.exists() else ''
                    match = re.search(r'MCP control: (\S+)', text)
                    if control is None:
                        if not match or 'event_loop entered' not in text:
                            continue
                        control = bridge.SerialControl(None, match.group(1))
                        control.request('profile reset')
                        control.request('profile on')
                    sample = {'elapsed': time.monotonic() - started,
                              'stage': native_program_profile.stage(native_image) if native_image else (
                                  (home / 'stage').read_text().strip() if (home / 'stage').exists() else 'startup')}
                    for command in ('profile top', 'profile execution', 'profile reads', 'profile io'):
                        sample[command] = control.request(command, timeout=60)
                    sample['elapsed_end'] = time.monotonic() - started
                    output.write(json.dumps(sample) + '\n')
                    output.flush()
                    stop.wait(.75)
            except (RuntimeError, OSError) as error:
                output.write(json.dumps({'control_error': str(error)}) + '\n')
            finally:
                if control:
                    control.close()

    profiler = threading.Thread(target=profile, daemon=True)
    profiler.start()
    try:
        if native_image:
            native_program_profile.launch(work, home, native_image, label, [name for name, _ in commands])
        else:
            launch(work, 'RETROOS/SHELL.ELF /home/retroos/run.sh', label, timeout=240,
                   memory=2048, qemu_args=('-smp', '2', '-audiodev', 'none,id=snd0', '-device', 'intel-hda', '-device', 'hda-duplex,audiodev=snd0'))
    finally:
        stop.set()
        profiler.join(timeout=10)
        if (home / 'timings').exists():
            print('timings:\n' + (home / 'timings').read_text(), flush=True)
        errors = ''.join((home / ('errors-' + name)).read_text()
                         for name, _ in commands if (home / ('errors-' + name)).exists())
        (home / 'errors').write_text(errors)
        if errors:
            print('errors:\n' + errors, flush=True)
    if options.codex_startup:
        for name, _ in commands:
            assert (home / ('output-' + name)).read_text().startswith('codex-cli ')
        print('PASS: native Codex starts twice without session state')
    else:
        assert (home / 'output-execute').read_text().strip() == 'BUILD_PROFILE_PASS'
        print('PASS: Python starts; guest GCC compiles, links and runs a fresh C program')


if __name__ == '__main__':
    main()
