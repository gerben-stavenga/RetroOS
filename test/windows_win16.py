#!/usr/bin/env python3
"""Exercise real NE -> guest Rust -> nested NE callbacks on both CPU backends."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def main():
    engine = os.environ.get('ENGINE', 'kvm')
    if engine not in ('kvm', 'tcg'):
        raise SystemExit('ENGINE must be kvm or tcg')
    host = 'retroos-host-kvm' if engine == 'kvm' else 'retroos-host'
    subprocess.run(['bazelisk', 'build', '//tools/command:command_com'], cwd=ROOT, check=True)
    command_binary = (ROOT / 'bazel-bin/tools/command/COMMAND.COM').resolve()
    targets = [f'//kernel:{host}', '//test/windows/win16:bridge', '//test/windows/win16:fpmath', '//test/windows/win16:civ_apis', '//test/windows/win16:window', '//test/windows/win16:legacy_user',
               '//lib/windows/user32:user32_dll', '//lib/windows/kernel32:kernel32_dll',
               '//lib/windows/compat:gdi32_dll', '//lib/windows/compat:winmm_dll', '//test/windows/win16:multimedia', '//test/windows/win16:mmio', '//test/windows/win16:text', '//test/windows/win16:clipping']
    targets += [f'//test/windows/win16:{name}' for name in ('initializers','init_dependency','init_nested','init_large','init_failure')]
    targets += [f'//lib/windows/win16:{name}_dll' for name in ('user','kernel','gdi','sound','shell','keyboard','lzexpand','win87em','mmsystem','commdlg')]
    subprocess.run(['bazelisk', 'build', *targets, '--platforms=@platforms//host'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-win16-') as directory:
        root = Path(directory)
        (root / "INSTALL.INI").write_text("[Installer]\nTarget=C:\\CIV\n", encoding="ascii")
        system = root / 'RETROOS/WINDOWS/SYSTEM'
        system.mkdir(parents=True)
        system32 = root / 'RETROOS/WINDOWS/SYSTEM32'
        system32.mkdir()
        for name in ('USER','KERNEL','GDI','SOUND','SHELL','KEYBOARD','LZEXPAND','WIN87EM','MMSYSTEM','COMMDLG'):
            shutil.copyfile(ROOT / f'bazel-bin/lib/windows/win16/{name}.DLL', system / f'{name}.DLL')
        for name, folder in [('USER32','user32'), ('KERNEL32','kernel32'), ('GDI32','compat'), ('WINMM','compat')]:
            shutil.copyfile(ROOT / f'bazel-bin/lib/windows/{folder}/{name}.DLL', system32 / f'{name}.DLL')
        shutil.copyfile(ROOT / 'bazel-bin/test/windows/win16/LEGACYUSER.DLL', root / 'USER.DLL')
        for name in ('INITDEP','INITNEST','INITLARGE','INITFAIL'):
            shutil.copyfile(ROOT / f'bazel-bin/test/windows/win16/{name}.DLL', root / f'{name}.DLL')
        for program in ('bridge', 'window', 'fpmath', 'civ_apis', 'initializers', 'multimedia', 'mmio', 'text', 'clipping'):
            shutil.copyfile(ROOT / f'bazel-bin/test/windows/win16/{program}.exe', root / 'BRIDGE.EXE')
            process = subprocess.Popen(['python3', str(ROOT/'test/disk_fixture.py'), '--root', directory, '--',
                str(ROOT/f'bazel-bin/kernel/{host}'), '--c-root', '/', '--cmd', '/BRIDGE.EXE probe' if program == 'window' else '/BRIDGE.EXE'],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
            try:
                log, _ = process.communicate(timeout=40)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                log, _ = process.communicate(timeout=5)
                raise SystemExit(f'{program} timed out:\n{log}')
            if process.returncode or f'WIN16 {program.upper()} PASS' not in log or any(x in log for x in ('PANIC', 'SEGV', ' FAIL')):
                raise SystemExit(log)
        # DOS parents encode cwd as C: or C:DIR/SUBDIR. Exercise the same
        # shell fork/exec boundary used by DN, not just direct NE startup.
        shutil.copyfile(command_binary, root / 'RETROOS/COMMAND.COM')
        shutil.copyfile(ROOT / 'bazel-bin/test/windows/win16/bridge.exe', root / 'BRIDGE.EXE')
        (root / 'LAUNCH/SUBDIR').mkdir(parents=True)
        for cwd in ('/', '/LAUNCH/SUBDIR'):
            result = subprocess.run(['python3', str(ROOT/'test/disk_fixture.py'), '--root', directory, '--',
                str(ROOT/f'bazel-bin/kernel/{host}'), '--c-root', '/', '--cwd', cwd,
                '--cmd', '/RETROOS/COMMAND.COM /C C:\\BRIDGE.EXE'],
                cwd=ROOT, capture_output=True, text=True, timeout=40)
            log = result.stdout + result.stderr
            if result.returncode or 'WIN16 BRIDGE PASS' not in log or any(x in log for x in ('PANIC', 'SEGV', ' FAIL')):
                raise SystemExit(log)
        shutil.copyfile(ROOT / 'bazel-bin/test/windows/win16/window.exe', root / 'BRIDGE.EXE')
        # A missing runtime is an error, not permission to revive an old ABI.
        (system / 'USER.DLL').rename(system / 'USER.saved')
        # Failed launch leaves the desktop running. Bound this negative test
        # and terminate the fixture and guest together, without orphaning either.
        process = subprocess.Popen(['python3', str(ROOT/'test/disk_fixture.py'), '--root', directory, '--',
            str(ROOT/f'bazel-bin/kernel/{host}'), '--c-root', '/', '--cmd', '/BRIDGE.EXE'],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            log, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            log, _ = process.communicate(timeout=5)
        if 'Windows: missing Win16 USER.DLL' not in log or 'WIN16 WINDOW PASS' in log:
            raise SystemExit(log)
        print(f'PASS: Win16 recursive callbacks, shared windows/GDI, messages, dialogs, multimedia timers, MMIO and exit ({engine})')

if __name__ == '__main__':
    main()
