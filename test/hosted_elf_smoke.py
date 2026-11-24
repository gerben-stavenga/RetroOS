#!/usr/bin/env python3
"""Run fixed ELF probes on the declared hosted backend."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    target = 'retroos-host-kvm' if os.environ.get('ENGINE') == 'kvm' else 'retroos-host'
    with tempfile.TemporaryDirectory(prefix='retroos-elf-') as directory:
        root = Path(directory)
        for name in ('hello', 'outlive_composite'):
            shutil.copyfile(ROOT / f'bazel-bin/tests/hosted_{name}.elf', root / (name + '.elf'))
            result = subprocess.run([str(ROOT / 'bazel-bin/kernel' / target), '--cmd', '/' + name + '.elf', str(root)], capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            assert result.returncode == 0, output
            assert 'Hello from an interpreted 32-bit Linux ELF!' in output, output
            assert 'panicked' not in output, output
            print('PASS:', target, name)

        home = root / 'DOS'
        release = home / 'RETROOS/releases/test'
        (release / 'DN').mkdir(parents=True)
        (release / 'RETROOS/DN').mkdir(parents=True)
        (release / 'RETROOS/DN/DN.COM').write_bytes(b'\xb8\x01\x4c\xcd\x21')
        (home / 'RETROOS/RETROOS.INI').write_text('[system]\nstart=C:\\DN\\DN.COM\n')
        (home / 'RETROOS/BOOT.INI').write_text(
            '[bundle]\nsource=UUID=ABCD-1234\nsubdir=/DOS/RETROOS/releases/test\n'
            '[mount "dos"]\nsource=UUID=ABCD-1234\nsubdir=/DOS\n'
            'path=/DOS\ndrive=C\naccess=rw\n'
        )
        shutil.copyfile(root / 'hello.elf', release / 'DN/DN.COM')
        with subprocess.Popen(
            [str(ROOT / 'bazel-bin/kernel' / target), '--host-c-root', str(home), str(root)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        ) as process:
            try:
                output, _ = process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                process.terminate()
                output, _ = process.communicate(timeout=5)
        assert 'Starting DOS/DN/DN.COM' in output, output[-4000:]
        assert 'Hello from an interpreted 32-bit Linux ELF!' in output, output[-4000:]
        assert not (home / 'DN').exists()
        print('PASS:', target, 'starts the exact program selected by RETROOS.INI')

        shutil.copyfile(ROOT / 'bazel-bin/tools/command/COMMAND.COM',
                        release / 'RETROOS/COMMAND.COM')
        user_ini = home / 'RETROOS/RETROOS.INI'
        user_ini.write_text('[environment]\nBATCH_CHECK=USER_SETTINGS\n')
        (release / 'RETROOS/RETROOS.INI').write_text('[environment]\nBATCH_CHECK=RELEASE_DEFAULT\n')
        stale_windows = home / 'RETROOS/WINDOWS/SYSTEM32'
        stale_windows.mkdir(parents=True)
        (stale_windows / 'NTDLL.DLL').write_text('STALE_WINDOWS\n')
        paired_runtime = root / 'paired-runtime'
        (paired_runtime / 'WINDOWS/SYSTEM32').mkdir(parents=True)
        (paired_runtime / 'WINDOWS/SYSTEM32/NTDLL.DLL').write_text('PAIRED_WINDOWS\n')
        shutil.copyfile(release / 'RETROOS/COMMAND.COM', paired_runtime / 'COMMAND.COM')
        (home / 'PLAY.BAT').write_bytes(
            b'@ECHO OFF\r\nTYPE C:\\RETROOS\\RETROOS.INI\r\nTYPE C:\\RETROOS\\WINDOWS\\SYSTEM32\\NTDLL.DLL\r\n'
        )
        result = subprocess.run(
            [str(ROOT / 'bazel-bin/kernel' / target), '--host-c-root', str(home),
             '--boot-runtime', str(paired_runtime), '--cmd', 'PLAY.BAT', str(root)],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        assert result.returncode == 0 and 'FATAL' not in output, output[-4000:]
        assert 'BATCH_CHECK=USER_SETTINGS' in output, output[-4000:]
        assert 'PAIRED_WINDOWS' in output and 'STALE_WINDOWS' not in output, output[-4000:]
        assert not (home / 'RETROOS/COMMAND.COM').exists()
        print('PASS:', target, 'runs a batch file with the installed shell and user settings')

        result = subprocess.run(
            [str(ROOT / 'bazel-bin/kernel' / target), '--boot-runtime', str(paired_runtime),
             '--cmd', 'PLAY.BAT'],
            env={**os.environ, 'HOME': str(root)}, capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        assert result.returncode == 0 and 'FATAL' not in output, output[-4000:]
        assert 'BATCH_CHECK=USER_SETTINGS' in output, output[-4000:]
        assert 'PAIRED_WINDOWS' in output and 'STALE_WINDOWS' not in output, output[-4000:]
        print('PASS:', target, 'uses HOME/DOS for a direct hosted launch')


if __name__ == '__main__':
    main()
