#!/usr/bin/env python3
"""Live host / over signed SMB; C: is a writable subdirectory, not a disk copy."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-live-files-') as directory:
        work = Path(directory)
        c_root = work / 'c'
        (c_root / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', c_root / 'RETROOS/RETROOS.INI')
        target = work / 'outside.txt'
        target.write_text('application symlink outside C:\n')
        (c_root / 'link').symlink_to(target)
        # Use the same DOS probe as the ordinary SMB test, through C: instead
        # of an extra drive. It is launched by the real host GNU shell.
        source = work / 'probe.asm'
        source.write_text((ROOT / 'test/smb_dos.asm').read_text().replace('H:\\DOS.TXT', 'C:\\DOS.TXT'))
        subprocess.run(['nasm', '-f', 'bin', str(source), '-o', str(c_root / 'PROBE.COM')], check=True)
        denied = work / 'root-must-stay-readonly'
        script = c_root / 'check.sh'
        script.write_text(f'''set -eu
/home/retroos/PROBE.COM
IFS= read -r os < /etc/os-release
printf '%s\\n' "$os" > /home/retroos/root.txt
IFS= read -r target < /home/retroos/link
printf '%s\\n' "$target" > /home/retroos/link.txt
if printf wrong > {denied}; then exit 23; fi
printf '# live settings edit\\n' > /home/retroos/RETROOS/RETROOS.INI
printf 'LIVE ROOT PASS\\n' > /home/retroos/result.txt
''')
        profile = work / 'profile.json'
        profile.write_text(json.dumps({'root': '/', 'c_root': str(c_root)}))
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
        command = [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless', '--sound', 'none',
                   '--cmd', '/bin/sh /home/retroos/check.sh']
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=150)
        log = result.stdout + result.stderr
        artifacts = ROOT / 'build/ci'
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / 'live-root.log').write_text(log)
        assert result.returncode == 0, log[-8000:]
        assert not any(s in log for s in ('PANIC', 'FATAL', '[LINUX] fatal')), log[-8000:]
        assert 'SMB: mounted / (authenticated, signed SMB2)' in log, log[-8000:]
        assert 'SMB: mounted /home/retroos (authenticated, signed SMB2)' in log, log[-8000:]
        assert '[mem] exit tid=1 code=0' in log, log[-8000:]
        assert (c_root / 'DOS.TXT').read_bytes() == b'DOS through shared SMB VFS\r\n'
        assert (c_root / 'root.txt').read_text().strip() == Path('/etc/os-release').read_text().splitlines()[0]
        assert (c_root / 'link.txt').read_bytes() == target.read_bytes()
        assert (c_root / 'result.txt').read_text() == 'LIVE ROOT PASS\n'
        assert (c_root / 'RETROOS/RETROOS.INI').read_text().endswith('# live settings edit\n')
        assert not denied.exists(), 'root view allowed a host write outside C:'
    print('PASS: real GNU shell from live /, shared writable C: for DOS/Linux, application symlinks and read-only root')


if __name__ == '__main__':
    main()
