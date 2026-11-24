#!/usr/bin/env python3
"""Live host / over signed SMB; C: is a writable subdirectory, not a disk copy."""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def dos_views(path):
    views = [[]]
    for attrs, _time, _date, size, name in struct.iter_unpack('<BHHI13s', path.read_bytes()):
        name = name.split(b'\0', 1)[0]
        if name:
            views[-1].append((name, attrs, size))
        else:
            views.append([])
    assert len(views) == 3 and not views[-1], views
    return views[:2]


def main():
    with (tempfile.TemporaryDirectory(prefix='retroos-live-files-') as directory,
          tempfile.TemporaryDirectory(prefix='retroos-live-readonly-', dir='/var/tmp') as readonly):
        work = Path(directory)
        home = work / 'home'
        c_root = home / 'DOS'
        (c_root / 'RETROOS').mkdir(parents=True)
        (c_root / 'RETROOS/releases').mkdir()
        (c_root / 'RETROOS/WINDOWS/SYSTEM32').mkdir(parents=True)
        (c_root / 'RETROOS/OS2').mkdir()
        (c_root / 'RETROOS/OS2/LOCAL.TXT').touch()
        (c_root / 'RETROOS/DN').mkdir()
        (c_root / 'RETROOS/DN/LOCAL.TXT').touch()
        (c_root / 'RETROOS/BOOT.INI').write_text('host boot config\n')
        (c_root / 'RETROOS/COMMAND.COM').write_text('stale command\n')
        stale_dll = c_root / 'RETROOS/WINDOWS/SYSTEM32/NTDLL.DLL'
        stale_dll.write_text('stale host file\n')
        (c_root / 'DN').mkdir()
        (c_root / 'DN/local.txt').write_text('from the host\n')
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', c_root / 'RETROOS/RETROOS.INI')
        target = work / 'outside.txt'
        target.write_text('application symlink outside C:\n')
        (c_root / 'link').symlink_to(target)
        # Use the same DOS probe as the ordinary SMB test, through C: instead
        # of an extra drive. It is launched by the real host GNU shell.
        source = work / 'probe.asm'
        source.write_text((ROOT / 'test/smb_dos.asm').read_text().replace('H:\\DOS.TXT', 'C:\\DOS.TXT'))
        subprocess.run(['nasm', '-f', 'bin', str(source), '-o', str(c_root / 'PROBE.COM')], check=True)
        items = c_root / 'ITEMS'
        (items / '.cache').mkdir(parents=True)
        (items / 'sixletters-second.txt').write_bytes(b'22')
        (items / 'sixletters-first.txt').write_bytes(b'1')
        (items / 'linked.txt').symlink_to('sixletters-first.txt')
        (items / 'dangling').symlink_to('missing')
        subprocess.run(['nasm', '-f', 'bin', str(ROOT / 'test/dos_find_view.asm'),
                        '-o', str(c_root / 'DNVIEW.COM')], check=True)
        outside_home = work / 'outside-home.txt'
        outside_home.write_text('host root\n')
        read_only_file = Path(readonly) / 'read-only.txt'
        read_only_file.write_text('read-only\n')
        script = c_root / 'check.sh'
        script.write_text(f'''set -eu
test "$HOME" = {home}
test "$TMPDIR" = /tmp
test "$(id -u)" = {os.getuid()}
test "$(id -g)" = {os.getgid()}
test -d {c_root}/RETROOS/releases
test "$(cat {c_root}/RETROOS/BOOT.INI)" = 'host boot config'
test -f {c_root}/RETROOS/COMMAND.COM
test "$(head -c 1 {c_root}/RETROOS/COMMAND.COM)" != s
test "$(head -c 2 {stale_dll})" = MZ
test -f {c_root}/RETROOS/DN/DN.COM
test ! -e {c_root}/RETROOS/DN/LOCAL.TXT
test -f {c_root}/RETROOS/OS2/DLL/DOSCALLS.DLL
test ! -e {c_root}/RETROOS/OS2/LOCAL.TXT
test ! -e {c_root}/DN/DN.COM
test -f {c_root}/DN/local.txt
test ! -e {c_root}/EFI
test ! -e {c_root}/boot
test ! -e {c_root}/TEMP
printf 'session home\\n' > "$HOME/result.txt"
{c_root}/PROBE.COM
{c_root}/DNVIEW.COM
IFS= read -r os < /etc/os-release
printf '%s\\n' "$os" > {c_root}/root.txt
IFS= read -r target < {c_root}/link
printf '%s\\n' "$target" > {c_root}/link.txt
test "$(cat {outside_home})" = 'host root'
printf 'live tmp\\n' > {outside_home}
test "$(cat {read_only_file})" = 'read-only'
if printf wrong > {read_only_file}; then exit 23; fi
printf '# live settings edit\\n' > {c_root}/RETROOS/RETROOS.INI
printf 'LIVE ROOT PASS\\n' > {c_root}/result.txt
''')
        profile = work / 'profile.json'
        profile.write_text(json.dumps({'root': '/', 'c_root': str(c_root), 'session_home': str(home)}))
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
        command = [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--live-root', '--headless', '--sound', 'none',
                   '--cmd', f'/bin/sh {script}']
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=150)
        log = result.stdout + result.stderr
        artifacts = ROOT / 'build/ci'
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / 'live-root.log').write_text(log)
        assert result.returncode == 0, log[-8000:]
        assert not any(s in log for s in ('PANIC', 'FATAL', '[LINUX] fatal')), log[-8000:]
        assert 'SMB: mounted / (authenticated, signed SMB2)' in log, log[-8000:]
        for path in ('/tmp', home, c_root):
            assert f'SMB: mounted {path} (authenticated, signed SMB2)' in log, log[-8000:]
        assert '[mem] exit tid=1 code=0' in log, log[-8000:]
        assert (c_root / 'DOS.TXT').read_bytes() == b'DOS through shared SMB VFS\r\n'
        assert (c_root / 'root.txt').read_text().strip() == Path('/etc/os-release').read_text().splitlines()[0]
        assert (c_root / 'link.txt').read_bytes() == target.read_bytes()
        assert (c_root / 'result.txt').read_text() == 'LIVE ROOT PASS\n'
        assert (home / 'result.txt').read_text() == 'session home\n'
        assert stale_dll.read_text() == 'stale host file\n'
        assert (c_root / 'RETROOS/RETROOS.INI').read_text().endswith('# live settings edit\n')
        assert outside_home.read_text() == 'live tmp\n'
        assert read_only_file.read_text() == 'read-only\n'
        view_output = c_root / 'DNVIEW.DAT'
        normal = [(b'LINKED.TXT', 0x20, 1), (b'SIXLET~1.TXT', 0x20, 1), (b'SIXLET~2.TXT', 0x20, 2)]
        expected = [normal, [(b'~1.CAC', 0x12, 0), *normal]]
        qemu_views = dos_views(view_output)
        assert qemu_views == expected, qemu_views
        view_output.unlink()
        result = subprocess.run([str(ROOT / 'run.sh'), 'hosted', '--kvm', '--headless', '--cmd', 'DNVIEW.COM'],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=150)
        assert result.returncode == 0 and view_output.is_file(), (result.stdout + result.stderr)[-8000:]
        hosted_views = dos_views(view_output)
        assert hosted_views == qemu_views, (hosted_views, qemu_views)
    print('PASS: live GNU shell, host home and identity, paired runtime, persistent writes, and hosted DOS directory parity')


if __name__ == '__main__':
    main()
