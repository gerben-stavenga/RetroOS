#!/usr/bin/env python3
"""Boot installer-generated FAT/Linux layouts and verify independent, persistent HOME."""
import configparser
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from boot_config import boot, qemu

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from machine_install import boot_configuration
from vm_mount_config import volumes


def run(*args):
    subprocess.run(list(map(str, args)), check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def check(work, kind):
    tree = work / kind
    tree.mkdir()
    data = work / (kind + '.img')
    home = '/home/alice' if kind == 'ext4' else '/RETROOS/HOME'
    c_dir = '/home/alice/DOS' if kind == 'ext4' else '/'
    c_path = c_dir if kind == 'ext4' else '/dos'
    physical = tree / c_dir.lstrip('/')
    (physical / 'RETROOS').mkdir(parents=True)
    if kind == 'ext4':
        for directory in ('bin', 'usr', 'etc'):
            (tree / directory).mkdir()
    settings = f'[environment]\nTEST={c_path}/RETROOS/SHELL.ELF {c_path}/CHECK.SH\n'
    (physical / 'RETROOS/RETROOS.INI').write_text(settings)
    (physical / 'CHECK.SH').write_text(f'''set -eu
test "$HOME" = {home}
test -d "$HOME"
test -d /tmp
test -d /run
test -s {c_path}/RETROOS/RETROOS.INI
test -s {c_path}/RETROOS/COMMAND.COM
printf 'persistent-home\\n' > "$HOME/STATE.TXT"
printf 'temporary\\n' > "$TMPDIR/TEMP.TXT"
test -s /tmp/TEMP.TXT
''')
    with data.open('wb') as stream:
        stream.truncate(64 * 1024 * 1024)
    if kind == 'ext4':
        run('mke2fs', '-q', '-F', '-t', 'ext4', '-d', tree, data)
    else:
        run('mkfs.fat', '-F', '16', data)
        run('mcopy', '-s', '-i', data, tree / 'RETROOS', '::/')
        run('mcopy', '-i', data, physical / 'CHECK.SH', '::/')
    ident = volumes(data)[0][1]
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(boot_configuration(dict(c_uuid=ident, c_dir=c_dir, c_fstype=kind,
        linux_root=ident if kind == 'ext4' else None, runtime_subdir='/')))
    # The private boot image supplies the matched runtime in this fixture.
    config['bundle'] = dict(source='UUID=5E77-0002', subdir='/')
    if kind == 'ext4':
        config['mount "commands"'] = dict(source='bundle', subdir='/bin', path='/bin', access='ram')
    text = io.StringIO()
    config.write(text, space_around_delimiters=False)
    disk = work / (kind + '-boot.img')
    shutil.copyfile(ROOT / 'bazel-bin/boot_disk.bin', disk)
    for name, content in [('BOOT.INI', text.getvalue()), ('RETROOS.INI', settings)]:
        path = work / name
        path.write_text(content)
        run('mcopy', '-o', '-i', str(disk) + '@@1048576', path, '::RETROOS/' + name)
    log = work / (kind + '.log')
    boot(qemu(log) + ['-drive', f'file={disk},format=raw,snapshot=on',
                      '-drive', f'file={data},format=raw'], log, work / (kind + '.stderr'))
    if kind == 'ext4':
        state = subprocess.check_output(['debugfs', '-R', f'cat {home}/STATE.TXT', str(data)],
                                        stderr=subprocess.DEVNULL)
    else:
        state = subprocess.check_output(['mtype', '-i', str(data), '::RETROOS/HOME/STATE.TXT'])
    assert state == b'persistent-home\n', state
    print(f'PASS: {kind} independent HOME, persistent state, DOS runtime/settings and RAM temporary files', flush=True)


if __name__ == '__main__':
    run('bazelisk', 'build', '//:boot_disk')
    with tempfile.TemporaryDirectory(prefix='retroos-session-layout-') as folder:
        for kind in ('fat', 'ext4'):
            check(Path(folder), kind)
