#!/usr/bin/env python3
"""SQLite WAL creation, snapshots, checkpoint and persistence on SMB or ext4."""
import argparse
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from linux_smb_symlink import ROOT, launch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ext4-home', action='store_true')
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='retroos-sqlite-') as directory:
        work = Path(directory)
        home = work / 'root/home/retroos' if options.ext4_home else work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        subprocess.run(['gcc', '-O2', str(ROOT / 'test/linux_sqlite_probe.c'),
                        '-Wl,-l:libsqlite3.so.0', '-o', str(home / 'probe')], check=True)
        profile = {'root': '/', 'c_root': str(home)}
        drives = []
        if options.ext4_home:
            data = work / 'home.img'
            with data.open('wb') as output:
                output.truncate(128 * 1024 * 1024)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(work / 'root'), str(data)], check=True)
            profile['native_home_image'] = str(data)
            drives = ['-drive', f'file={data},format=raw,if=none,id=fsdata',
                      '-device', 'nvme,drive=fsdata,serial=RETROOS-SQLITE,write-cache=on']
        (work / 'profile.json').write_text(json.dumps(profile))
        launch(work, 'probe', 'linux-sqlite-ext4' if options.ext4_home else 'linux-sqlite', qemu_args=drives)
        if options.ext4_home:
            home = work / 'recovered'
            home.mkdir()
            for name in ('wal.sqlite', 'wal.sqlite-wal', 'wal.sqlite-shm'):
                subprocess.run(['debugfs', '-R', f'dump /home/retroos/{name} {home / name}', str(data)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # The guest has exited before host SQLite inspects the database.
        with sqlite3.connect(str(home / 'wal.sqlite')) as database:
            assert database.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            assert database.execute('SELECT value FROM entries ORDER BY value').fetchall() == [(1,), (2,)]
    print('PASS: SQLite WAL snapshots, checkpoint, reopen and host integrity check')


if __name__ == '__main__':
    main()
