#!/usr/bin/env python3
"""SQLite WAL creation, reader snapshots, checkpoint and persistent rows over SMB."""
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from linux_smb_symlink import ROOT, launch


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-sqlite-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        subprocess.run(['gcc', '-O2', str(ROOT / 'test/linux_sqlite_probe.c'),
                        '-Wl,-l:libsqlite3.so.0', '-o', str(home / 'probe')], check=True)
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        launch(work, 'probe', 'linux-sqlite')
        # The guest has exited before host SQLite inspects the database.
        with sqlite3.connect(str(home / 'wal.sqlite')) as database:
            assert database.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            assert database.execute('SELECT value FROM entries ORDER BY value').fetchall() == [(1,), (2,)]
    print('PASS: SQLite WAL snapshots, checkpoint, reopen and host integrity check')


if __name__ == '__main__':
    main()
