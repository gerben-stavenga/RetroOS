#!/usr/bin/env python3
"""Check disk fixture writeback without overwriting concurrent host changes."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class DiskFixtureTest(unittest.TestCase):
    def test_changed_files_and_host_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            root = work / 'root'
            root.mkdir()
            (root / 'untouched').write_text('original')
            (root / 'log').write_text('before')
            (root / 'deleted').write_text('remove me')
            payload = work / 'payload'
            payload.write_text('guest output')
            guest = work / 'guest.py'
            guest.write_text('''import pathlib, subprocess, sys
root, payload, image = sys.argv[1:]
pathlib.Path(root, 'log').write_text('host updated log')
for command in [f'write {payload} /result', 'rm /deleted']:
    subprocess.run(['debugfs', '-w', '-R', command, image], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
''')
            subprocess.run(['python3', str(Path(__file__).with_name('disk_fixture.py')),
                            '--root', str(root), '--', 'python3', str(guest), str(root), str(payload)], check=True)
            self.assertEqual((root / 'result').read_text(), 'guest output')
            self.assertEqual((root / 'untouched').read_text(), 'original')
            self.assertEqual((root / 'log').read_text(), 'host updated log')
            self.assertFalse((root / 'deleted').exists())
            self.assertFalse((root / 'RETROOS/BOOT.INI').exists())


if __name__ == '__main__':
    unittest.main()
