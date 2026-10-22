#!/usr/bin/env python3
"""USB configuration uses real INI files, without touching host disks or GRUB."""
import configparser
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import install_machine as installer


class UsbInstallTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.usb = Path(self.directory.name)
        self.ini = self.usb / 'boot/retroos/BOOT.INI'
        self.ini.parent.mkdir(parents=True)
        self.original = ('[bundle]\nsource=module\nsubdir=/\n'
                         '[mount "session"]\nsource=bundle\npath=/\ndrive=C\naccess=ram\n'
                         '[mount "extra"]\nsource=UUID=CCCC-DDDD\npath=/extra\ndrive=E\naccess=ro\n')
        self.ini.write_text(self.original)
        self.volumes = [dict(uuid='AAAA-BBBB', fstype='vfat', path='/dev/sda1', size=100)]
        fs = dict(fstype='vfat', target=str(self.usb), fsroot='/')
        self.filesystem = self.enterContext(patch.object(installer.disk, 'filesystem', return_value=fs))
        self.enterContext(patch.object(installer.module, 'candidates', return_value=self.volumes))
        self.host_install = self.enterContext(patch.object(installer.disk, 'install'))
        self.grub_install = self.enterContext(patch.object(installer.module, 'install'))
        self.stdout = self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def config(self, text=None):
        result = configparser.ConfigParser(interpolation=None)
        result.read_string(self.ini.read_text() if text is None else text)
        return result

    def test_writes_physical_c_and_preserves_other_mounts_and_backup(self):
        installer.configure_usb(self.usb, c_uuid='AAAA-BBBB')
        config = self.config()
        self.assertEqual(config['bundle']['source'], 'module')
        self.assertEqual(config['mount "data"']['source'], 'UUID=AAAA-BBBB')
        self.assertEqual(config['mount "data"']['subdir'], '/')
        self.assertEqual(config['mount "extra"']['drive'], 'E')
        self.assertNotIn('mount "session"', config)
        self.assertEqual(self.ini.with_suffix('.INI.previous').read_text(), self.original)
        # Applying the same selection again must also work.
        installer.configure_usb(self.usb, c_uuid='AAAA-BBBB')

    def test_preview_does_not_write(self):
        installer.configure_usb(self.usb, preview=True)
        self.assertEqual(self.ini.read_text(), self.original)
        self.assertFalse(self.ini.with_suffix('.INI.previous').exists())
        self.assertEqual(self.config(self.stdout.getvalue())['mount "data"']['drive'], 'C')

    def test_ram_c_and_existing_linux_root(self):
        self.ini.write_text(self.original + '[mount "linux"]\nsource=UUID=root\npath=/\naccess=ro\n')
        installer.configure_usb(self.usb, c_ram=True)
        config = self.config()
        self.assertEqual(config['mount "session"']['path'], '/dos')
        self.assertEqual(config['mount "linux"']['source'], 'UUID=root')

    def test_ext4_directory_and_linux_root(self):
        root = 'ea8c19a0-a2e3-4d14-9fd2-6955c176122c'
        self.volumes[:] = [dict(uuid=root, fstype='ext4', path='/dev/sda2', size=100)]
        installer.configure_usb(self.usb, c_uuid=root, c_dir='/games', root_uuid=root)
        config = self.config()
        self.assertEqual(config['mount "linux"']['path'], '/')
        self.assertEqual(config['mount "data"']['subdir'], '/games')

    def test_rejects_invalid_selection_before_writing(self):
        for kwargs in [dict(c_uuid='CCCC-DDDD'), dict(c_dir='/games'),
                       dict(root_uuid='AAAA-BBBB'), dict(c_uuid='AAAA-BBBB', c_ram=True)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                installer.configure_usb(self.usb, **kwargs)
            self.assertEqual(self.ini.read_text(), self.original)

    def test_requires_flashed_fat_mountpoint(self):
        for fs in [dict(fstype='ext4', target=str(self.usb), fsroot='/'),
                   dict(fstype='vfat', target='/', fsroot='/')]:
            self.filesystem.return_value = fs
            with self.assertRaises(ValueError):
                installer.configure_usb(self.usb)
        self.filesystem.return_value = dict(fstype='vfat', target=str(self.usb), fsroot='/')
        self.ini.unlink()
        with self.assertRaisesRegex(ValueError, 'flash the USB image first'):
            installer.configure_usb(self.usb)

    def test_cli_does_not_install_host_even_with_saved_selection(self):
        with patch.object(sys, 'argv', ['install.sh', '--usb', str(self.usb), '--c-ram']):
            installer.main()
        self.host_install.assert_not_called()
        self.grub_install.assert_not_called()
        self.assertEqual(self.config()['mount "session"']['access'], 'ram')


if __name__ == '__main__':
    unittest.main()
