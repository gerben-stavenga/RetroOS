#!/usr/bin/env python3
"""Disk showcase seeding preserves existing user data and symlink directories."""
from pathlib import Path
import sys
import tempfile
import tarfile
import json
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import machine_install as installer
import install_machine as unified


class ShowcaseTests(unittest.TestCase):
    def test_runtime_guest_links_can_be_extracted_repeatedly(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / 'runtime.tar'
            with tarfile.open(archive, 'w') as tar:
                for name, target in [('bin/rc', '/COMMANDER/RC/RC.EXE'), ('bin/rcedit', 'rc')]:
                    member = tarfile.TarInfo(name)
                    member.type = tarfile.SYMTYPE
                    member.linkname = target
                    tar.addfile(member)
            for _ in range(2):
                with tarfile.open(archive) as tar:
                    tar.extractall(root / 'runtime', filter=installer.runtime_filter)
                self.assertEqual((root / 'runtime/bin/rc').readlink(), Path('/COMMANDER/RC/RC.EXE'))
                self.assertEqual((root / 'runtime/bin/rcedit').readlink(), Path('rc'))

    def test_runtime_guest_links_reject_escaping_parent_and_other_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runtime = root / 'runtime'
            runtime.mkdir()
            outside = root / 'outside'
            outside.mkdir()
            (runtime / 'bin').symlink_to(outside)
            member = tarfile.TarInfo('bin/rc')
            member.type = tarfile.SYMTYPE
            member.linkname = '/COMMANDER/RC/RC.EXE'
            with self.assertRaises(tarfile.OutsideDestinationError):
                installer.runtime_filter(member, runtime)
            member.name = 'other'
            with self.assertRaises(tarfile.AbsoluteLinkError):
                installer.runtime_filter(member, runtime)

    def test_seed_preserves_files_and_links_and_can_repeat(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'showcase'
            (source / 'GAMES/OWN').mkdir(parents=True)
            (source / 'GAMES/OWN/CFG').write_text('default')
            (source / 'GAMES/OWN/NEW').write_text('new')
            (source / 'GAMES/OWN/NEW').chmod(0o444)
            (source / 'GAMES/LINK').mkdir()
            (source / 'GAMES/LINK/NEW').write_text('do not write through')
            target = root / 'C'
            (target / 'GAMES/OWN').mkdir(parents=True)
            (target / 'GAMES/OWN/CFG').write_text('user settings')
            other = root / 'other'
            other.mkdir()
            (target / 'GAMES/LINK').symlink_to(other)
            self.assertEqual(installer.copy_showcase_tree(source, target), 1)
            self.assertEqual((target / 'GAMES/OWN/CFG').read_text(), 'user settings')
            self.assertEqual((target / 'GAMES/OWN/NEW').read_text(), 'new')
            self.assertFalse((other / 'NEW').exists())
            self.assertEqual((target / 'GAMES/OWN/NEW').stat().st_mode & 0o777, 0o644)
            self.assertEqual(installer.copy_showcase_tree(source, target), 0)

    def test_prepare_stages_optional_files_outside_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core = root / 'core'
            (core / 'RETROOS').mkdir(parents=True)
            (core / 'RETROOS/RETROOS.INI').write_text('[system]\nstart=C:\\DN\\DN.COM\n')
            archive = root / 'core.tar'
            with tarfile.open(archive, 'w') as tar:
                tar.add(core / 'RETROOS', arcname='RETROOS')
            optional = root / 'optional'
            (optional / 'GAMES').mkdir(parents=True)
            (optional / 'GAMES/OWN.DAT').write_text('game')
            showcase = root / 'showcase.tar'
            with tarfile.open(showcase, 'w') as tar:
                tar.add(optional / 'GAMES', arcname='GAMES')
            with patch.object(installer, 'STAGE', root / 'stage'), \
                 patch.object(installer, 'filesystem', return_value={'uuid': 'test-uuid', 'fstype': 'ext4', 'fsroot': '/', 'target': '/'}):
                installer.prepare(root / 'C', root / 'boot', archive, True, showcase)
                stage = Path((root / 'stage/selected').read_text().strip())
                self.assertTrue((stage / 'showcase/GAMES/OWN.DAT').is_file())
                self.assertFalse((stage / 'runtime/GAMES').exists())
                self.assertFalse((root / 'C').exists())
                self.assertTrue(json.loads((stage / 'plan.json').read_text())['copy_showcase'])
                self.assertIn('showcase/GAMES/OWN.DAT', json.loads((stage / 'checksums.json').read_text()))
                installer.prepare(root / 'C', root / 'boot', archive, False)
                stage = Path((root / 'stage/selected').read_text().strip())
                self.assertFalse((stage / 'showcase').exists())
                self.assertFalse(json.loads((stage / 'plan.json').read_text())['copy_showcase'])

    def test_disk_install_publishes_the_same_runtime_for_fat_and_ext4(self):
        for kind in ('vfat', 'ext4'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage = root / 'stage'
                runtime = stage / 'runtime'
                (runtime / 'RETROOS').mkdir(parents=True)
                (runtime / 'bin').mkdir()
                (runtime / 'kernel.elf').write_bytes(b'kernel')
                (runtime / 'RETROOS/DOSRT.EXE').write_bytes(b'runtime')
                (runtime / 'bin/busybox').write_bytes(b'busybox')
                (runtime / 'bin/sh').symlink_to('busybox')
                installer.normalize_runtime(runtime)
                self.assertEqual((runtime / 'RETROOS/UNIXLINK.LST').read_text(), 'sh\tbusybox\n')
                self.assertFalse((runtime / 'bin/sh').exists())
                (stage / 'RETROOS.INI').write_text('[system]\n')
                (stage / 'grub.cfg').write_text('menuentry test {}\n')
                (stage / '41_retroos').write_text('#!/bin/sh\n')
                home = root / 'C'
                home.mkdir()
                plan = dict(c_uuid='AAAA-BBBB', c_fstype=kind, c_dir='/', linux_root=None,
                            archive_sha256='a'*64, release=str(root / 'boot/releases/version'),
                            runtime_subdir='/RETROOS/releases/'+'a'*12, settings_observed=True,
                            user_ini_sha256=None, boot_ini_sha256=None, copy_showcase=False)
                (stage / 'BOOT.INI').write_text(installer.boot_configuration(plan))
                (root / 'inactive').write_text('menuentry "RetroOS (old module)" {}\n')
                (root / 'inactive').chmod(0o755)
                with patch.object(installer, 'MANAGED', root / 'managed'), \
                     patch.object(installer, 'CUSTOM', root / 'custom'), \
                     patch.object(installer, 'OTHER_MANAGED', root / 'inactive'), \
                     patch.object(installer.os, 'chown'), \
                     patch.object(unified.module.shutil, 'which', side_effect=lambda name: '/usr/bin/grub-mkconfig' if name == 'grub-mkconfig' else None), \
                     patch.object(unified.module, 'grub_config_path', return_value=root / 'grub.cfg'), \
                     patch.object(installer.subprocess, 'run') as update:
                    installer.install_into(stage, plan, home)
                    update.assert_called_with(['/usr/bin/grub-mkconfig', '-o', str(root / 'grub.cfg')], check=True)
                    release = home / 'RETROOS/releases' / ('a'*12)
                    self.assertEqual((root / 'inactive').stat().st_mode & 0o777, 0o644)
                    self.assertTrue((root / 'inactive.previous').is_file())
                    self.assertEqual((release / 'RETROOS/DOSRT.EXE').read_bytes(), b'runtime')
                    self.assertEqual((release / 'RETROOS/UNIXLINK.LST').read_text(), 'sh\tbusybox\n')
                    self.assertEqual((root / 'boot/releases/version/kernel.elf').read_bytes(), b'kernel')
                    boot = (home / 'RETROOS/BOOT.INI').read_text()
                    self.assertIn('source=UUID=AAAA-BBBB', boot)
                    self.assertNotIn('source=module', boot)
                    (home / 'RETROOS/RETROOS.INI').write_text('[system]\n# user edit\n')
                    plan['user_ini_sha256'] = installer.checksum(home / 'RETROOS/RETROOS.INI')
                    plan['boot_ini_sha256'] = installer.checksum(home / 'RETROOS/BOOT.INI')
                    installer.install_into(stage, plan, home)
                    self.assertIn('# user edit', (home / 'RETROOS/RETROOS.INI').read_text())

    def test_prepare_choice_and_noninteractive_default(self):
        for flags, exists, terminal, answer, expected in [
            ([], False, True, 'yes', True), ([], False, True, 'no', False),
            ([], False, False, None, False), ([], True, True, None, False),
            ([], True, False, None, False),
            (['--copy-showcase'], True, True, None, True),
            (['--copy-showcase'], False, False, None, True),
            (['--no-copy-showcase'], False, True, None, False),
        ]:
            with tempfile.TemporaryDirectory() as folder:
                c_root = Path(folder) / 'C'
                if exists:
                    c_root.mkdir()
                with self.subTest(flags=flags, exists=exists, terminal=terminal), \
                     patch.object(sys, 'argv', ['machine_install', '--prepare', '--c-root', str(c_root)] + flags), \
                     patch.object(sys.stdin, 'isatty', return_value=terminal), \
                     patch('builtins.input', return_value=answer) as prompt, \
                     patch.object(installer, 'prepare') as prepare:
                    installer.main()
                    self.assertEqual(prepare.call_args.args[3], expected)
                    self.assertEqual(prompt.called, not exists and terminal and not flags)



class UnifiedInstallTests(unittest.TestCase):
    def test_default_installer_prepares_fat_without_module_flag_and_remembers_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'stage'
            stage.mkdir()
            selected = stage / 'selected'
            selected.write_text(str(stage / 'ready') + '\n')
            choice = root / 'choice.json'
            fs = {'fstype': 'ext4', 'uuid': 'root', 'target': '/', 'fsroot': '/'}
            with patch.object(sys, 'argv', ['install', '--prepare', '--c-uuid=AAAA-BBBB', '--copy-showcase']), \
                 patch.object(unified.os, 'geteuid', return_value=1000), \
                 patch.object(unified.disk, 'filesystem', return_value=fs), \
                 patch.object(unified.disk, 'STAGE', stage), \
                 patch.object(unified, 'SELECTED', choice), \
                 patch.object(unified.module, 'candidates', return_value=[{'uuid': 'AAAA-BBBB', 'fstype': 'vfat', 'path': '/dev/data', 'size': 1, 'mountpoints': []}]), \
                 patch.object(unified.disk, 'prepare') as prepare:
                unified.main()
                self.assertEqual(prepare.call_args.kwargs['volume']['uuid'], 'AAAA-BBBB')
                self.assertTrue(prepare.call_args.args[3])
                self.assertEqual(json.loads(choice.read_text())['mode'], 'disk')
            with patch.object(sys, 'argv', ['install']), \
                 patch.object(unified.disk, 'STAGE', stage), \
                 patch.object(unified, 'SELECTED', choice), \
                 patch.object(unified.disk, 'install') as install:
                unified.main()
                install.assert_called_once()
                selected.write_text('different-stage\n')
                with self.assertRaisesRegex(ValueError, 'prepared installation changed'):
                    unified.main()

    def test_fat_and_ext4_use_disk_runtime_even_with_separate_boot(self):
        from argparse import Namespace
        args = Namespace(module=False, image=None, c_uuid=None, c_ram=False, c_dir=None, root_uuid=None)
        fs = {'fstype': 'ext4', 'uuid': 'root'}
        self.assertEqual(unified.installation_mode(args, fs, fs, fs), 'disk')
        fat = {'fstype': 'vfat', 'uuid': 'fat'}
        self.assertEqual(unified.installation_mode(args, fs, fs, fat), 'disk')
        self.assertEqual(unified.installation_mode(args, fs, fat, fs), 'disk')
        self.assertEqual(unified.installation_mode(args, {'fstype': 'btrfs'}, {'fstype': 'btrfs'}, fat), 'disk')
        args.module = True
        self.assertEqual(unified.installation_mode(args, fs, fs, fat), 'module')

    def test_fat_mountpoint_and_ext4_subdirectory_selection(self):
        fat = {'fstype': 'vfat', 'uuid': 'AAAA-BBBB', 'target': '/mnt/data', 'fsroot': '/'}
        self.assertEqual(unified.c_selection(Path('/mnt/data'), fat), ('AAAA-BBBB', None))
        with self.assertRaisesRegex(ValueError, 'volume mountpoint'):
            unified.c_selection(Path('/mnt/data/subdir'), fat)
        ext4 = dict(fat, fstype='ext4')
        self.assertEqual(unified.c_selection(Path('/mnt/data/DOS'), ext4), ('AAAA-BBBB', '/DOS'))


if __name__ == '__main__':
    unittest.main()
